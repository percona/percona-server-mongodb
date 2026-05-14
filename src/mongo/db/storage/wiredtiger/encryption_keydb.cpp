/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2018-present Percona and/or its affiliates. All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the Server Side Public License, version 1,
    as published by MongoDB, Inc.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Server Side Public License for more details.

    You should have received a copy of the Server Side Public License
    along with this program. If not, see
    <http://www.mongodb.com/licensing/server-side-public-license>.

    As a special exception, the copyright holders give permission to link the
    code of portions of this program with the OpenSSL library under certain
    conditions as described in each individual source file and distribute
    linked combinations including the program with the OpenSSL library. You
    must comply with the Server Side Public License in all respects for
    all of the code used other than as permitted herein. If you modify file(s)
    with this exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do so,
    delete this exception statement from your version. If you delete this
    exception statement from all source files in the program, then also delete
    it in the license file.
======= */


#include "mongo/db/storage/wiredtiger/encryption_keydb.h"

#include "mongo/db/database_name_util.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/service_context.h"
#include "mongo/db/shard_role/shard_catalog/collection.h"
#include "mongo/db/shard_role/shard_catalog/collection_catalog.h"
#include "mongo/db/storage/record_store.h"
#include "mongo/db/storage/storage_engine.h"
#include "mongo/db/storage/wiredtiger/encryption_keydb_c_api.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_kv_engine.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_session.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_util.h"
#include "mongo/logv2/log.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/debug_util.h"
#include "mongo/util/system_clock_source.h"
#include "mongo/util/uuid.h"

#include <cstring>  // memcpy

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kStorage


namespace mongo {

static EncryptionKeyDB* encryptionKeyDB = nullptr;
static EncryptionKeyDB* rotationKeyDB = nullptr;

static constexpr const char* gcm_iv_key = "_gcm_iv_reserved";
constexpr int EncryptionKeyDB::_gcm_iv_bytes;

static void dump_key(unsigned char* key, const int _key_len, const char* msg) {
    const char* m = "0123456789ABCDEF";
    char buf[_key_len * 3 + 1];  // NOLINT(clang-diagnostic-vla-cxx-extension)
    char* p = buf;
    for (int i = 0; i < _key_len; ++i) {
        *p++ = m[*key >> 4];
        *p++ = m[*key & 0xf];
        *p++ = ' ';
        ++key;
    }
    *p = 0;
    LOGV2(29033, "{msg}: {buf}", "msg"_attr = msg, "buf"_attr = static_cast<const char*>(buf));
}

static void dump_table(WT_SESSION* _sess, const int _key_len, const char* msg) {
    LOGV2(29034, "{msg}", "msg"_attr = msg);
    WT_CURSOR* cursor;
    int res = _sess->open_cursor(_sess, "table:key", nullptr, nullptr, &cursor);
    if (res) {
        LOGV2(29035, "{e}", "e"_attr = wiredtiger_strerror(res));
        return;
    }
    while ((res = cursor->next(cursor)) == 0) {
        char* k;
        WT_ITEM v;
        res = cursor->get_key(cursor, &k);
        res = cursor->get_value(cursor, &v);
        std::stringstream ss;
        ss << v.size << ": " << k;
        dump_key((unsigned char*)v.data, _key_len, ss.str().c_str());
    }
    res = cursor->close(cursor);
}

std::unique_ptr<EncryptionKeyDB> EncryptionKeyDB::create(const std::string& path,
                                                         const encryption::Key& masterKey) {
    std::unique_ptr<EncryptionKeyDB> db(new EncryptionKeyDB(path, masterKey, false));
    db->init();
    return db;
}

EncryptionKeyDB::EncryptionKeyDB(const std::string& path,
                                 const encryption::Key& masterKey,
                                 const bool rotation)
    : _rotation(rotation),
      _path(path),
      _srng(std::make_unique<SecureRandom>()),
      _prng(std::make_unique<PseudoRandom>(_srng->nextInt64())),
      _masterkey(masterKey) {
    // single instance is allowed as main keydb
    // and another one for rotation
    if (!_rotation) {
        invariant(encryptionKeyDB == nullptr);
        encryptionKeyDB = this;
    } else {
        invariant(rotationKeyDB == nullptr);
        rotationKeyDB = this;
    }
}

EncryptionKeyDB::~EncryptionKeyDB() {
    close_handles();
    // should be the last line because closing wiredTiger's handles may write to DB
    if (!_rotation)
        encryptionKeyDB = nullptr;
    else
        rotationKeyDB = nullptr;
}

void EncryptionKeyDB::close_handles() {
    if (kDebugBuild && _sess)
        dump_table(_sess, encryption::Key::kLength, "dump_table from destructor");
    _backupSession.reset();
    _backupCursor = nullptr;
    if (_sess) {
        _gcm_iv_reserved = _gcm_iv;
        store_gcm_iv_reserved();
        _sess->close(_sess, nullptr);
        _sess = nullptr;
    }
    if (_connection) {
        WT_CONNECTION* conn = _connection->conn();
        conn->close(conn, nullptr);
        _connection.reset();
    }
}

void EncryptionKeyDB::generate_secure_key(unsigned char* key) {
    std::lock_guard<std::mutex> lk(_lock_key);
    _srng->fill(key, encryption::Key::kLength);
}

// this function uses _srng without synchronization
// caller must ensure it is safe
void EncryptionKeyDB::generate_secure_key_inlock(char key[]) {
    _srng->fill(key, encryption::Key::kLength);
}

// Open db with correct compatibility mode
// Based on WiredTigerKVEngine::_openWiredTiger
// Should be synced with changes in WiredTigerKVEngine::_openWiredTiger
int EncryptionKeyDB::_openWiredTiger(const std::string& path, const std::string& wtOpenConfig) {
    // For now we don't use event handler in EncryptionKeyDB
    WT_EVENT_HANDLER* wtEventHandler = nullptr;

    int ret = 0;
    WT_CONNECTION* conn = nullptr;
    ScopeGuard initConnection([this, &conn, &ret] {
        invariant(!ret, "this scope guard should be dismissed in case of anny failure");
        invariant(conn, "connection should be initialized if there is no error");
        _fastClockSource = std::make_unique<SystemClockSource>();
        _connection = std::make_unique<WiredTigerConnection>(
            conn, _fastClockSource.get(), /*sessionCacheMax=*/33000);
    });

    // MongoDB 4.4 will always run in compatibility version 10.0.
    std::string configStr = wtOpenConfig + ",compatibility=(require_min=\"10.0.0\")";
    ret = wiredtiger_open(path.c_str(), wtEventHandler, configStr.c_str(), &conn);
    if (!ret) {
        //_fileVersion = {WiredTigerFileVersion::StartupVersion::IS_44_FCV_44};
        return ret;
    }

    // MongoDB 4.4 doing clean shutdown in FCV 4.2 will use compatibility version 3.3.
    configStr = wtOpenConfig + ",compatibility=(require_min=\"3.3.0\")";
    ret = wiredtiger_open(path.c_str(), wtEventHandler, configStr.c_str(), &conn);
    if (!ret) {
        //_fileVersion = {WiredTigerFileVersion::StartupVersion::IS_44_FCV_42};
        return ret;
    }

    // MongoDB 4.2 uses compatibility version 3.2.
    configStr = wtOpenConfig + ",compatibility=(require_min=\"3.2.0\")";
    ret = wiredtiger_open(path.c_str(), wtEventHandler, configStr.c_str(), &conn);
    if (!ret) {
        //_fileVersion = {WiredTigerFileVersion::StartupVersion::IS_42};
        return ret;
    }

    initConnection.dismiss();

    LOGV2_WARNING(
        29054, "EncryptionKeyDB: Failed to start up WiredTiger under any compatibility version.");
    if (ret == WT_TRY_SALVAGE)
        LOGV2_WARNING(29055,
                      "EncryptionKeyDB: WiredTiger metadata corruption detected or "
                      "an invalid encryption key is used");

    LOGV2_FATAL_NOTRACE(29056,
                        "Reason: {wtRCToStatus_ret_reason}",
                        "wtRCToStatus_ret_reason"_attr = wtRCToStatus(ret, nullptr).reason());

    return ret;
}

void EncryptionKeyDB::init() {
    try {
        std::stringstream ss;
        ss << "create,";
        ss << "config_base=false,";
        // encryptionGlobalParams.encryptionCipherMode is not used here with a reason:
        // keys DB will always use CBC cipher because wiredtiger_open internally calls
        // encryption extension's encrypt function which depends on the GCM encryption counter
        // loaded later (see 'load parameters' section below)
        ss << "extensions=[local=(entry=percona_encryption_extension_init,early_load=true,config=("
              "cipher=AES256-CBC"
           << (_rotation ? ",rotation=true" : ",rotation=false") << "))],";
        ss << "encryption=(name=percona,keyid=\"\"),";
        // logging configured; updates durable on application or system failure
        // https://source.wiredtiger.com/3.0.0/tune_durability.html
        ss << "log=(enabled,file_max=5MB),transaction_sync=(enabled=true,method=fsync),";
        std::string config = ss.str();
        LOGV2(29037, "Initializing KeyDB with wiredtiger_open config: {cfg}", "cfg"_attr = config);
        int res = _openWiredTiger(_path, config);
        if (res) {
            throw std::runtime_error(std::string("error opening keys DB at '") + _path +
                                     "': " + wiredtiger_strerror(res));
        }
        _wtOpenConfig = config;

        // empty keyid means masterkey
        invariant(_connection, "Connection is not initialized");
        invariant(_connection->conn(), "WiredTiger connection is not initialized");
        res = _connection->conn()->open_session(_connection->conn(), nullptr, nullptr, &_sess);
        if (res) {
            throw std::runtime_error(std::string("error opening wiredTiger session: ") +
                                     wiredtiger_strerror(res));
        }

        if (kDebugBuild)
            dump_table(_sess, encryption::Key::kLength, "before create");
        // try to create 'key' table
        // ignore error if table already exists
        res = _sess->create(
            _sess, "table:key", "key_format=S,value_format=u,access_pattern_hint=random");
        if (res) {
            throw std::runtime_error(std::string("error creating/opening key table: ") +
                                     wiredtiger_strerror(res));
        }
        if (kDebugBuild)
            dump_table(_sess, encryption::Key::kLength, "after create");

        // try to create 'parameters' table
        // ignore error if table already exists
        res = _sess->create(
            _sess, "table:parameters", "key_format=S,value_format=u,access_pattern_hint=random");
        if (res) {
            throw std::runtime_error(std::string("error creating/opening parameters table: ") +
                                     wiredtiger_strerror(res));
        }

        // load parameters
        {
            WT_CURSOR* cursor;
            int res = _sess->open_cursor(_sess, "table:parameters", nullptr, nullptr, &cursor);
            if (res) {
                throw std::runtime_error(std::string("error opening cursor: ") +
                                         wiredtiger_strerror(res));
            }
            // create cursor delete guard
            std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> cursor_guard(
                cursor, [](WT_CURSOR* c) { c->close(c); });
            // load _gcm_iv_reserved from DB
            cursor->set_key(cursor, gcm_iv_key);
            res = cursor->search(cursor);
            if (res == 0) {
                WT_ITEM v;
                cursor->get_value(cursor, &v);
                import_bits(
                    _gcm_iv_reserved, (uint8_t*)v.data, (uint8_t*)v.data + v.size, 8, false);
                _gcm_iv = _gcm_iv_reserved;
            } else if (res != WT_NOTFOUND) {
                throw std::runtime_error(std::string("error reading parameters: ") +
                                         wiredtiger_strerror(res));
            }
        }
    } catch (std::exception& e) {
        LOGV2_ERROR(29038, "Exception in EncryptionKeyDB::init: {e}", "e"_attr = e.what());
        throw;
    }
    LOGV2(29039, "Encryption keys DB is initialized successfully");
}

void EncryptionKeyDB::import_data_from(const EncryptionKeyDB* proto) {
    // not doing any synchronization here because key rotation process is single threaded
    try {
        // copy parameters table
        // clone is called right after init(). at this point _gcm_iv_reserved is equal to _gcm_iv
        _gcm_iv_reserved = proto->_gcm_iv_reserved;
        if (store_gcm_iv_reserved()) {
            throw std::runtime_error("failed to copy key db data during rotation");
        }
        // copy key table
        int res;
        auto cursor_close = [](WT_CURSOR* c) {
            c->close(c);
        };
        WT_CURSOR* srcc;
        res = proto->_sess->open_cursor(proto->_sess, "table:key", nullptr, nullptr, &srcc);
        if (res)
            throw std::runtime_error(std::string("clone: error opening cursor: ") +
                                     wiredtiger_strerror(res));
        std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> srcc_guard(srcc, cursor_close);
        WT_CURSOR* dstc;
        res = _sess->open_cursor(_sess, "table:key", nullptr, nullptr, &dstc);
        if (res)
            throw std::runtime_error(std::string("clone: error opening cursor: ") +
                                     wiredtiger_strerror(res));
        std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> dstc_guard(dstc, cursor_close);
        while ((res = srcc->next(srcc)) == 0) {
            char* k;
            WT_ITEM v;
            if ((res = srcc->get_key(srcc, &k)) || (res = srcc->get_value(srcc, &v)))
                throw std::runtime_error(
                    std::string("clone: error getting key/value from the key table: ") +
                    wiredtiger_strerror(res));
            invariant(v.size == encryption::Key::kLength);
            dstc->set_key(dstc, k);
            dstc->set_value(dstc, &v);
            if ((res = dstc->insert(dstc)) != 0)
                throw std::runtime_error(std::string("clone: error writing key table: ") +
                                         wiredtiger_strerror(res));
        }
        if (res != WT_NOTFOUND)
            throw std::runtime_error(std::string("clone: error reading key table: ") +
                                     wiredtiger_strerror(res));
        // (No table:active_keyid clone -- this branch resolves the active
        // keyId per database via the CollectionCatalog rather than a
        // persisted mapping. Nothing in the keys DB needs to be cloned for
        // the rotation instance beyond table:key and table:parameters.)
    } catch (std::exception& e) {
        LOGV2_ERROR(29049, "Exception in EncryptionKeyDB::clone: {e}", "e"_attr = e.what());
        throw;
    }
}

std::unique_ptr<EncryptionKeyDB> EncryptionKeyDB::clone(const std::string& path,
                                                        const encryption::Key& masterKey) const {
    std::unique_ptr<EncryptionKeyDB> duplicate(new EncryptionKeyDB(path, masterKey, true));
    duplicate->init();
    duplicate->import_data_from(this);
    return duplicate;
}

int EncryptionKeyDB::get_key_by_id(const char* keyid, size_t len, unsigned char* key, void* pe) {
    LOGV2_DEBUG(29050, 4, "get_key_by_id for keyid: '{id}'", "id"_attr = std::string{keyid, len});
    // return key from keyfile if len == 0
    if (len == 0) {
        memcpy(key, const_cast<const encryption::Key&>(_masterkey).data(), _masterkey.size());
        if (kDebugBuild)
            dump_key(key, _masterkey.size(), "returning masterkey");
        return 0;
    }

    int res;
    // open cursor
    WT_CURSOR* cursor;
    // search/write of db encryption key should be atomic
    std::lock_guard<std::mutex> lk(_lock_sess);
    res = _sess->open_cursor(_sess, "table:key", nullptr, nullptr, &cursor);
    if (res) {
        LOGV2_ERROR(29040,
                    "get_key_by_id: error opening cursor: {err}",
                    "err"_attr = wiredtiger_strerror(res));
        return res;
    }

    // create cursor delete guard
    std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> cursor_guard(
        cursor, [](WT_CURSOR* c) { c->close(c); });

    // read key from DB
    std::string c_str(keyid, len);
    LOGV2_DEBUG(29041, 4, "trying to load encryption key for keyid: {id}", "id"_attr = c_str);
    cursor->set_key(cursor, c_str.c_str());
    res = cursor->search(cursor);
    if (res == 0) {
        WT_ITEM v;
        cursor->get_value(cursor, &v);
        invariant(v.size == encryption::Key::kLength);
        memcpy(key, v.data, encryption::Key::kLength);
        if (kDebugBuild)
            dump_key(key, encryption::Key::kLength, "loaded key from key DB");
        // No refcount increment here. WT caches the customized encryptor per
        // keyid, so this code path fires only on the first WT_SESSION::create
        // that names a given keyid in the lifetime of the connection -- not
        // once per URI. Counting here would yield exactly 1 ref per keyid
        // regardless of how many URIs reference it, which would not pair
        // correctly against the per-URI uri_dropped events. The per-URI
        // increment is done in `getOrCreateActiveKeyId`, which the
        // customization hook calls on every WT_SESSION::create, and at
        // startup `seedRefcountsFromWtMetadata` walks the user-data
        // metadata to seed the URI portion of the count.
        return 0;
    }
    if (res != WT_NOTFOUND) {
        LOGV2_ERROR(29042,
                    "cursor->search error {code}: {desc}",
                    "code"_attr = res,
                    "desc"_attr = wiredtiger_strerror(res));
        return res;
    }

    // create key if it does not exist
    generate_secure_key(key);
    WT_ITEM v;
    v.size = encryption::Key::kLength;
    v.data = key;
    cursor->set_key(cursor, c_str.c_str());
    cursor->set_value(cursor, &v);
    res = cursor->insert(cursor);
    if (res) {
        LOGV2_ERROR(29043,
                    "cursor->insert error {code}: {desc}",
                    "code"_attr = res,
                    "desc"_attr = wiredtiger_strerror(res));
        return res;
    }

    if (kDebugBuild)
        dump_key(key, encryption::Key::kLength, "generated and stored key");
    // No refcount increment here either; same rationale as the cache-hit
    // branch above. This branch only fires for keyids that have no
    // pre-existing row in table:key -- legacy bare-`<dbName>` idents from
    // a master-format keys DB, "/default" for system idents at very first
    // connection open, etc. -- and the customization hook routes new
    // generation keyIds through getOrCreateActiveKeyId's atomic-insert
    // path that pre-creates the table:key row, so this fallback should be
    // rare in practice.
    return 0;
}

int EncryptionKeyDB::delete_key_by_id(const std::string& keyid) {
    LOGV2_DEBUG(29044, 4, "delete_key_by_id for keyid: '{id}'", "id"_attr = keyid);

    int res;
    // open cursor
    WT_CURSOR* cursor;
    std::lock_guard<std::mutex> lk(_lock_sess);
    res = _sess->open_cursor(_sess, "table:key", nullptr, nullptr, &cursor);
    if (res) {
        LOGV2_ERROR(29045,
                    "delete_key_by_id: error opening cursor: {desc}",
                    "desc"_attr = wiredtiger_strerror(res));
        return res;
    }

    // create cursor delete guard
    std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> cursor_guard(
        cursor, [](WT_CURSOR* c) { c->close(c); });

    // delete key
    cursor->set_key(cursor, keyid.c_str());
    res = cursor->remove(cursor);
    if (res) {
        LOGV2_ERROR(29046,
                    "cursor->remove error {code}: {desc}",
                    "code"_attr = res,
                    "desc"_attr = wiredtiger_strerror(res));
    }

    // delete_key_by_id is now a pure cursor-based row delete on table:key.
    // The previous "rearm percona_sessioncreate / track _encryptors" logic
    // is gone: with generation keyIds (Phase 1) a cached customized-encryptor
    // slot is never reused across drop+recreate, and the per-keyId refcount
    // (Phase 4) is the authoritative driver of when this function is called
    // (only from onUriDropped's refcount-zero path, plus the pre-existing
    // master callers that no longer fire in the production drop path).
    return res;
}

void EncryptionKeyDB::onUriDropped(const std::string& keyid) {
    // PSMDB-1997 diagnostic: promoted from LOGV2_DEBUG so we can correlate
    // every uri_dropped event with the keyid it carries, in case the
    // wrongkey_replset.js orphan keyid is being reaped here.
    LOGV2(29092, "onUriDropped for keyid: '{id}'", "id"_attr = keyid);

    bool reap = false;
    {
        std::lock_guard<std::mutex> lkrc(_refcounts_lock);
        auto it = _refcounts.find(keyid);
        if (it == _refcounts.end()) {
            // Either a double uri_dropped for the same URI (which WT-core
            // shouldn't emit), or a uri_dropped for a keyid the engine
            // never observed via customize -- e.g. a startup-replay event
            // arriving before seedRefcountsFromWtMetadata had run, or a
            // race during shutdown. Defensive: log and return without
            // reaping; reaping a row not in table:key is a no-op anyway,
            // but spurious release_encryptor calls would still mask a
            // real bug if we silently swallow them.
            LOGV2_WARNING(29096,
                          "onUriDropped: no refcount entry for keyid",
                          "keyid"_attr = keyid);
            return;
        }
        if (--it->second > 0)
            return;
        _refcounts.erase(it);
        reap = true;
    }

    // Last reference released. Outside _refcounts_lock so delete_key_by_id
    // (which takes _lock_sess) and release_encryptor (which re-enters the
    // WT extension API) can run without lock-ordering hazards.
    if (reap) {
        delete_key_by_id(keyid);
        WT_CONNECTION* conn = _connection->conn();
        if (conn->release_encryptor != nullptr) {
            conn->release_encryptor(conn, keyid.c_str());
        }
    }
}

boost::optional<std::string> EncryptionKeyDB::tryGetCachedActiveKeyId(
    const DatabaseName& dbName) const {
    std::lock_guard<std::mutex> lk(_activeKeyIdMutex);
    auto it = _activeKeyIds.find(dbName);
    if (it == _activeKeyIds.end()) {
        return boost::none;
    }
    return it->second;
}

std::string EncryptionKeyDB::cacheActiveKeyIdIfAbsent(const DatabaseName& dbName,
                                                     std::string keyId) {
    // This helper carries both refcount bumps so the caller doesn't have
    // to coordinate two locks: on every call we add +1 URI ref (the
    // customization hook fires once per WT_SESSION::create -- i.e. once
    // per URI -- and is the only caller of `encryption::activeKeyIdForDb`,
    // which always ends up here), and on first insert we additionally add
    // +1 for the cache anchor (released in clearCachedActiveKeyId).
    //
    // Lock order across the keydb: _activeKeyIdMutex -> _refcounts_lock.
    // No other site nests these the other way.
    std::string finalKeyId;
    bool inserted;
    {
        std::lock_guard<std::mutex> lk(_activeKeyIdMutex);
        auto [it, didInsert] = _activeKeyIds.try_emplace(dbName, std::move(keyId));
        finalKeyId = it->second;
        inserted = didInsert;
    }
    {
        std::lock_guard<std::mutex> lkrc(_refcounts_lock);
        if (inserted) {
            ++_refcounts[finalKeyId];  // cache anchor
            LOGV2(29086,
                  "cacheActiveKeyIdIfAbsent: cached keyId for dbName",
                  logAttrs(dbName),
                  "keyId"_attr = finalKeyId);
        }
        ++_refcounts[finalKeyId];  // per-URI ref for THIS caller
    }
    return finalKeyId;
}

void EncryptionKeyDB::clearCachedActiveKeyId(const DatabaseName& dbName) {
    // PSMDB-1997 diagnostic: see every keydbDropDatabase entry.
    LOGV2(29087, "clearCachedActiveKeyId for dbName", logAttrs(dbName));

    std::string keyIdToReap;
    bool reap = false;
    {
        std::lock_guard<std::mutex> lk(_activeKeyIdMutex);
        auto it = _activeKeyIds.find(dbName);
        if (it == _activeKeyIds.end()) {
            // Idempotent: the dbName was either never resolved in this
            // process (cache cold-miss), or already cleared by a previous
            // drop.
            return;
        }
        const std::string activeKeyId = it->second;
        _activeKeyIds.erase(it);

        std::lock_guard<std::mutex> lkrc(_refcounts_lock);
        auto rcIt = _refcounts.find(activeKeyId);
        if (rcIt == _refcounts.end()) {
            // Cache entry existed but the matching refcount didn't. That
            // would mean cacheActiveKeyIdIfAbsent ran without incrementing,
            // which is a bookkeeping bug. Log and proceed without reap.
            LOGV2_WARNING(29095,
                          "clearCachedActiveKeyId: no refcount entry for cached keyId",
                          "keyId"_attr = activeKeyId);
            return;
        }
        if (--rcIt->second == 0) {
            _refcounts.erase(rcIt);
            keyIdToReap = activeKeyId;
            reap = true;
        }
    }

    if (reap) {
        // Outside both locks. delete_key_by_id reacquires _lock_sess for
        // its cursor work, and release_encryptor re-enters the WT
        // extension API (which may invoke the cached encryptor's
        // terminate callback).
        delete_key_by_id(keyIdToReap);
        WT_CONNECTION* conn = _connection->conn();
        if (conn->release_encryptor != nullptr) {
            conn->release_encryptor(conn, keyIdToReap.c_str());
        }
    }
}

std::vector<std::string> EncryptionKeyDB::getAllCachedActiveKeyIds() const {
    std::vector<std::string> result;
    std::lock_guard<std::mutex> lk(_activeKeyIdMutex);
    result.reserve(_activeKeyIds.size());
    for (const auto& [_, keyId] : _activeKeyIds) {
        result.push_back(keyId);
    }
    return result;
}

namespace {
// Parses the `keyid="..."` value out of an URI's metadata config string.
// The encryption block has the form:
//   ...,encryption=(name=<n>,keyid="<k>"),...
// or, for the unencrypted case (which is unrelated to "encryption=none"
// in the keyid sense -- "none" still has the field but signals "not
// encrypted, do not look up an encryptor"):
//   ...,encryption=(name=none),...
//
// Returns true and sets keyIdOut on success; returns false if the URI is
// not encrypted, has no keyid, or the encryption block is malformed.
//
// We hand-roll the extraction (rather than reuse WT_CONFIG_PARSER from
// the extension API) because that API requires a WT_EXTENSION_API*,
// which isn't readily threaded through to the keydb side. The metadata
// config format is stable and the substring search is bounded by the
// encryption=(...) block.
bool parseKeyIdFromMetadata(StringData metaCfg, std::string& keyIdOut) {
    constexpr StringData kEncOpen{"encryption=("};
    auto encStart = metaCfg.find(kEncOpen);
    if (encStart == std::string::npos)
        return false;
    encStart += kEncOpen.size();
    auto encEnd = metaCfg.find(')', encStart);
    if (encEnd == std::string::npos)
        return false;
    StringData encBlock = metaCfg.substr(encStart, encEnd - encStart);

    constexpr StringData kKeyId{"keyid="};
    auto kidStart = encBlock.find(kKeyId);
    if (kidStart == std::string::npos)
        return false;
    kidStart += kKeyId.size();

    bool quoted = kidStart < encBlock.size() && encBlock[kidStart] == '"';
    if (quoted)
        ++kidStart;

    auto kidEnd = kidStart;
    while (kidEnd < encBlock.size()) {
        const char c = encBlock[kidEnd];
        if (quoted ? (c == '"') : (c == ','))
            break;
        ++kidEnd;
    }
    if (kidEnd <= kidStart)
        return false;
    keyIdOut.assign(encBlock.data() + kidStart, kidEnd - kidStart);
    return !keyIdOut.empty();
}
}  // namespace

void EncryptionKeyDB::seedRefcountsFromWtMetadata(WT_CONNECTION* conn) {
    invariant(conn);

    // No anchor units to seed: the in-memory cache (`_activeKeyIds`)
    // starts empty at process start and gets populated lazily by
    // `encryption::activeKeyIdForDb` on the first ident-create per
    // dbName. The previous A2 design seeded an anchor per row in the
    // persisted table:active_keyid; the A3 catalog-scan design has no
    // such table.

    // Use a private session on the user-data connection. Don't reuse the
    // keydb's _sess: this walk targets the user-data WT instance's
    // metadata, not the keydb's metadata.
    WT_SESSION* session = nullptr;
    int res = conn->open_session(conn, nullptr, nullptr, &session);
    if (res) {
        LOGV2_ERROR(29097,
                    "seedRefcountsFromWtMetadata: open_session failed",
                    "err"_attr = wiredtiger_strerror(res));
        return;
    }
    std::unique_ptr<WT_SESSION, std::function<void(WT_SESSION*)>> session_guard(
        session, [](WT_SESSION* s) { s->close(s, nullptr); });

    WT_CURSOR* cursor = nullptr;
    res = session->open_cursor(session, "metadata:", nullptr, nullptr, &cursor);
    if (res) {
        LOGV2_ERROR(29098,
                    "seedRefcountsFromWtMetadata: open_cursor on metadata failed",
                    "err"_attr = wiredtiger_strerror(res));
        return;
    }
    std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> cursor_guard(
        cursor, [](WT_CURSOR* c) { c->close(c); });

    // Walk metadata into a temp map first; then take _refcounts_lock once
    // and apply both the URI counts and the active anchors atomically.
    // Doing it in two phases keeps the cursor walk out of the
    // _refcounts_lock critical section (the walk can be slow on a large
    // metadata) and avoids holding the lock across an external callback.
    std::map<std::string, std::size_t> uriCounts;
    std::size_t uriRefs = 0;
    while ((res = cursor->next(cursor)) == 0) {
        const char* uri;
        const char* metaCfg;
        if (cursor->get_key(cursor, &uri) != 0 || cursor->get_value(cursor, &metaCfg) != 0)
            continue;
        // Only file: URIs back actual idents that go through the
        // encryptor. Tables, indexes, etc. either delegate to file: URIs
        // (whose metadata we'll see separately) or aren't encrypted at
        // the WT layer. file: URIs whose creation predates the upgrade
        // carry the legacy bare "<dbName>" keyId; those are tracked
        // exactly like generation keyIds and reaped via the same path.
        if (!StringData(uri).starts_with("file:"))
            continue;
        std::string keyId;
        if (!parseKeyIdFromMetadata(StringData(metaCfg), keyId))
            continue;
        ++uriCounts[keyId];
        ++uriRefs;
    }
    if (res != WT_NOTFOUND) {
        LOGV2_ERROR(29099,
                    "seedRefcountsFromWtMetadata: metadata cursor walk failed",
                    "err"_attr = wiredtiger_strerror(res));
        // Fall through: we still apply whatever we collected, plus the
        // active-anchor portion -- a partial seed is better than none.
    }

    // PSMDB-1997 diagnostic: read every keyid currently in table:key on the
    // keys DB so we can flag any URI-referenced or anchored keyid that has
    // no row in table:key (the orphan that drives the bad-decrypt panic on
    // wrongkey_replset.js's correct-key restart). The walk runs on the
    // keys DB's own session under _lock_sess; intentionally separate from
    // the _refcounts_lock critical section below. The result is held as a
    // std::map<keyid, char> to reuse the already-included <map> header
    // rather than pull in <set> just for membership lookup.
    std::map<std::string, char> keyRowIds;
    {
        std::lock_guard<std::mutex> lk(_lock_sess);
        WT_CURSOR* keyCursor = nullptr;
        int kres = _sess->open_cursor(_sess, "table:key", nullptr, nullptr, &keyCursor);
        if (kres) {
            LOGV2_ERROR(29105,
                        "seedRefcountsFromWtMetadata: open_cursor on table:key failed",
                        "err"_attr = wiredtiger_strerror(kres));
        } else {
            std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> kg(
                keyCursor, [](WT_CURSOR* c) { c->close(c); });
            while ((kres = keyCursor->next(keyCursor)) == 0) {
                char* k;
                if (keyCursor->get_key(keyCursor, &k) == 0) {
                    keyRowIds.emplace(std::string(k), 0);
                }
            }
            if (kres != WT_NOTFOUND) {
                LOGV2_ERROR(29106,
                            "seedRefcountsFromWtMetadata: table:key cursor walk failed",
                            "err"_attr = wiredtiger_strerror(kres));
            }
        }
    }

    // Build the URI-orphan list: keyids referenced in user-data metadata
    // but missing from table:key. Loud (LOGV2 not LOGV2_DEBUG) because
    // finding even one names the keyid that's about to fail decryption.
    std::vector<std::string> uriOrphans;
    for (const auto& [keyId, _] : uriCounts) {
        if (keyRowIds.count(keyId) == 0)
            uriOrphans.push_back(keyId);
    }

    // Apply atomically.
    std::size_t distinct = 0;
    {
        std::lock_guard<std::mutex> lkrc(_refcounts_lock);
        for (auto& [keyId, count] : uriCounts) {
            _refcounts[keyId] += count;
        }
        distinct = _refcounts.size();
    }

    LOGV2(29100,
          "seedRefcountsFromWtMetadata: seeded refcounts",
          "uriRefs"_attr = uriRefs,
          "distinctKeyIds"_attr = distinct,
          "tableKeyRows"_attr = keyRowIds.size(),
          "uriOrphans"_attr = uriOrphans);

    if (!uriOrphans.empty()) {
        LOGV2_WARNING(29107,
                      "seedRefcountsFromWtMetadata: orphan keyIds detected -- "
                      "the keys DB is missing rows that user-data metadata "
                      "references; opening any URI under an orphaned keyId "
                      "will fall into get_key_by_id's 'create key if it does "
                      "not exist' path and trigger a bad-decrypt panic on the "
                      "next page read",
                      "uriOrphans"_attr = uriOrphans);
    }
}

int EncryptionKeyDB::store_gcm_iv_reserved() {
    uint8_t tmp[_gcm_iv_bytes];
    auto end = export_bits(_gcm_iv_reserved, tmp, 8, false);

    int res;
    // open cursor
    WT_CURSOR* cursor;
    std::lock_guard<std::mutex> lk(_lock_sess);
    res = _sess->open_cursor(_sess, "table:parameters", nullptr, nullptr, &cursor);
    if (res) {
        LOGV2_ERROR(29047,
                    "store_gcm_iv_reserved: error opening cursor: {desc}",
                    "desc"_attr = wiredtiger_strerror(res));
        return res;
    }

    // create cursor delete guard
    std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> cursor_guard(
        cursor, [](WT_CURSOR* c) { c->close(c); });

    // put new value into the DB
    WT_ITEM v;
    v.size = end - tmp;
    v.data = tmp;
    cursor->set_key(cursor, gcm_iv_key);
    cursor->set_value(cursor, &v);
    res = cursor->insert(cursor);
    if (res) {
        LOGV2_ERROR(29048,
                    "cursor->insert error {code}: {desc}",
                    "code"_attr = res,
                    "desc"_attr = wiredtiger_strerror(res));
        return res;
    }
    return 0;
}

int EncryptionKeyDB::reserve_gcm_iv_range() {
    _gcm_iv_reserved += (1 << 12);
    return store_gcm_iv_reserved();
}

int EncryptionKeyDB::get_iv_gcm(uint8_t* buf, int len) {
    std::lock_guard<std::recursive_mutex> lk(_lock);
    ++_gcm_iv;
    uint8_t tmp[_gcm_iv_bytes];
    auto end = export_bits(_gcm_iv, tmp, 8, false);
    int ls = end - tmp;
    memset(buf, 0, len);
    memcpy(buf, tmp, std::min(len, ls));
    if (_gcm_iv > _gcm_iv_reserved) {
        return reserve_gcm_iv_range();
    }
    return 0;
}

void EncryptionKeyDB::store_pseudo_bytes(uint8_t* buf, int len) {
    invariant((len % 4) == 0);
    std::lock_guard<std::recursive_mutex> lk(_lock);
    for (int i = 0; i < len / 4; ++i) {
        *(int32_t*)buf = _prng->nextInt32();
        buf += 4;
    }
}

void EncryptionKeyDB::reconfigure(const char* newCfg) {
    // For now we don't use event handler in EncryptionKeyDB
    WT_EVENT_HANDLER* wtEventHandler = nullptr;

    auto startTime = Date_t::now();
    LOGV2(29075, "Closing KeyDB in preparation for reconfiguring");
    close_handles();
    LOGV2(29076, "KeyDB closed", "duration"_attr = Date_t::now() - startTime);

    startTime = Date_t::now();
    WT_CONNECTION* conn = nullptr;
    invariantWTOK(wiredtiger_open(_path.c_str(), wtEventHandler, _wtOpenConfig.c_str(), &conn),
                  nullptr);
    LOGV2(29077, "KeyDB re-opened", "duration"_attr = Date_t::now() - startTime);

    startTime = Date_t::now();
    LOGV2(29078, "Reconfiguring KeyDB", "newConfig"_attr = newCfg);
    invariantWTOK(conn->reconfigure(conn, newCfg), nullptr);
    LOGV2(29079, "KeyDB reconfigure complete", "duration"_attr = Date_t::now() - startTime);

    _connection = std::make_unique<WiredTigerConnection>(
        conn, _fastClockSource.get(), /*sessionCacheMax=*/33000);
}

namespace encryption {

namespace {

// Resolve the user-data `WiredTigerKVEngine` via the storage engine
// registered on `opCtx`'s service context. Returns nullptr if encryption
// is not enabled or the engine isn't WT-based. We avoid passing the
// engine in explicitly so the hook stays decoupled from KV-engine
// selection.
WiredTigerKVEngine* getWtEngine(OperationContext* opCtx) {
    auto se = opCtx->getServiceContext()->getStorageEngine();
    if (!se) {
        return nullptr;
    }
    return dynamic_cast<WiredTigerKVEngine*>(se->getEngine());
}

// Reads the encryption keyId baked into the WT ident metadata for
// `ident`. Returns boost::none if metadata cannot be read or has no
// usable keyId (so the caller falls through to the next candidate).
// Uses the file-local `parseKeyIdFromMetadata` (defined further up in
// this translation unit) rather than `WiredTigerUtil::getEncryptionKeyId`
// (which is a deferred-cleanup-branch helper not present on this branch).
boost::optional<std::string> readKeyIdFromIdent(WiredTigerSession& session, StringData ident) {
    auto metadata =
        WiredTigerUtil::getMetadataCreate(session, WiredTigerUtil::buildTableUri(ident));
    if (!metadata.isOK()) {
        LOGV2_DEBUG(29200,
                    3,
                    "activeKeyIdForDb: unable to read WT metadata for ident",
                    "ident"_attr = ident,
                    "error"_attr = metadata.getStatus());
        return boost::none;
    }
    std::string keyId;
    if (!parseKeyIdFromMetadata(StringData(metadata.getValue()), keyId)) {
        return boost::none;
    }
    if (keyId.empty() || keyId == "/default") {
        return boost::none;
    }
    return keyId;
}

}  // namespace

std::string activeKeyIdForDb(OperationContext* opCtx, const DatabaseName& dbName) {
    invariant(opCtx);

    std::string dbStr =
        DatabaseNameUtil::serialize(dbName, SerializationContext::stateDefault());

    // Early-startup fallback. The MDB catalog ident is created from
    // inside the `StorageEngineImpl` constructor, before the storage
    // engine is registered on the ServiceContext. In that window we
    // can't reach the EncryptionKeyDB through the storage engine, but
    // the catalog ident's dbName ("_mdb_catalog") never gets dropped
    // and recreated either -- so falling back to the legacy bare-
    // `<dbName>` keyId keeps it stable across restarts.
    auto* wtEngine = getWtEngine(opCtx);
    if (!wtEngine) {
        return dbStr;
    }

    EncryptionKeyDB* keyDb = wtEngine->getEncryptionKeyDB();
    invariant(keyDb, "activeKeyIdForDb called when encryption is disabled");

    // Fast path: cache hit. The cacheActiveKeyIdIfAbsent call returns
    // whatever's currently in the cache (the passed-in `*cached` is
    // discarded for an existing entry) and adds +1 URI ref atomically.
    // If another thread cleared the cache entry between tryGet and here,
    // cacheActiveKeyIdIfAbsent re-installs `*cached` and counts both the
    // anchor and the URI ref.
    if (auto cached = keyDb->tryGetCachedActiveKeyId(dbName)) {
        return keyDb->cacheActiveKeyIdIfAbsent(dbName, *cached);
    }

    // Cache miss: scan the CollectionCatalog for any live collection in
    // `dbName` and reuse its keyId. We use `CollectionCatalog::range`
    // rather than `getAllCollectionNamesFromDb` because the latter wants
    // a MODE_S DB lock that's incompatible with the MODE_IX held by an
    // in-progress createCollection.
    boost::optional<std::string> resolved;
    auto catalog = CollectionCatalog::get(opCtx);
    auto range = catalog->range(dbName);
    if (!range.empty()) {
        auto session = wtEngine->getConnection().getUninterruptibleSession();
        for (auto* coll : range) {
            if (!coll) {
                continue;
            }
            auto* rs = coll->getRecordStore();
            if (!rs) {
                continue;
            }
            auto keyId = readKeyIdFromIdent(*session, rs->getIdent());
            if (keyId) {
                resolved = std::move(*keyId);
                break;
            }
        }
    }

    if (!resolved) {
        // Genuinely-new database: allocate a fresh `<dbName>.<UUID>`.
        // dbNames cannot contain '.', so the dot in `<dbName>.<UUID>`
        // unambiguously separates the parts.
        resolved = dbStr + "." + UUID::gen().toString();
        LOGV2_DEBUG(29201,
                    1,
                    "activeKeyIdForDb: allocated fresh keyId",
                    logAttrs(dbName),
                    "keyId"_attr = *resolved);
    }

    // Atomic check-and-set. If a concurrent thread won the race, we use
    // its keyId so all idents created in this WUOW agree on a single
    // value. Installs the cache anchor (+1 on _refcounts) on insert.
    return keyDb->cacheActiveKeyIdIfAbsent(dbName, std::move(*resolved));
}

}  // namespace encryption

}  // namespace mongo

extern "C" void store_pseudo_bytes(uint8_t* buf, int len) {
    invariant(mongo::encryptionKeyDB);
    mongo::encryptionKeyDB->store_pseudo_bytes(buf, len);
}

extern "C" void rotation_store_pseudo_bytes(uint8_t* buf, int len) {
    invariant(mongo::rotationKeyDB);
    mongo::rotationKeyDB->store_pseudo_bytes(buf, len);
}

extern "C" int get_iv_gcm(uint8_t* buf, int len) {
    invariant(mongo::encryptionKeyDB);
    return mongo::encryptionKeyDB->get_iv_gcm(buf, len);
}

extern "C" int rotation_get_iv_gcm(uint8_t* buf, int len) {
    invariant(mongo::rotationKeyDB);
    return mongo::rotationKeyDB->get_iv_gcm(buf, len);
}

// returns encryption key from keys DB
// create key if it does not exists
// return key from keyfile if len == 0
extern "C" int get_key_by_id(const char* keyid, size_t len, unsigned char* key, void* pe) {
    invariant(mongo::encryptionKeyDB);
    return mongo::encryptionKeyDB->get_key_by_id(keyid, len, key, pe);
}

extern "C" int rotation_get_key_by_id(const char* keyid, size_t len, unsigned char* key, void* pe) {
    invariant(mongo::rotationKeyDB);
    return mongo::rotationKeyDB->get_key_by_id(keyid, len, key, pe);
}

extern "C" int notify_uri_dropped(const char* keyid, size_t len) {
    // The encryption extension may fire uri_dropped during connection
    // teardown after the keydb singleton has been reset to nullptr; in
    // that case the engine is going away and there is nothing to clean
    // up, so silently no-op rather than crashing.
    if (mongo::encryptionKeyDB == nullptr)
        return 0;
    mongo::encryptionKeyDB->onUriDropped(std::string(keyid, len));
    return 0;
}

extern "C" int rotation_notify_uri_dropped(const char* keyid, size_t len) {
    // Same teardown-safety rationale as notify_uri_dropped; the rotation
    // instance also disappears at end-of-rotation, before the connection
    // it backs is necessarily quiesced.
    if (mongo::rotationKeyDB == nullptr)
        return 0;
    mongo::rotationKeyDB->onUriDropped(std::string(keyid, len));
    return 0;
}

extern "C" void generate_secure_key(unsigned char* key) {
    invariant(mongo::encryptionKeyDB);
    mongo::encryptionKeyDB->generate_secure_key(key);
}
