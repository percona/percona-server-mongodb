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

#include "mongo/db/database_name.h"
#include "mongo/db/database_name_util.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/service_context.h"
#include "mongo/db/shard_role/shard_catalog/collection.h"
#include "mongo/db/shard_role/shard_catalog/collection_catalog.h"
#include "mongo/db/storage/record_store.h"
#include "mongo/db/storage/storage_engine.h"
#include "mongo/db/storage/wiredtiger/encryption_keydb_c_api.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_kv_engine.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_recovery_unit.h"
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
        invariant(pe);
        _encryptors[c_str] = pe;
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
    invariant(pe);
    _encryptors[c_str] = pe;
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

    // prepare encryptor for reuse in case DB with the same name will be recreated
    // it is not an error if encryptor is not found - that means customize was not called
    // for the keyid and it will be called when necessary (in theory this may happen if
    // DB is dropped just after mongod is started and before any read/write operations)
    auto it = _encryptors.find(keyid);
    if (it != _encryptors.end()) {
        invariant(it->second);
        percona_encryption_extension_drop_keyid(it->second);
        _encryptors.erase(it);
    }

    return res;
}

bool EncryptionKeyDB::isSpecialKeyId(const std::string& keyId) {
    return keyId.empty() || keyId == "/default";
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
    std::lock_guard<std::mutex> lk(_activeKeyIdMutex);
    auto [it, inserted] = _activeKeyIds.try_emplace(dbName, std::move(keyId));
    return it->second;
}

void EncryptionKeyDB::clearCachedActiveKeyId(const DatabaseName& dbName) {
    std::lock_guard<std::mutex> lk(_activeKeyIdMutex);
    _activeKeyIds.erase(dbName);
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

std::vector<std::string> EncryptionKeyDB::getAllKeyIds() {
    std::vector<std::string> keyIds;

    WT_CURSOR* cursor;
    std::lock_guard<std::mutex> lk(_lock_sess);
    int res = _sess->open_cursor(_sess, "table:key", nullptr, nullptr, &cursor);
    if (res) {
        LOGV2_ERROR(
            29155, "getAllKeyIds: error opening cursor", "error"_attr = wiredtiger_strerror(res));
        return keyIds;
    }

    // Create cursor close guard
    std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> cursor_guard(
        cursor, [](WT_CURSOR* c) { c->close(c); });

    while ((res = cursor->next(cursor)) == 0) {
        char* k;
        res = cursor->get_key(cursor, &k);
        if (res == 0 && k != nullptr) {
            std::string keyId(k);
            if (!isSpecialKeyId(keyId)) {
                keyIds.emplace_back(std::move(keyId));
            }
        }
    }

    if (res != WT_NOTFOUND) {
        LOGV2_ERROR(
            29156, "getAllKeyIds: error iterating cursor", "error"_attr = wiredtiger_strerror(res));
    }

    LOGV2_DEBUG(29157, 2, "getAllKeyIds: found keys", "count"_attr = keyIds.size());
    return keyIds;
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

// Resolve the user-data WiredTigerKVEngine via the storage engine stored on
// `opCtx`'s service context. We avoid passing the engine in explicitly so the
// hook stays decoupled from kv-engine selection. Returns nullptr if encryption
// is not enabled or the engine is not WiredTiger-based.
WiredTigerKVEngine* getWtEngine(OperationContext* opCtx) {
    auto se = opCtx->getServiceContext()->getStorageEngine();
    if (!se) {
        return nullptr;
    }
    return dynamic_cast<WiredTigerKVEngine*>(se->getEngine());
}

// Reads the encryption key id stored in the WiredTiger metadata for the given
// `ident`. Returns boost::none if the metadata cannot be read or contains no
// key id, in which case the caller should fall through to the next candidate.
boost::optional<std::string> readKeyIdFromIdent(WiredTigerSession& session, StringData ident) {
    auto metadata = WiredTigerUtil::getMetadataCreate(session, WiredTigerUtil::buildTableUri(ident));
    if (!metadata.isOK()) {
        LOGV2_DEBUG(29200,
                    3,
                    "activeKeyIdForDb: unable to read WT metadata for ident",
                    "ident"_attr = ident,
                    "error"_attr = metadata.getStatus());
        return boost::none;
    }
    auto keyId = WiredTigerUtil::getEncryptionKeyId(metadata.getValue());
    if (!keyId || EncryptionKeyDB::isSpecialKeyId(*keyId)) {
        return boost::none;
    }
    return keyId;
}

}  // namespace

std::string activeKeyIdForDb(OperationContext* opCtx, const DatabaseName& dbName) {
    invariant(opCtx);

    std::string dbStr =
        DatabaseNameUtil::serialize(dbName, SerializationContext::stateDefault());

    // Early-startup fallback. The MDB catalog ident is created from inside the
    // `StorageEngineImpl` constructor, *before* the StorageEngine has been
    // registered on the ServiceContext. At that point we can't reach the
    // EncryptionKeyDB through the storage engine, but the catalog also doesn't
    // need per-generation key ids - its dbName ("_mdb_catalog") never gets
    // dropped and recreated. Fall back to the legacy bare-`<dbName>` keyid in
    // this window; it matches what the pre-generation code emitted, so the
    // catalog ident keeps using the same key id across restarts.
    auto* wtEngine = getWtEngine(opCtx);
    if (!wtEngine) {
        return dbStr;
    }

    EncryptionKeyDB* keyDb = wtEngine->getEncryptionKeyDB();
    invariant(keyDb, "activeKeyIdForDb called when encryption is disabled");

    if (auto cached = keyDb->tryGetCachedActiveKeyId(dbName)) {
        return *cached;
    }

    // Scan the catalog for any live collection in `dbName` and reuse its key
    // id. We pick the first one that yields a usable key id; on a healthy
    // system every collection in a given db shares the same key id, so the
    // choice doesn't matter. Defensive fall-through handles legacy / mixed
    // states where some idents have no encryption clause.
    //
    // We use `CollectionCatalog::range` rather than `getAllCollectionNamesFromDb`
    // because the latter requires the caller to hold the DB lock in MODE_S, which
    // is incompatible with the MODE_IX held by an in-progress createCollection.
    // `range` iterates an immutable snapshot and tolerates concurrent mutation.
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
        // Fresh generation: `<dbName>.<UUID>`. The dot is unambiguous because
        // MongoDB database names cannot contain '.'.
        resolved = dbStr + "." + UUID::gen().toString();
        LOGV2_DEBUG(29201,
                    1,
                    "activeKeyIdForDb: allocated fresh key id",
                    logAttrs(dbName),
                    "keyId"_attr = *resolved);
    }

    // Atomic check-and-set: another thread may have raced with us and won the
    // insert. In that case we discard our value and use the winner's so all
    // idents created in this WUOW agree on the same key id.
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

extern "C" void generate_secure_key(unsigned char* key) {
    invariant(mongo::encryptionKeyDB);
    mongo::encryptionKeyDB->generate_secure_key(key);
}
