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

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kStorage

#include <sys/stat.h>

#include <cstring>  // memcpy
#include <fstream>

#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/encryption/encryption_vault.h"
#include "mongo/db/encryption/encryption_kmip.h"
#include "mongo/db/server_options.h"
#include "mongo/db/storage/wiredtiger/encryption_keydb.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_util.h"
#include "mongo/logv2/log.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/base64.h"
#include "mongo/util/debug_util.h"

#include <third_party/wiredtiger/ext/encryptors/percona/encryption_keydb_c_api.h>


namespace mongo {

static EncryptionKeyDB *encryptionKeyDB = nullptr;
static EncryptionKeyDB *rotationKeyDB = nullptr;

static constexpr const char * gcm_iv_key = "_gcm_iv_reserved";
constexpr int EncryptionKeyDB::_key_len;
constexpr int EncryptionKeyDB::_gcm_iv_bytes;

static void dump_key(unsigned char *key, const int _key_len, const char * msg) {
    const char* m = "0123456789ABCDEF";
    char buf[_key_len * 3 + 1];
    char* p=buf;
    for (int i=0; i<_key_len; ++i) {
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
    WT_CURSOR *cursor;
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

EncryptionKeyDB::EncryptionKeyDB(const bool just_created, const std::string& path, const bool rotation)
  : _just_created(just_created),
    _rotation(rotation),
    _path(path) {
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
        dump_table(_sess, _key_len, "dump_table from destructor");
    if (_sess) {
        _gcm_iv_reserved = _gcm_iv;
        store_gcm_iv_reserved();
        _sess->close(_sess, nullptr);
        _sess = nullptr;
    }
    if (_conn) {
        _conn->close(_conn, nullptr);
        _conn = nullptr;
    }
}

// this function uses _srng without synchronization
// caller must ensure it is safe
void EncryptionKeyDB::generate_secure_key(char key[]) {
    _srng->fill(key, _key_len);
}

void EncryptionKeyDB::init_masterkey() {
    std::string encoded_key;
    if (!encryptionGlobalParams.kmipServerName.empty()) {
        if (_rotation) {
            // generate new key
            char newkey[_key_len];
            generate_secure_key(newkey);
            encoded_key = base64::encode(StringData{newkey, _key_len});
        } else {
            // read key from KMIP
            encoded_key = kmipReadKey();
            // empty key is returned when there was an error
            // if this happens on first run (with empty keydb) then
            // we can generate key here
            if (encoded_key.empty()) {
                if (!_just_created) {
                    throw std::runtime_error(
                        "Cannot start. Master encryption key is absent in KMIP. Check "
                        "configuration options.");
                }
                LOGV2(29043, "Master key is absent in KMIP. Generating and writing one.");
                char newkey[_key_len];
                generate_secure_key(newkey);
                encoded_key = base64::encode(StringData{newkey, _key_len});
                kmipWriteKey(encoded_key);
            }
        }
    } else if (!encryptionGlobalParams.vaultServerName.empty()) {
        if (encryptionGlobalParams.vaultToken.empty()) {
            struct stat stats;

            if (stat(encryptionGlobalParams.vaultTokenFile.c_str(), &stats) == -1) {
                throw std::runtime_error(str::stream()
                                         << "cannot read stats of the Vault token file: "
                                         << encryptionGlobalParams.vaultTokenFile
                                         << ": " << strerror(errno));
            }
            auto prohibited_perms{S_IRWXG | S_IRWXO};
            if (serverGlobalParams.relaxPermChecks && stats.st_uid == 0) {
                prohibited_perms = S_IWGRP | S_IXGRP | S_IRWXO;
            }
            if ((stats.st_mode & prohibited_perms) != 0) {
                throw std::runtime_error(str::stream()
                                         << "permissions on " << encryptionGlobalParams.vaultTokenFile
                                         << " are too open");
            }
            std::ifstream f(encryptionGlobalParams.vaultTokenFile);
            if (!f.is_open()) {
                throw std::runtime_error(str::stream()
                                         << "cannot open specified Vault token file: "
                                         << encryptionGlobalParams.vaultTokenFile);
            }
            f >> encryptionGlobalParams.vaultToken;
        }
        if (_rotation) {
            // generate new key
            char newkey[_key_len];
            generate_secure_key(newkey);
            encoded_key = base64::encode(StringData{newkey, _key_len});
        } else {
            // read key from the Vault
            encoded_key = vaultReadKey();
            // empty key is returned when there was HTTP error 404
            // if this happens on first run (with empty keydb) then
            // we can generate key here
            if (encoded_key.empty()) {
                if (!_just_created) {
                    throw std::runtime_error("Cannot start. Master encryption key is absent in the Vault. Check configuration options.");
                }
                LOGV2(29036, "Master key is absent in the Vault. Generating and writing one.");
                char newkey[_key_len];
                generate_secure_key(newkey);
                encoded_key = base64::encode(StringData{newkey, _key_len});
                vaultWriteKey(encoded_key);
            }
        }
    } else {
        struct stat stats;

        if (stat(encryptionGlobalParams.encryptionKeyFile.c_str(), &stats) == -1) {
            throw std::runtime_error(str::stream()
                                     << "cannot read stats of encryption key file: "
                                     << encryptionGlobalParams.encryptionKeyFile
                                     << ": " << strerror(errno));
        }
        auto prohibited_perms{S_IRWXG | S_IRWXO};
        if (serverGlobalParams.relaxPermChecks && stats.st_uid == 0) {
            prohibited_perms = S_IWGRP | S_IXGRP | S_IRWXO;
        }
        if ((stats.st_mode & prohibited_perms) != 0) {
            throw std::runtime_error(str::stream()
                                     << "permissions on " << encryptionGlobalParams.encryptionKeyFile
                                     << " are too open");
        }
        std::ifstream f(encryptionGlobalParams.encryptionKeyFile);
        if (!f.is_open()) {
            throw std::runtime_error(str::stream()
                                     << "cannot open specified encryption key file: "
                                     << encryptionGlobalParams.encryptionKeyFile);
        }
        f >> encoded_key;
    }

    auto key = base64::decode(encoded_key);
    if (key.length() != _key_len) {
        throw std::runtime_error(str::stream()
                                 << "encryption key length should be " << _key_len << " bytes");
    }
    memcpy(_masterkey, key.c_str(), _key_len);
}

// Open db with correct compatibility mode
// Based on WiredTigerKVEngine::_openWiredTiger
// Should be synced with changes in WiredTigerKVEngine::_openWiredTiger
int EncryptionKeyDB::_openWiredTiger(const std::string& path, const std::string& wtOpenConfig) {
    // For now we don't use event handler in EncryptionKeyDB
    WT_EVENT_HANDLER* wtEventHandler = nullptr;

    // MongoDB 4.4 will always run in compatibility version 10.0.
    std::string configStr = wtOpenConfig + ",compatibility=(require_min=\"10.0.0\")";
    int ret = wiredtiger_open(path.c_str(), wtEventHandler, configStr.c_str(), &_conn);
    if (!ret) {
        //_fileVersion = {WiredTigerFileVersion::StartupVersion::IS_44_FCV_44};
        return ret;
    }

    // MongoDB 4.4 doing clean shutdown in FCV 4.2 will use compatibility version 3.3.
    configStr = wtOpenConfig + ",compatibility=(require_min=\"3.3.0\")";
    ret = wiredtiger_open(path.c_str(), wtEventHandler, configStr.c_str(), &_conn);
    if (!ret) {
        //_fileVersion = {WiredTigerFileVersion::StartupVersion::IS_44_FCV_42};
        return ret;
    }

    // MongoDB 4.2 uses compatibility version 3.2.
    configStr = wtOpenConfig + ",compatibility=(require_min=\"3.2.0\")";
    ret = wiredtiger_open(path.c_str(), wtEventHandler, configStr.c_str(), &_conn);
    if (!ret) {
        //_fileVersion = {WiredTigerFileVersion::StartupVersion::IS_42};
        return ret;
    }

    LOGV2_WARNING(29054,
        "EncryptionKeyDB: Failed to start up WiredTiger under any compatibility version. "
        "This may be due to an unsupported upgrade or downgrade.");
    if (ret == WT_TRY_SALVAGE)
        LOGV2_WARNING(29055, "EncryptionKeyDB: WiredTiger metadata corruption detected");

    LOGV2_FATAL_NOTRACE(29056, "Terminating.", "Reason"_attr = wtRCToStatus(ret).reason());

    return ret;
}

void EncryptionKeyDB::init() {
    _srng = std::make_unique<SecureRandom>();
    _prng = std::make_unique<PseudoRandom>(_srng->nextInt64());
    try {
        init_masterkey();

        std::stringstream ss;
        ss << "create,";
        ss << "config_base=false,";
        // encryptionGlobalParams.encryptionCipherMode is not used here with a reason:
        // keys DB will always use CBC cipher because wiredtiger_open internally calls
        // encryption extension's encrypt function which depends on the GCM encryption counter
        // loaded later (see 'load parameters' section below)
        ss << "extensions=[local=(entry=percona_encryption_extension_init,early_load=true,config=(cipher=AES256-CBC" << (_rotation ? ",rotation=true" : ",rotation=false") << "))],";
        ss << "encryption=(name=percona,keyid=\"\"),";
        // logging configured; updates durable on application or system failure
        // https://source.wiredtiger.com/3.0.0/tune_durability.html
        ss << "log=(enabled,file_max=5MB),transaction_sync=(enabled=true,method=fsync),";
        std::string config = ss.str();
        LOGV2(29037, "Initializing KeyDB with wiredtiger_open config: {cfg}", "cfg"_attr = config);
        int res = _openWiredTiger(_path, config);
        if (res) {
            throw std::runtime_error(std::string("error opening keys DB at '") + _path + "': " + wiredtiger_strerror(res));
        }
        _wtOpenConfig = config;

        // empty keyid means masterkey
        res = _conn->open_session(_conn, nullptr, nullptr, &_sess);
        if (res) {
            throw std::runtime_error(std::string("error opening wiredTiger session: ") + wiredtiger_strerror(res));
        }

        if (kDebugBuild) dump_table(_sess, _key_len, "before create");
        // try to create 'key' table
        // ignore error if table already exists
        res = _sess->create(_sess, "table:key", "key_format=S,value_format=u,access_pattern_hint=random");
        if (res) {
            throw std::runtime_error(std::string("error creating/opening key table: ") + wiredtiger_strerror(res));
        }
        if (kDebugBuild) dump_table(_sess, _key_len, "after create");

        // try to create 'parameters' table
        // ignore error if table already exists
        res = _sess->create(_sess, "table:parameters", "key_format=S,value_format=u,access_pattern_hint=random");
        if (res) {
            throw std::runtime_error(std::string("error creating/opening parameters table: ") + wiredtiger_strerror(res));
        }

        // load parameters
        {
            WT_CURSOR *cursor;
            int res = _sess->open_cursor(_sess, "table:parameters", nullptr, nullptr, &cursor);
            if (res){
                throw std::runtime_error(std::string("error opening cursor: ") + wiredtiger_strerror(res));
            }
            // create cursor delete guard
            std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> cursor_guard(cursor, [](WT_CURSOR* c)
                {
                    c->close(c);
                });
            // load _gcm_iv_reserved from DB
            cursor->set_key(cursor, gcm_iv_key);
            res = cursor->search(cursor);
            if (res == 0) {
                WT_ITEM v;
                cursor->get_value(cursor, &v);
                import_bits(_gcm_iv_reserved, (uint8_t*)v.data, (uint8_t*)v.data + v.size, 8, false);
                _gcm_iv = _gcm_iv_reserved;
            }
            else if (res != WT_NOTFOUND) {
                throw std::runtime_error(std::string("error reading parameters: ") + wiredtiger_strerror(res));
            }
        }
    } catch (std::exception& e) {
        LOGV2_ERROR(29038, "Exception in EncryptionKeyDB::init: {e}", "e"_attr = e.what());
        throw;
    }
    LOGV2(29039, "Encryption keys DB is initialized successfully");
}

void EncryptionKeyDB::clone(EncryptionKeyDB *old) {
    // not doing any synchronization here because key rotation process is single threaded
    try {
        // copy parameters table
        // clone is called right after init(). at this point _gcm_iv_reserved is equal to _gcm_iv
        _gcm_iv_reserved = old->_gcm_iv_reserved;
        if (store_gcm_iv_reserved()) {
            throw std::runtime_error("failed to copy key db data during rotation");
        }
        // copy key table
        int res;
        auto cursor_close = [](WT_CURSOR* c){c->close(c);};
        WT_CURSOR *srcc;
        res = old->_sess->open_cursor(old->_sess, "table:key", nullptr, nullptr, &srcc);
        if (res)
            throw std::runtime_error(std::string("clone: error opening cursor: ") + wiredtiger_strerror(res));
        std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> srcc_guard(srcc, cursor_close);
        WT_CURSOR *dstc;
        res = _sess->open_cursor(_sess, "table:key", nullptr, nullptr, &dstc);
        if (res)
            throw std::runtime_error(std::string("clone: error opening cursor: ") + wiredtiger_strerror(res));
        std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> dstc_guard(dstc, cursor_close);
        while ((res = srcc->next(srcc)) == 0) {
            char* k;
            WT_ITEM v;
            if ((res = srcc->get_key(srcc, &k))
                || (res = srcc->get_value(srcc, &v)))
                throw std::runtime_error(std::string("clone: error getting key/value from the key table: ") + wiredtiger_strerror(res));
            invariant(v.size == _key_len);
            dstc->set_key(dstc, k);
            dstc->set_value(dstc, &v);
            if ((res = dstc->insert(dstc)) != 0)
                throw std::runtime_error(std::string("clone: error writing key table: ") + wiredtiger_strerror(res));
        }
        if (res != WT_NOTFOUND)
            throw std::runtime_error(std::string("clone: error reading key table: ") + wiredtiger_strerror(res));
    } catch (std::exception& e) {
        LOGV2_ERROR(29049, "Exception in EncryptionKeyDB::clone: {e}", "e"_attr = e.what());
        throw;
    }
}

void EncryptionKeyDB::store_masterkey() {
    auto encodedKey = base64::encode(StringData{(const char*)_masterkey, _key_len});
    if (!encryptionGlobalParams.kmipServerName.empty()) {
        kmipWriteKey(encodedKey);
    } else if (!encryptionGlobalParams.vaultServerName.empty()) {
        vaultWriteKey(encodedKey);
    } else {
        throw std::logic_error(
            "Can't save master key because neither HashiCorp's Vault nor "
            "KMIP server is configured");
    }
}

int EncryptionKeyDB::get_key_by_id(const char *keyid, size_t len, unsigned char *key, void *pe) {
    LOGV2_DEBUG(29050, 4, "get_key_by_id for keyid: '{id}'", "id"_attr = std::string{keyid, len});
    // return key from keyfile if len == 0
    if (len == 0) {
        memcpy(key, _masterkey, _key_len);
        if (kDebugBuild) dump_key(key, _key_len, "returning masterkey");
        return 0;
    }

    int res;
    // open cursor
    WT_CURSOR *cursor;
    {
        stdx::lock_guard<Latch> lk(_lock_sess);
        res = _sess->open_cursor(_sess, "table:key", nullptr, nullptr, &cursor);
        if (res){
            LOGV2_ERROR(29040, "get_key_by_id: error opening cursor: {err}", "err"_attr = wiredtiger_strerror(res));
            return res;
        }
    }

    // create cursor delete guard
    std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> cursor_guard(cursor, [](WT_CURSOR* c)
        {
            c->close(c);
        });

    // search/write of db encryption key should be atomic
    stdx::lock_guard<Latch> lk(_lock_key);
    // read key from DB
    std::string c_str(keyid, len);
    LOGV2_DEBUG(29041, 4, "trying to load encryption key for keyid: {id}", "id"_attr = c_str);
    cursor->set_key(cursor, c_str.c_str());
    res = cursor->search(cursor);
    if (res == 0) {
        WT_ITEM v;
        cursor->get_value(cursor, &v);
        invariant(v.size == _key_len);
        memcpy(key, v.data, _key_len);
        if (kDebugBuild) dump_key(key, _key_len, "loaded key from key DB");
        _encryptors[c_str] = pe;
        return 0;
    }
    if (res != WT_NOTFOUND) {
        LOGV2_ERROR(29042, "cursor->search error {code}: {desc}",
                    "code"_attr = res, "desc"_attr = wiredtiger_strerror(res));
        return res;
    }

    // create key if it does not exist
    // call to fill() is protected by _lock_key above
    _srng->fill(key, _key_len);
    WT_ITEM v;
    v.size = _key_len;
    v.data = key;
    cursor->set_key(cursor, c_str.c_str());
    cursor->set_value(cursor, &v);
    res = cursor->insert(cursor);
    if (res) {
        LOGV2_ERROR(29043, "cursor->insert error {code}: {desc}",
                    "code"_attr = res, "desc"_attr = wiredtiger_strerror(res));
        return res;
    }

    if (kDebugBuild) dump_key(key, _key_len, "generated and stored key");
    _encryptors[c_str] = pe;
    return 0;
}

int EncryptionKeyDB::delete_key_by_id(const std::string&  keyid) {
    LOGV2_DEBUG(29044, 4, "delete_key_by_id for keyid: '{id}'", "id"_attr = keyid);

    int res;
    // open cursor
    WT_CURSOR *cursor;
    {
        stdx::lock_guard<Latch> lk(_lock_sess);
        res = _sess->open_cursor(_sess, "table:key", nullptr, nullptr, &cursor);
        if (res){
            LOGV2_ERROR(29045, "delete_key_by_id: error opening cursor: {desc}", "desc"_attr = wiredtiger_strerror(res));
            return res;
        }
    }

    // create cursor delete guard
    std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> cursor_guard(cursor, [](WT_CURSOR* c)
        {
            c->close(c);
        });

    // delete key
    cursor->set_key(cursor, keyid.c_str());
    res = cursor->remove(cursor);
    if (res) {
        LOGV2_ERROR(29046, "cursor->remove error {code}: {desc}",
                    "code"_attr = res, "desc"_attr = wiredtiger_strerror(res));
    }

    // prepare encryptor for reuse in case DB with the same name will be recreated
    // it is not an error if encryptor is not found - that means customize was not called
    // for the keyid and it will be called when necessary (in theory this may happen if
    // DB is dropped just after mongod is started and before any read/write operations)
    auto it = _encryptors.find(keyid);
    if (it != _encryptors.end()) {
        percona_encryption_extension_drop_keyid(it->second);
        _encryptors.erase(it);
    }

    return res;
}

int EncryptionKeyDB::store_gcm_iv_reserved() {
    uint8_t tmp[_gcm_iv_bytes];
    auto end = export_bits(_gcm_iv_reserved, tmp, 8, false);

    int res;
    // open cursor
    WT_CURSOR *cursor;
    {
        stdx::lock_guard<Latch> lk(_lock_sess);
        res = _sess->open_cursor(_sess, "table:parameters", nullptr, nullptr, &cursor);
        if (res){
            LOGV2_ERROR(29047, "store_gcm_iv_reserved: error opening cursor: {desc}",
                       "desc"_attr = wiredtiger_strerror(res));
            return res;
        }
    }

    // create cursor delete guard
    std::unique_ptr<WT_CURSOR, std::function<void(WT_CURSOR*)>> cursor_guard(cursor, [](WT_CURSOR* c)
        {
            c->close(c);
        });

    // put new value into the DB
    WT_ITEM v;
    v.size = end - tmp;
    v.data = tmp;
    cursor->set_key(cursor, gcm_iv_key);
    cursor->set_value(cursor, &v);
    res = cursor->insert(cursor);
    if (res) {
        LOGV2_ERROR(29048, "cursor->insert error {code}: {desc}",
                    "code"_attr = res, "desc"_attr = wiredtiger_strerror(res));
        return res;
    }
    return 0;
}

int EncryptionKeyDB::reserve_gcm_iv_range() {
    _gcm_iv_reserved += (1<<12);
    return store_gcm_iv_reserved();
}

int EncryptionKeyDB::get_iv_gcm(uint8_t *buf, int len) {
    stdx::lock_guard<stdx::recursive_mutex> lk(_lock);
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

void EncryptionKeyDB::store_pseudo_bytes(uint8_t *buf, int len) {
    invariant((len % 4) == 0);
    stdx::lock_guard<stdx::recursive_mutex> lk(_lock);
    for (int i = 0; i < len / 4; ++i) {
        *(int32_t*)buf = _prng->nextInt32();
        buf += 4;
    }
}

void EncryptionKeyDB::reconfigure(const char *newCfg) {
    // For now we don't use event handler in EncryptionKeyDB
    WT_EVENT_HANDLER* wtEventHandler = nullptr;

    auto startTime = Date_t::now();
    LOGV2(29075, "Closing KeyDB in preparation for reconfiguring");
    close_handles();
    LOGV2(29076, "KeyDB closed", "duration"_attr = Date_t::now() - startTime);

    startTime = Date_t::now();
    invariantWTOK(wiredtiger_open(_path.c_str(), wtEventHandler, _wtOpenConfig.c_str(), &_conn));
    LOGV2(29077, "KeyDB re-opened", "duration"_attr = Date_t::now() - startTime);

    startTime = Date_t::now();
    LOGV2(29078, "Reconfiguring KeyDB", "newConfig"_attr = newCfg);
    invariantWTOK(_conn->reconfigure(_conn, newCfg));
    LOGV2(29079, "KeyDB reconfigure complete", "duration"_attr = Date_t::now() - startTime);
}

extern "C" void store_pseudo_bytes(uint8_t *buf, int len) {
    invariant(encryptionKeyDB);
    encryptionKeyDB->store_pseudo_bytes(buf, len);
}

extern "C" void rotation_store_pseudo_bytes(uint8_t *buf, int len) {
    invariant(rotationKeyDB);
    rotationKeyDB->store_pseudo_bytes(buf, len);
}

extern "C" int get_iv_gcm(uint8_t *buf, int len) {
    invariant(encryptionKeyDB);
    return encryptionKeyDB->get_iv_gcm(buf, len);
}

extern "C" int rotation_get_iv_gcm(uint8_t *buf, int len) {
    invariant(rotationKeyDB);
    return rotationKeyDB->get_iv_gcm(buf, len);
}

// returns encryption key from keys DB
// create key if it does not exists
// return key from keyfile if len == 0
extern "C" int get_key_by_id(const char *keyid, size_t len, unsigned char *key, void *pe) {
    invariant(encryptionKeyDB);
    return encryptionKeyDB->get_key_by_id(keyid, len, key, pe);
}

extern "C" int rotation_get_key_by_id(const char *keyid, size_t len, unsigned char *key, void *pe) {
    invariant(rotationKeyDB);
    return rotationKeyDB->get_key_by_id(keyid, len, key, pe);
}

}  // namespace mongo
