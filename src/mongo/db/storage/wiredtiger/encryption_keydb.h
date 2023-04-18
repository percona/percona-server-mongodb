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

#pragma once

#include <map>
#include <string>

#include <boost/multiprecision/cpp_int.hpp>
#include <wiredtiger.h>

#include "mongo/db/encryption/key.h"
#include "mongo/db/storage/storage_engine.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_session_cache.h"
#include "mongo/platform/mutex.h"
#include "mongo/platform/random.h"

namespace mongo {

class EncryptionKeyDB
{
public:
    ~EncryptionKeyDB();

    /// @brief Open an existing key database or creates a new one.
    ///
    /// @param path Path to the directory where the existing key database is
    ///             stored or the new database should be created. In the latter
    ///             case, the path must point to an existing empty directory.
    /// @param masterKey The master key for decrypting the existing database
    ///                  or encrypting the new one.
    ///
    /// @throws std::runtime_error if can't open the encryption key database
    /// or craete the new one at the specified path
    static std::unique_ptr<EncryptionKeyDB> create(const std::string& path,
                                                   const encryption::Key& masterKey);

    /// @brief Clones the database for the purpose of master key rotation.
    ///
    /// Creates a new encryption key database with data identidal to that of this one
    /// and stores it at the specifed path. The difference with this database is that
    /// the new one is encrypted with a new master key. The function is intended to
    /// be used only for master key rotation.
    ///
    /// @param path Path to the directory where the database should be created;
    ///             must point to an existing empty directory.
    /// @param masterKey The master key for encrypting the new database.
    ///
    /// @returns Copy of this encryption key database suitable for master key rotation.
    ///
    /// @throws std::runtime_error if can't craete a key database new one at the specified path or
    /// can't copy the data to the just created database.
    std::unique_ptr<EncryptionKeyDB> clone(const std::string& path,
                                           const encryption::Key& masterKey) const;

    // returns encryption key from keys DB
    // create key if it does not exists
    // return key from keyfile if len == 0
    int get_key_by_id(const char *keyid, size_t len, unsigned char *key, void *pe);

    // drop key for specific keyid (used in dropDatabase)
    int delete_key_by_id(const std::string&  keyid);

    // get new counter value for IV in GCM mode
    int get_iv_gcm(uint8_t *buf, int len);

    // len should be multiple of 4
    void store_pseudo_bytes(uint8_t *buf, int len);

    // get connection for hot backup procedure to create backup
    WT_CONNECTION*  getConnection() const { return _conn; }

    // reconfigure wiredtiger (used for downgrade)
    // after reconfiguration this instance is not fully functional
    // for example _sess pointer is null
    void reconfigure(const char *);

    // generate secure encryption key
    // _srng use protected by _lock_key
    void generate_secure_key(unsigned char* key);

    StatusWith<std::deque<StorageEngine::BackupBlock>> beginNonBlockingBackup(
        const StorageEngine::BackupOptions& options);

    Status endNonBlockingBackup();

    StatusWith<std::deque<std::string>> extendBackupCursor();

    const encryption::Key& masterKey() const noexcept {
        return _masterkey;
    }

    const std::string& path() const noexcept {
        return _path;
    }

private:
    typedef boost::multiprecision::uint128_t _gcm_iv_type;

    EncryptionKeyDB(const std::string& path, const encryption::Key& masterKey, const bool rotation);

    // tries to read master key from specified file
    // then opens WT connection
    // throws exceptions if something goes wrong
    void init();

    int _openWiredTiger(const std::string& path, const std::string& wtOpenConfig);

    // during rotation copies data from provided instance
    void import_data_from(const EncryptionKeyDB* proto);

    StatusWith<std::deque<StorageEngine::BackupBlock>> _disableIncrementalBackup();

    void close_handles();
    int store_gcm_iv_reserved();
    int reserve_gcm_iv_range();
    void generate_secure_key_inlock(char key[]);  // uses _srng without locks

    const bool _rotation;
    const std::string _path;
    std::string _wtOpenConfig;
    WT_CONNECTION *_conn = nullptr;
    stdx::recursive_mutex _lock;  // _prng, _gcm_iv, _gcm_iv_reserved
    Mutex _lock_sess = MONGO_MAKE_LATCH("EncryptionKeyDB::_lock_sess");  // _sess
    Mutex _lock_key = MONGO_MAKE_LATCH("EncryptionKeyDB::_lock_key");  // serialize access to the encryption keys table, also protects _srng
    WT_SESSION *_sess = nullptr;
    std::unique_ptr<SecureRandom> _srng;
    std::unique_ptr<PseudoRandom> _prng;
    encryption::Key _masterkey;
    _gcm_iv_type _gcm_iv{0};
    _gcm_iv_type _gcm_iv_reserved{0};
    static constexpr int _gcm_iv_bytes = (std::numeric_limits<decltype(_gcm_iv)>::digits + 7) / 8;
    // encryptors per db name
    // get_key_by_id creates entry
    // delete_key_by_it lets encryptor know that DB was deleted and deletes entry
    std::map<std::string, void*> _encryptors;

    std::unique_ptr<WiredTigerSession> _backupSession;
    WT_CURSOR* _backupCursor;
};

}  // namespace mongo
