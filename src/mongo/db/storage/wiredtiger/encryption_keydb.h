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

#include "mongo/db/storage/storage_engine.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_session_cache.h"
#include "mongo/platform/mutex.h"
#include "mongo/platform/random.h"

namespace mongo {

class EncryptionKeyDB
{
public:
    ~EncryptionKeyDB();

    /// @brief Creates a (possibly encrypted at rest) new encryption key database.
    ///
    /// @param path Path to the directory where the key db should be created;
    ///     the path must point to an existing empty directory
    /// @param kmipMasterKeyId In the case encryption is enabled and KMIP is used as
    ///     a key management solution, this is the identifier of the database master key.
    ///     If it is an empty string, then the function automatically creates a master key.
    ///     and uploads it to the KMIP server specified in configuration.
    ///     IF KMIP is not used, the parameter is ignored.
    ///
    /// @returns Crated key database
    ///
    /// @throws std::runtime_error if
    ///     1. the master key can't be read from or written to a KMIP or Vault server
    ///     2. Vault token file can't be read
    ///     3. can't create encryption key db at the specified path
    static std::unique_ptr<EncryptionKeyDB> create(const std::string& path,
                                                   const std::string& kmipMasterKeyId);

    /// @brief Reads (possibly encrypted at rest) the encryption key database.
    ///
    /// @param path Path to the directory with the encyption key database
    /// @param kmipMasterKeyId If the database is encrypted with a key stored using a KMIP-based
    ///     key management solution, this is the identifier of the database master key.
    ///     It can't be impty if the database is encrypted in that case. In all other cases,
    ///     the argument must be an empty string.
    ///
    /// @returns Read key database
    ///
    /// @throws std::runtime_error if
    ///     1. the master key can't be read from a KMIP or Vault server
    ///     2. Vault token file can't be read
    ///     3. can't read encryption key db at the specified path
    ///
    /// @note The function can't encrypt already existing non-encrypted key database.
    static std::unique_ptr<EncryptionKeyDB> read(const std::string& path,
                                                 const std::string& kmipMasterKeyId);

    /// @brief Clones the database.
    ///
    /// Creates a new encryption key database with data identidal to that of this one
    /// and stores it at the specifed path. The difference with this database is that
    /// the new one is encrypted with a new master key. The function is intended to
    /// be used only for master key rotation.
    ///
    /// Plase see the `create` function for the descriptions of parameters and thrown excepitons.
    /// Additionally, the function throws `std::runtime_error` if it can't copy this key database.
    ///
    /// @returns Identifier of a new KMIP master key if encryption is enabled and KMIP is used as
    ///     a key management solution and an empty string in all other cases.
    std::unique_ptr<EncryptionKeyDB> clone(const std::string& path,
                                           const std::string& kmipMasterKeyId);

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

    StatusWith<std::deque<BackupBlock>> beginNonBlockingBackup(
        OperationContext* opCtx,
        boost::optional<Timestamp> checkpointTimestamp,
        const StorageEngine::BackupOptions& options);

    Status endNonBlockingBackup(OperationContext* opCtx);

    StatusWith<std::deque<std::string>> extendBackupCursor(OperationContext* opCtx);

    const std::string& kmipMasterKeyId() const noexcept {
        return _kmipMasterKeyId;
    }

private:
    typedef boost::multiprecision::uint128_t _gcm_iv_type;

    EncryptionKeyDB(const bool pre_existed,
                    const std::string& path,
                    const std::string& kmipMasterKeyId,
                    const bool rotation);

    // tries to read master key from specified file
    // then opens WT connection
    // throws exceptions if something goes wrong
    void init();

    int _openWiredTiger(const std::string& path, const std::string& wtOpenConfig);

    // during rotation copies data from provided instance
    void import_data_from(EncryptionKeyDB* proto);

    // write master key to the Vault (during rotation)
    void store_masterkey();

    StatusWith<std::deque<BackupBlock>> _disableIncrementalBackup();

    void close_handles();
    int store_gcm_iv_reserved();
    int reserve_gcm_iv_range();
    void generate_secure_key_inlock(char key[]);  // uses _srng without locks

    void init_masterkey();

    static constexpr int _key_len = 32;
    const bool _pre_existed;
    const bool _rotation;
    const std::string _path;
    std::string _wtOpenConfig;
    std::string _kmipMasterKeyId;
    unsigned char _masterkey[_key_len];
    WT_CONNECTION *_conn = nullptr;
    stdx::recursive_mutex _lock;  // _prng, _gcm_iv, _gcm_iv_reserved
    Mutex _lock_sess = MONGO_MAKE_LATCH("EncryptionKeyDB::_lock_sess");  // _sess
    Mutex _lock_key = MONGO_MAKE_LATCH("EncryptionKeyDB::_lock_key");  // serialize access to the encryption keys table, also protects _srng
    WT_SESSION *_sess = nullptr;
    std::unique_ptr<SecureRandom> _srng;
    std::unique_ptr<PseudoRandom> _prng;
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
