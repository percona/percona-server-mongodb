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

#include "mongo/db/database_name.h"
#include "mongo/db/encryption/key.h"
#include "mongo/db/storage/storage_engine.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_connection.h"
#include "mongo/platform/random.h"

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <wiredtiger.h>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/optional.hpp>

namespace mongo {

class EncryptionKeyDB {
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
    int get_key_by_id(const char* keyid, size_t len, unsigned char* key, void* pe);

    // drop key for specific keyid (used in dropDatabase)
    int delete_key_by_id(const std::string& keyid);

    // Returns all key IDs (database names) stored in the key database.
    // Excludes the master key (empty keyid) and special keys like "/default".
    // Used for deferred encryption key cleanup.
    std::vector<std::string> getAllKeyIds();

    // Returns true if the key ID is a special/reserved key that should not be
    // included in user key lists (empty key for master key, "/default" key).
    static bool isSpecialKeyId(const std::string& keyId);

    // Returns the cached active key id for the database, if any. The cache is
    // populated by `cacheActiveKeyIdIfAbsent` during the catalog-scan based
    // resolution and cleared by `clearCachedActiveKeyId` when the database is
    // dropped. A cache miss does not imply the database has no key id - it only
    // means this process has not resolved one yet.
    boost::optional<std::string> tryGetCachedActiveKeyId(const DatabaseName& dbName) const;

    // Inserts `keyId` as the active key id for `dbName` only if no entry
    // exists yet, and returns whatever value is in the cache after the
    // operation. This atomicity matters when concurrent threads race to
    // resolve the active key id of the same database; only one of them will
    // win the insert and all callers will agree on the value.
    std::string cacheActiveKeyIdIfAbsent(const DatabaseName& dbName, std::string keyId);

    // Removes the cached active key id for `dbName`. The next call to
    // `encryption::activeKeyIdForDb` will cold-miss, scan the (now empty)
    // catalog and allocate a fresh key id.
    void clearCachedActiveKeyId(const DatabaseName& dbName);

    // Returns a snapshot of all currently-cached active key id values. Used by
    // the orphan key cleanup pass to avoid reaping a freshly-allocated key id
    // before it has had a chance to attach to an ident on disk.
    std::vector<std::string> getAllCachedActiveKeyIds() const;

    // get new counter value for IV in GCM mode
    int get_iv_gcm(uint8_t* buf, int len);

    // len should be multiple of 4
    void store_pseudo_bytes(uint8_t* buf, int len);

    // get connection for hot backup procedure to create backup
    WiredTigerConnection* getConnection() const {
        return _connection.get();
    }

    // reconfigure wiredtiger (used for downgrade)
    // after reconfiguration this instance is not fully functional
    // for example _sess pointer is null
    void reconfigure(const char*);

    // generate secure encryption key
    // _srng use protected by _lock_key
    void generate_secure_key(unsigned char* key);

    StatusWith<std::deque<KVBackupBlock>> beginNonBlockingBackup(
        OperationContext* opCtx,
        boost::optional<Timestamp> checkpointTimestamp,
        const StorageEngine::BackupOptions& options);

    Status endNonBlockingBackup(OperationContext* opCtx);

    StatusWith<std::deque<std::string>> extendBackupCursor(OperationContext* opCtx);

    const encryption::Key& masterKey() const noexcept {
        return _masterkey;
    }

    const std::string& path() const noexcept {
        return _path;
    }

private:
    typedef boost::multiprecision::uint128_t _gcm_iv_type;

    EncryptionKeyDB(const std::string& path, const encryption::Key& masterKey, bool rotation);

    // tries to read master key from specified file
    // then opens WT connection
    // throws exceptions if something goes wrong
    void init();

    int _openWiredTiger(const std::string& path, const std::string& wtOpenConfig);

    // during rotation copies data from provided instance
    void import_data_from(const EncryptionKeyDB* proto);

    StatusWith<std::deque<KVBackupBlock>> _disableIncrementalBackup();

    void close_handles();
    int store_gcm_iv_reserved();
    int reserve_gcm_iv_range();
    void generate_secure_key_inlock(char key[]);  // uses _srng without locks

    const bool _rotation;
    const std::string _path;
    std::string _wtOpenConfig;
    std::unique_ptr<ClockSource> _fastClockSource;
    std::unique_ptr<WiredTigerConnection> _connection;
    std::recursive_mutex _lock;  // _prng, _gcm_iv, _gcm_iv_reserved
    std::mutex _lock_sess;       // _sess
    std::mutex _lock_key;  // serialize access to the encryption keys table, also protects _srng
    WT_SESSION* _sess = nullptr;
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

    // Cache of resolved active key ids per database, scoped to the lifetime of
    // this `EncryptionKeyDB` instance. This is the source of truth for "which
    // key id should new idents in dbName X use" once warmed up; on a miss
    // `encryption::activeKeyIdForDb` consults the catalog and populates it.
    mutable std::mutex _activeKeyIdMutex;
    std::map<DatabaseName, std::string> _activeKeyIds;

    std::unique_ptr<WiredTigerSession> _backupSession;
    WT_CURSOR* _backupCursor;
};

namespace encryption {

/**
 * Returns the active encryption key id for the given database.
 *
 * The lookup goes through the per-process cache on the global `EncryptionKeyDB`:
 *   1. Cache hit: the cached key id is returned immediately.
 *   2. Cache miss: scan the `CollectionCatalog` for any live collection in
 *      `dbName`. If one exists, read its WT ident metadata to extract the
 *      `keyid="..."` clause; that key id is cached and returned. The first key
 *      id found wins, so a database that already contains tables continues to
 *      use the same key id its tables were created with (this preserves
 *      backward compatibility with the legacy bare-`<dbName>` format).
 *   3. Catalog empty: a fresh key id of the form `<dbName>.<UUID>` is
 *      generated, cached and returned. After a `dropDatabase` followed by a
 *      recreate this is the path that produces a new generation.
 *
 * Requires `opCtx` to be non-null and to carry a `WiredTigerRecoveryUnit` so
 * that the catalog scan and any per-ident metadata reads can be performed.
 */
std::string activeKeyIdForDb(OperationContext* opCtx, const DatabaseName& dbName);

}  // namespace encryption

}  // namespace mongo
