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

#include <openssl/evp.h>

#include "mongo/db/storage/encryption_hooks.h"

namespace mongo {
class EncryptionKeyDB;

class WiredTigerEncryptionHooks: public EncryptionHooks
{
public:
    explicit WiredTigerEncryptionHooks(EncryptionKeyDB* encryptionKeyDB);
    virtual ~WiredTigerEncryptionHooks() override;

    /**
     * Returns true if the encryption hooks are enabled.
     */
    virtual bool enabled() const override;

    /**
     * Perform any encryption engine initialization/sanity checking that needs to happen after
     * storage engine initialization but before the server starts accepting incoming connections.
     *
     * Returns true if the server needs to be rebooted because of configuration changes.
     */
    virtual bool restartRequired() override;

    /**
     * Inform the encryption storage system to prepare its data such that its files can be copied
     * along with MongoDB data files for a backup.
     */
    virtual StatusWith<std::deque<KVBackupBlock>> beginNonBlockingBackup(
        OperationContext* opCtx,
        boost::optional<Timestamp> checkpointTimestamp,
        const StorageEngine::BackupOptions& options) override;

    /**
     * Inform the encryption storage system that it can release resources associated with a
     * previous call to `beginNonBlockingBackup`. This function may be called without a pairing
     * `beginNonBlockingBackup`. In that case it must return `Status::OK()`;
     */
    virtual Status endNonBlockingBackup(OperationContext* opCtx) override;

    /**
     * Get list of log files changed since the moment of backup cursor creation
     */
    virtual StatusWith<std::deque<std::string>> extendBackupCursor(
        OperationContext* opCtx) override;

protected:
    EncryptionKeyDB* _encryptionKeyDB;
    static constexpr int _key_len{32};
    const EVP_CIPHER *_cipher{nullptr};
    int _iv_len = 0;

    const unsigned char* dbKey(boost::optional<DatabaseName> dbName, unsigned char* buf);
};

class WiredTigerEncryptionHooksCBC: public WiredTigerEncryptionHooks
{
public:
    explicit WiredTigerEncryptionHooksCBC(EncryptionKeyDB* encryptionKeyDB);
    virtual ~WiredTigerEncryptionHooksCBC() override;

    /**
     * Transform temp data to non-readable form before writing it to disk.
     */
    Status protectTmpData(ConstDataRange in,
                          DataRange* out,
                          boost::optional<DatabaseName> dbName) override;

    /**
     * Tranforms temp data back to readable form, after reading from disk.
     */
    Status unprotectTmpData(ConstDataRange in,
                            DataRange* out,
                            boost::optional<DatabaseName> dbName) override;

    /**
     * Returns the maximum size addition when doing transforming temp data.
     */
    virtual size_t additionalBytesForProtectedBuffer() override;

    /**
     * Get the data protector object
     */
    virtual std::unique_ptr<DataProtector> getDataProtector() override;

    /**
     * Get an implementation specific path suffix to tag files with
     */
    virtual boost::filesystem::path getProtectedPathSuffix() override;

private:
    static constexpr int _chksum_len{sizeof(uint32_t)};
    uint32_t (*wiredtiger_checksum_crc32c)(const void *, size_t);
};

class WiredTigerEncryptionHooksGCM: public WiredTigerEncryptionHooks
{
public:
    explicit WiredTigerEncryptionHooksGCM(EncryptionKeyDB* encryptionKeyDB);
    virtual ~WiredTigerEncryptionHooksGCM() override;

    /**
     * Transform temp data to non-readable form before writing it to disk.
     */
    Status protectTmpData(ConstDataRange in,
                          DataRange* out,
                          boost::optional<DatabaseName> dbName) override;

    /**
     * Tranforms temp data back to readable form, after reading from disk.
     */
    Status unprotectTmpData(ConstDataRange in,
                            DataRange* out,
                            boost::optional<DatabaseName> dbName) override;

    /**
     * Returns the maximum size addition when doing transforming temp data.
     */
    virtual size_t additionalBytesForProtectedBuffer() override;

    /**
     * Get the data protector object
     */
    virtual std::unique_ptr<DataProtector> getDataProtector() override;

    /**
     * Get an implementation specific path suffix to tag files with
     */
    virtual boost::filesystem::path getProtectedPathSuffix() override;

private:
    static constexpr int _gcm_tag_len{16};
};

}  // namespace mongo
