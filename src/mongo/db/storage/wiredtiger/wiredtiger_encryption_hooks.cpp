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


#include <boost/filesystem/path.hpp>

#include <openssl/err.h>

#include <wiredtiger.h>

#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/storage/wiredtiger/encryption_keydb.h"
#include "mongo/db/storage/wiredtiger/encryption_keydb_c_api.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_data_protector.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_encryption_hooks.h"
#include "mongo/logv2/log.h"
#include "mongo/util/database_name_util.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kStorage


namespace mongo {

namespace {
    class EVPCipherCtx {
    public:
        EVPCipherCtx() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            EVP_CIPHER_CTX_init(&_ctx_value);
#else
            _ctx= EVP_CIPHER_CTX_new();
#endif
        }

        ~EVPCipherCtx() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            EVP_CIPHER_CTX_cleanup(&_ctx_value);
#else
            EVP_CIPHER_CTX_free(_ctx);
#endif
        }

        operator EVP_CIPHER_CTX* () {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            return &_ctx_value;
#else
            return _ctx;
#endif
        }

    private:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX _ctx_value;
#else
        EVP_CIPHER_CTX *_ctx{nullptr};
#endif
    };

    // callback for ERR_print_errors_cb
    static int err_print_cb(const char *str, size_t len, void *param) {
        LOGV2_ERROR(29029, "{str}", "str"_attr = str);
        return 1;
    }

    Status handleCryptoErrors() {
        ERR_print_errors_cb(&err_print_cb, nullptr);
        return Status(ErrorCodes::InternalError,
                      "libcrypto error");
    }
}


WiredTigerEncryptionHooks::WiredTigerEncryptionHooks(EncryptionKeyDB* encryptionKeyDB)
    : _encryptionKeyDB(encryptionKeyDB) {}

WiredTigerEncryptionHooks::~WiredTigerEncryptionHooks() = default;

bool WiredTigerEncryptionHooks::enabled() const {
    return true;
}

bool WiredTigerEncryptionHooks::restartRequired() {
    return false;
}

StatusWith<std::deque<KVBackupBlock>> WiredTigerEncryptionHooks::beginNonBlockingBackup(
    OperationContext* opCtx,
    boost::optional<Timestamp> checkpointTimestamp,
    const StorageEngine::BackupOptions& options) {
    return _encryptionKeyDB->beginNonBlockingBackup(opCtx, checkpointTimestamp, options);
}

Status WiredTigerEncryptionHooks::endNonBlockingBackup(OperationContext* opCtx) {
    return _encryptionKeyDB->endNonBlockingBackup(opCtx);
}

StatusWith<std::deque<std::string>> WiredTigerEncryptionHooks::extendBackupCursor(
    OperationContext* opCtx) {
    return _encryptionKeyDB->extendBackupCursor(opCtx);
}

const unsigned char* WiredTigerEncryptionHooks::dbKey(boost::optional<DatabaseName> dbName,
                                                      unsigned char* buf) {
    if (!dbName) {
        // static local initialization is thread safe since C++11
        static const struct TmpKey {
            unsigned char _tmpkey[_key_len];
            TmpKey() {
                // generate temporary key valid only while current process is running
                generate_secure_key(static_cast<unsigned char*>(_tmpkey));
            }
        } tmp_key_holder;
        return static_cast<const unsigned char*>(tmp_key_holder._tmpkey);
    }
    std::string dbNameStr =
        DatabaseNameUtil::serialize(*dbName, SerializationContext::stateDefault());
    get_key_by_id(dbNameStr.c_str(), dbNameStr.length(), buf, nullptr);
    return buf;
}


WiredTigerEncryptionHooksCBC::WiredTigerEncryptionHooksCBC(EncryptionKeyDB* encryptionKeyDB)
    : WiredTigerEncryptionHooks(encryptionKeyDB) {
    _cipher = EVP_aes_256_cbc();
    _iv_len = EVP_CIPHER_iv_length(_cipher);
    // get wiredTiger's crc32c function
    wiredtiger_checksum_crc32c = wiredtiger_crc32c_func();
}

WiredTigerEncryptionHooksCBC::~WiredTigerEncryptionHooksCBC() {}

Status WiredTigerEncryptionHooksCBC::protectTmpData(const uint8_t* in,
                                                    size_t inLen,
                                                    uint8_t* out,
                                                    size_t outLen,
                                                    size_t* resultLen,
                                                    boost::optional<DatabaseName> dbName) {

    if (outLen < _chksum_len + _iv_len + inLen + EVP_CIPHER_block_size(_cipher))
        return Status(ErrorCodes::InternalError,
                      "encryption output buffer not big enough");

    *resultLen = 0;
    EVPCipherCtx ctx;

    *(uint32_t*)(out + *resultLen) = wiredtiger_checksum_crc32c(in, inLen);
    *resultLen += _chksum_len;

    uint8_t *iv = out + *resultLen;
    store_pseudo_bytes(iv, _iv_len);
    *resultLen += _iv_len;

    unsigned char db_key[_key_len];
    if (1 !=
        EVP_EncryptInit_ex(
            ctx, _cipher, nullptr, dbKey(dbName, static_cast<unsigned char*>(db_key)), iv))
        return handleCryptoErrors();

    int encrypted_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, out + *resultLen, &encrypted_len, in, inLen))
        return handleCryptoErrors();
    *resultLen += encrypted_len;

    if (1 != EVP_EncryptFinal_ex(ctx, out + *resultLen, &encrypted_len))
        return handleCryptoErrors();
    *resultLen += encrypted_len;

    return Status::OK();
}

Status WiredTigerEncryptionHooksCBC::unprotectTmpData(const uint8_t* in,
                                                      size_t inLen,
                                                      uint8_t* out,
                                                      size_t outLen,
                                                      size_t* resultLen,
                                                      boost::optional<DatabaseName> dbName) {

    *resultLen = 0;
    EVPCipherCtx ctx;

    uint32_t crc32c = *(uint32_t*)in;
    in += _chksum_len;
    inLen -= _chksum_len;

    unsigned char db_key[_key_len];
    if (1 !=
        EVP_DecryptInit_ex(
            ctx, _cipher, nullptr, dbKey(dbName, static_cast<unsigned char*>(db_key)), in))
        return handleCryptoErrors();
    in += _iv_len;
    inLen -= _iv_len;

    int decrypted_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, out, &decrypted_len, in, inLen))
        return handleCryptoErrors();
    *resultLen += decrypted_len;
    in += inLen;
    inLen = 0;

    if (1 != EVP_DecryptFinal_ex(ctx, out + *resultLen, &decrypted_len))
        return handleCryptoErrors();
    *resultLen += decrypted_len;

    if (wiredtiger_checksum_crc32c(out, *resultLen) != crc32c)
        return Status(ErrorCodes::InternalError,
                      "Decrypted data integrity check has failed. "
                      "Probably the data or the encryption key is corrupted.");

    return Status::OK();
}

size_t WiredTigerEncryptionHooksCBC::additionalBytesForProtectedBuffer() {
    return _chksum_len + _iv_len + EVP_CIPHER_block_size(_cipher);
}

std::unique_ptr<DataProtector> WiredTigerEncryptionHooksCBC::getDataProtector() {
    return std::make_unique<WiredTigerDataProtectorCBC>();
}

boost::filesystem::path WiredTigerEncryptionHooksCBC::getProtectedPathSuffix() {
    return ".aes256-cbc";
}


WiredTigerEncryptionHooksGCM::WiredTigerEncryptionHooksGCM(EncryptionKeyDB* encryptionKeyDB)
    : WiredTigerEncryptionHooks(encryptionKeyDB) {
    _cipher = EVP_aes_256_gcm();
    _iv_len = EVP_CIPHER_iv_length(_cipher);
}

WiredTigerEncryptionHooksGCM::~WiredTigerEncryptionHooksGCM() {}

Status WiredTigerEncryptionHooksGCM::protectTmpData(const uint8_t* in,
                                                    size_t inLen,
                                                    uint8_t* out,
                                                    size_t outLen,
                                                    size_t* resultLen,
                                                    boost::optional<DatabaseName> dbName) {

    if (outLen < _iv_len + inLen + _gcm_tag_len)
        return Status(ErrorCodes::InternalError,
                      "encryption output buffer not big enough");

    *resultLen = 0;
    EVPCipherCtx ctx;

    // reserve space for GCM tag
    *resultLen += _gcm_tag_len;

    uint8_t *iv = out + *resultLen;
    if (0 != get_iv_gcm(iv, _iv_len))
        return Status(ErrorCodes::InternalError,
                      "failed generating IV for GCM");
    *resultLen += _iv_len;

    unsigned char db_key[_key_len];
    if (1 !=
        EVP_EncryptInit_ex(
            ctx, _cipher, nullptr, dbKey(dbName, static_cast<unsigned char*>(db_key)), iv))
        return handleCryptoErrors();

    // we don't provide any AAD data yet

    int encrypted_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, out + *resultLen, &encrypted_len, in, inLen))
        return handleCryptoErrors();
    *resultLen += encrypted_len;

    if (1 != EVP_EncryptFinal_ex(ctx, out + *resultLen, &encrypted_len))
        return handleCryptoErrors();
    *resultLen += encrypted_len;

    // get the tag and place it at the beginning of the output buffer
    // (to be compatible with the file layout used for rollback files)
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, _gcm_tag_len, out))
        return handleCryptoErrors();

    return Status::OK();
}

Status WiredTigerEncryptionHooksGCM::unprotectTmpData(const uint8_t* in,
                                                      size_t inLen,
                                                      uint8_t* out,
                                                      size_t outLen,
                                                      size_t* resultLen,
                                                      boost::optional<DatabaseName> dbName) {

    *resultLen = 0;
    EVPCipherCtx ctx;

    // skip GCM tag
    uint8_t* gcm_tag = const_cast<uint8_t*>(in);
    in += _gcm_tag_len;
    inLen -= _gcm_tag_len;

    unsigned char db_key[_key_len];
    if (1 !=
        EVP_DecryptInit_ex(
            ctx, _cipher, nullptr, dbKey(dbName, static_cast<unsigned char*>(db_key)), in))
        return handleCryptoErrors();
    in += _iv_len;
    inLen -= _iv_len;

    // we have no AAD yet

    int decrypted_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, out, &decrypted_len, in, inLen))
        return handleCryptoErrors();
    *resultLen += decrypted_len;
    in += inLen;
    inLen = 0;

    // Set expected tag value. Works in OpenSSL 1.0.1d and later
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, _gcm_tag_len, gcm_tag))
        return handleCryptoErrors();

    if (1 != EVP_DecryptFinal_ex(ctx, out + *resultLen, &decrypted_len))
        return handleCryptoErrors();
    *resultLen += decrypted_len;

    return Status::OK();
}

size_t WiredTigerEncryptionHooksGCM::additionalBytesForProtectedBuffer() {
    return _iv_len + _gcm_tag_len;
}

std::unique_ptr<DataProtector> WiredTigerEncryptionHooksGCM::getDataProtector() {
    return std::make_unique<WiredTigerDataProtectorGCM>();
}

boost::filesystem::path WiredTigerEncryptionHooksGCM::getProtectedPathSuffix() {
    return ".aes256-gcm";
}

}  // namespace mongo
