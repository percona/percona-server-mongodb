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

#include <cstring>

#include <openssl/err.h>

#include "mongo/base/status.h"
#include "mongo/db/storage/wiredtiger/encryption_keydb_c_api.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_data_protector.h"
#include "mongo/logv2/log.h"


namespace mongo {

namespace {
    // callback for ERR_print_errors_cb
    static int err_print_cb(const char *str, size_t len, void *param) {
        LOGV2_ERROR(29028, "{str}", "str"_attr = str);
        return 1;
    }

    Status handleCryptoErrors() {
        ERR_print_errors_cb(&err_print_cb, nullptr);
        return Status(ErrorCodes::InternalError,
                      "libcrypto error");
    }
}


WiredTigerDataProtector::WiredTigerDataProtector() {
    // get master key
    get_key_by_id(nullptr, 0, _masterkey, nullptr);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    _ctx = new EVP_CIPHER_CTX{};
    EVP_CIPHER_CTX_init(_ctx);
#else
    _ctx= EVP_CIPHER_CTX_new();
#endif
}

WiredTigerDataProtector::~WiredTigerDataProtector() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(_ctx);
    delete _ctx;
#else
    EVP_CIPHER_CTX_free(_ctx);
#endif
}


WiredTigerDataProtectorCBC::WiredTigerDataProtectorCBC() {
    _cipher = EVP_aes_256_cbc();
    _iv_len = EVP_CIPHER_iv_length(_cipher);
}

WiredTigerDataProtectorCBC::~WiredTigerDataProtectorCBC() {}

Status WiredTigerDataProtectorCBC::protect(const std::uint8_t* in,
                                        std::size_t inLen,
                                        std::uint8_t* out,
                                        std::size_t outLen,
                                        std::size_t* bytesWritten) {
    *bytesWritten = 0;

    if (_first) {
        _first = false;

        // reserve space for CRC32c
        std::memset(out + *bytesWritten, 0, _chksum_len);
        *bytesWritten += _chksum_len;

        uint8_t *iv = out + *bytesWritten;
        store_pseudo_bytes(iv, _iv_len);
        *bytesWritten += _iv_len;

        if (1 != EVP_EncryptInit_ex(_ctx, _cipher, nullptr, _masterkey, iv))
            return handleCryptoErrors();
    }

    int encrypted_len = 0;
    if (1 != EVP_EncryptUpdate(_ctx, out + *bytesWritten, &encrypted_len, in, inLen))
        return handleCryptoErrors();
    *bytesWritten += encrypted_len;
    crc32c.process_bytes(in, inLen);

    return Status::OK();
}

Status WiredTigerDataProtectorCBC::finalize(std::uint8_t* out, std::size_t outLen, std::size_t* bytesWritten) {
    int encrypted_len = 0;
    if (1 != EVP_EncryptFinal_ex(_ctx, out, &encrypted_len))
        return handleCryptoErrors();
    *bytesWritten = encrypted_len;

    return Status::OK();
}

std::size_t WiredTigerDataProtectorCBC::getNumberOfBytesReservedForTag() const {
    return _chksum_len;
}

Status WiredTigerDataProtectorCBC::finalizeTag(std::uint8_t* out,
                                            std::size_t outLen,
                                            std::size_t* bytesWritten) {
    *(uint32_t*)out = crc32c();
    *bytesWritten = _chksum_len;
    return Status::OK();
}


WiredTigerDataProtectorGCM::WiredTigerDataProtectorGCM() {
    _cipher = EVP_aes_256_gcm();
    _iv_len = EVP_CIPHER_iv_length(_cipher);
}

WiredTigerDataProtectorGCM::~WiredTigerDataProtectorGCM() {}

Status WiredTigerDataProtectorGCM::protect(const std::uint8_t* in,
                                        std::size_t inLen,
                                        std::uint8_t* out,
                                        std::size_t outLen,
                                        std::size_t* bytesWritten) {
    *bytesWritten = 0;

    if (_first) {
        _first = false;

        // reserve space for GCM tag
        std::memset(out + *bytesWritten, 0, _gcm_tag_len);
        *bytesWritten += _gcm_tag_len;

        uint8_t *iv = out + *bytesWritten;
        if (0 != get_iv_gcm(iv, _iv_len))
            return Status(ErrorCodes::InternalError,
                          "failed generating IV for GCM");
        *bytesWritten += _iv_len;

        if (1 != EVP_EncryptInit_ex(_ctx, _cipher, nullptr, _masterkey, iv))
            return handleCryptoErrors();
    }

    int encrypted_len = 0;
    if (1 != EVP_EncryptUpdate(_ctx, out + *bytesWritten, &encrypted_len, in, inLen))
        return handleCryptoErrors();
    *bytesWritten += encrypted_len;

    return Status::OK();
}

Status WiredTigerDataProtectorGCM::finalize(std::uint8_t* out, std::size_t outLen, std::size_t* bytesWritten) {
    int encrypted_len = 0;
    if (1 != EVP_EncryptFinal_ex(_ctx, out, &encrypted_len))
        return handleCryptoErrors();
    *bytesWritten = encrypted_len;

    return Status::OK();
}

std::size_t WiredTigerDataProtectorGCM::getNumberOfBytesReservedForTag() const {
    return _gcm_tag_len;
}

Status WiredTigerDataProtectorGCM::finalizeTag(std::uint8_t* out,
                                            std::size_t outLen,
                                            std::size_t* bytesWritten) {
    // get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_GET_TAG, _gcm_tag_len, out))
        return handleCryptoErrors();
    *bytesWritten += _gcm_tag_len;
    return Status::OK();
}


}  // namespace mongo
