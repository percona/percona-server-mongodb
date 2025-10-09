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


#include <cstring>

#include <openssl/err.h>

#include "mongo/base/status.h"
#include "mongo/db/storage/wiredtiger/encryption_keydb_c_api.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_data_protector.h"
#include "mongo/logv2/log.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kStorage


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

    template <typename T, typename DataRangeType>
    T* buffer_at(DataRangeType* range, size_t offset = 0) {
        return reinterpret_cast<T*>(range->data()) + offset;
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

Status WiredTigerDataProtectorCBC::protect(ConstDataRange in, DataRange* out) {
    invariant(out != nullptr);
    size_t bytesWritten = 0;

    if (_first) {
        _first = false;

        // reserve space for CRC32c
        std::memset(out->data(), 0, _chksum_len);
        bytesWritten += _chksum_len;

        uint8_t *iv = buffer_at<uint8_t>(out, bytesWritten);
        store_pseudo_bytes(iv, _iv_len);
        bytesWritten += _iv_len;

        if (1 != EVP_EncryptInit_ex(_ctx, _cipher, nullptr, _masterkey, iv))
            return handleCryptoErrors();
    }

    int encrypted_len = 0;
    if (1 !=
        EVP_EncryptUpdate(_ctx,
                          buffer_at<unsigned char>(out, bytesWritten),
                          &encrypted_len,
                          buffer_at<const unsigned char>(&in),
                          in.length()))
        return handleCryptoErrors();
    invariant(encrypted_len >= 0);
    bytesWritten += encrypted_len;
    crc32c.process_bytes(in.data(), in.length());

    *out = DataRange(out->data(), bytesWritten);

    return Status::OK();
}

Status WiredTigerDataProtectorCBC::finalize(DataRange* out) {
    invariant(out != nullptr);
    int encrypted_len = 0;
    if (1 != EVP_EncryptFinal_ex(_ctx, buffer_at<unsigned char>(out), &encrypted_len))
        return handleCryptoErrors();
    invariant(encrypted_len >= 0);

    *out = DataRange(out->data(), encrypted_len);

    return Status::OK();
}

std::size_t WiredTigerDataProtectorCBC::getNumberOfBytesReservedForTag() const {
    return _chksum_len;
}

Status WiredTigerDataProtectorCBC::finalizeTag(DataRange* out) {
    invariant(out != nullptr);
    out->write<uint32_t>(crc32c());
    *out = DataRange(out->data(), _chksum_len);
    return Status::OK();
}


WiredTigerDataProtectorGCM::WiredTigerDataProtectorGCM() {
    _cipher = EVP_aes_256_gcm();
    _iv_len = EVP_CIPHER_iv_length(_cipher);
}

WiredTigerDataProtectorGCM::~WiredTigerDataProtectorGCM() {}

Status WiredTigerDataProtectorGCM::protect(ConstDataRange in, DataRange* out) {
    invariant(out != nullptr);
    size_t bytesWritten = 0;

    if (_first) {
        _first = false;

        // reserve space for GCM tag
        std::memset(out->data(), 0, _gcm_tag_len);
        bytesWritten += _gcm_tag_len;

        uint8_t *iv = buffer_at<uint8_t>(out, bytesWritten);
        if (0 != get_iv_gcm(iv, _iv_len))
            return Status(ErrorCodes::InternalError,
                          "failed generating IV for GCM");
        bytesWritten += _iv_len;

        if (1 != EVP_EncryptInit_ex(_ctx, _cipher, nullptr, _masterkey, iv))
            return handleCryptoErrors();
    }

    int encrypted_len = 0;
    if (1 !=
        EVP_EncryptUpdate(_ctx,
                          buffer_at<unsigned char>(out, bytesWritten),
                          &encrypted_len,
                          buffer_at<const unsigned char>(&in),
                          in.length()))
        return handleCryptoErrors();
    bytesWritten += encrypted_len;

    *out = DataRange(out->data(), bytesWritten);

    return Status::OK();
}

Status WiredTigerDataProtectorGCM::finalize(DataRange* out) {
    invariant(out != nullptr);
    int encrypted_len = 0;
    if (1 != EVP_EncryptFinal_ex(_ctx, buffer_at<unsigned char>(out), &encrypted_len))
        return handleCryptoErrors();
    invariant(encrypted_len >= 0);

    *out = DataRange(out->data(), encrypted_len);

    return Status::OK();
}

std::size_t WiredTigerDataProtectorGCM::getNumberOfBytesReservedForTag() const {
    return _gcm_tag_len;
}

Status WiredTigerDataProtectorGCM::finalizeTag(DataRange* out) {
    invariant(out != nullptr);
    // get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_GET_TAG, _gcm_tag_len, out->data()))
        return handleCryptoErrors();
    *out = DataRange(out->data(), _gcm_tag_len);
    return Status::OK();
}


}  // namespace mongo
