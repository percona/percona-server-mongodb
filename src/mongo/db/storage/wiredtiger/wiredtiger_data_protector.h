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

#include <boost/crc.hpp>

#include <openssl/evp.h>

#include "mongo/db/storage/data_protector.h"

namespace mongo {

class WiredTigerDataProtector: public DataProtector
{
public:
    WiredTigerDataProtector();
    virtual ~WiredTigerDataProtector();

protected:
    static constexpr int _key_len{32};
    unsigned char _masterkey[_key_len];
    const EVP_CIPHER *_cipher{nullptr};
    int _iv_len;
    bool _first{true};
    EVP_CIPHER_CTX *_ctx{nullptr};
};

class WiredTigerDataProtectorCBC: public WiredTigerDataProtector
{
public:
    WiredTigerDataProtectorCBC();
    virtual ~WiredTigerDataProtectorCBC();

    /**
     * Copy `inLen` bytes from `in`, process them, and write the processed bytes into `out`.
     * As processing may produce more or fewer bytes than were provided, the actual number
     * of bytes written will placed in `bytesWritten`.
     */
    Status protect(ConstDataRange in, DataRange* out) override;

    /**
     * Declares that this DataProtector will be provided no more data to protect.
     * Fills `out` with any leftover state that needs serialization.
     */
    Status finalize(DataRange* out) override;

    /**
     * Returns the number of bytes reserved for metadata at the end of the last output
     * buffer.
     * Not all implementations will choose to reserve this space. They will return 0.
     */
    std::size_t getNumberOfBytesReservedForTag() const override;

    /**
     * Fills buffer `out` of size `outLen`, with implementation defined metadata that had to be
     * calculated after finalization.
     * `bytesWritten` is filled with the number of bytes written into `out`.
     */
    Status finalizeTag(DataRange* out) override;

private:
    static constexpr int _chksum_len{sizeof(uint32_t)};
    boost::crc_optimal<32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true, true> crc32c;
};

class WiredTigerDataProtectorGCM: public WiredTigerDataProtector
{
public:
    WiredTigerDataProtectorGCM();
    virtual ~WiredTigerDataProtectorGCM();

    /**
     * Copy `inLen` bytes from `in`, process them, and write the processed bytes into `out`.
     * As processing may produce more or fewer bytes than were provided, the actual number
     * of bytes written will placed in `bytesWritten`.
     */
    Status protect(ConstDataRange in, DataRange* out) override;

    /**
     * Declares that this DataProtector will be provided no more data to protect.
     * Fills `out` with any leftover state that needs serialization.
     */
    Status finalize(DataRange* out) override;

    /**
     * Returns the number of bytes reserved for metadata at the end of the last output
     * buffer.
     * Not all implementations will choose to reserve this space. They will return 0.
     */
    std::size_t getNumberOfBytesReservedForTag() const override;

    /**
     * Fills buffer `out` of size `outLen`, with implementation defined metadata that had to be
     * calculated after finalization.
     * `bytesWritten` is filled with the number of bytes written into `out`.
     */
    Status finalizeTag(DataRange* out) override;

private:
    static constexpr int _gcm_tag_len{16};
};

}  // namespace mongo
