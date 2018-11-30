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

#include "mongo/platform/random.h"
#include "mongo/stdx/mutex.h"

namespace mongo {

class EncryptionKeyDB
{
public:
    EncryptionKeyDB(const std::string& path);
    ~EncryptionKeyDB();

    // tries to read master key from specified file
    // then opens WT connection
    // throws exceptions if something goes wrong
    void init();

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

private:
    typedef boost::multiprecision::uint128_t _gcm_iv_type;

    int store_gcm_iv_reserved();
    int reserve_gcm_iv_range();

    static constexpr int _key_len = 32;
    const std::string _path;
    unsigned char _masterkey[_key_len];
    WT_CONNECTION *_conn = nullptr;
    stdx::recursive_mutex _lock;  // _prng, _gcm_iv, _gcm_iv_reserved
    stdx::mutex _lock_sess;  // _sess
    stdx::mutex _lock_key;  // serialize access to the encryption keys table, also protects _srng
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
};

}  // namespace mongo
