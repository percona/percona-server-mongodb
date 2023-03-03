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

#include <boost/crc.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include "mongo/platform/basic.h"

#include <memory>
#include <fstream>

#include <wiredtiger.h>

#include "mongo/base/init.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/encryption/key.h"
#include "mongo/db/json.h"
#include "mongo/db/storage/wiredtiger/encryption_keydb.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_data_protector.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_encryption_hooks.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_util.h"
#include "mongo/unittest/temp_dir.h"
#include "mongo/unittest/unittest.h"

namespace mongo {
namespace {

using std::string;

constexpr uint8_t data[]{
    0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01,
    0x69, 0x4b, 0x65, 0x39, 0x6b, 0x49, 0x74, 0x76, 0x67, 0x71, 0x7a, 0x4c, 0x6c, 0x35, 0x41, 0x62,
    0x7a, 0x30, 0x41, 0x53, 0x4c, 0x77, 0x53, 0x6b, 0x75, 0x52, 0x52, 0x70, 0x30, 0x67, 0x75, 0x6c,
    0x48, 0x4b, 0x48, 0x41, 0x76, 0x47, 0x35, 0x35, 0x63, 0x6f, 0x77, 0x3d, 0x0a,};

constexpr size_t datalen{sizeof(data)};

class EncryptionHarness {
public:
    EncryptionHarness(const string& mode) {
        encryptionGlobalParams.enableEncryption = true;
        encryptionGlobalParams.encryptionCipherMode = mode;
        encryptionGlobalParams.encryptionKeyFile = _keydbpath.path() + "/encryption_key_file";
        std::ofstream keyfile{encryptionGlobalParams.encryptionKeyFile};
        if (!keyfile.is_open()) {
            throw std::runtime_error(std::string("cannot open specified encryption key file: ")
                                                 + encryptionGlobalParams.encryptionKeyFile);
        }
        keyfile << "iKe9kItvgqzLl5Abz0ASLwSkuRRp0gulHKHAvG55cow=" << std::endl;
        // set keyfile permissions
        boost::filesystem::permissions(
            encryptionGlobalParams.encryptionKeyFile,
            boost::filesystem::owner_read | boost::filesystem::owner_write);

        _encryptionKeyDB = EncryptionKeyDB::create(_keydbpath.path(), encryption::Key());
    }

    ~EncryptionHarness() {
        _encryptionKeyDB.reset(nullptr);
    }

    EncryptionKeyDB* getKeyDB() const {
        return _encryptionKeyDB.get();
    }

private:
    unittest::TempDir _keydbpath{"keydb"};
    std::unique_ptr<EncryptionKeyDB> _encryptionKeyDB;
};

TEST(WiredTigerEncryptionTest, EncryptionCRC32C) {
    typedef boost::crc_optimal<32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true, true> crc32c_t;
    crc32c_t crc32c_a;
    crc32c_t crc32c_b;
    crc32c_a.process_bytes(data, sizeof(data));
    auto half = sizeof(data)/2;
    crc32c_b.process_bytes(data, half);
    crc32c_b.process_bytes(data + half, sizeof(data) - half);
    ASSERT_EQ(crc32c_a(), crc32c_b());

    auto wiredtiger_checksum_crc32c = wiredtiger_crc32c_func();
    ASSERT_EQ(crc32c_b(), wiredtiger_checksum_crc32c(data, sizeof(data)));

    crc32c_a.reset();
    for (unsigned int i = 0; i <= sizeof(data); ++i) {
        if (i != 0) {
            crc32c_a.process_bytes(data + i - 1, 1);
        }
        ASSERT_EQ(crc32c_a(), wiredtiger_checksum_crc32c(data, i));
    }
}

void test_encryption_hooks(WiredTigerEncryptionHooks* hooks) {
    ASSERT_TRUE(hooks->enabled());

    size_t protectedSizeMax = datalen + hooks->additionalBytesForProtectedBuffer();

    auto dataprotector{hooks->getDataProtector()};
    std::unique_ptr<uint8_t[]> protectorText;
    size_t protectorTextLen;
    {
        protectorText.reset(new uint8_t[protectedSizeMax]);
        auto datatoprotect = data;
        size_t dataleft = datalen;
        auto outbuf = protectorText.get();
        auto outbuflen = protectedSizeMax;
        size_t resultLen;
        while (dataleft > 0) {
            auto chunklen{dataleft/2 + 1};
            ASSERT_OK(dataprotector->protect(datatoprotect, chunklen, outbuf, outbuflen, &resultLen));
            dataleft -= chunklen;
            datatoprotect += chunklen;
            outbuflen -= resultLen;
            outbuf += resultLen;
        }
        ASSERT_OK(dataprotector->finalize(outbuf, outbuflen, &resultLen));
        outbuflen -= resultLen;
        outbuf += resultLen;
        // tag should be at the buffer's start (this is how it is placed in rollback files)
        // the space for tag is reserved by the first call to protect()
        ASSERT_OK(dataprotector->finalizeTag(protectorText.get(), protectedSizeMax, &resultLen));
        ASSERT_EQ(resultLen, dataprotector->getNumberOfBytesReservedForTag());
        protectorTextLen = outbuf - protectorText.get();
    }

    std::unique_ptr<uint8_t[]> cipherText;
    cipherText.reset(new uint8_t[protectedSizeMax]);
    size_t cipherLen;
    // pass boost::none to use ephemeral key
    ASSERT_OK(hooks->protectTmpData(
        data, datalen, cipherText.get(), protectedSizeMax, &cipherLen, boost::none));
    ASSERT_TRUE(cipherLen <= protectedSizeMax);
    ASSERT_EQ(protectorTextLen, cipherLen);

    std::unique_ptr<uint8_t[]> plainText;
    plainText.reset(new uint8_t[cipherLen]);
    size_t plainLen;
    // pass boost::none to use ephemeral key
    ASSERT_OK(hooks->unprotectTmpData(
        cipherText.get(), cipherLen, plainText.get(), cipherLen, &plainLen, boost::none));
    ASSERT_EQ(plainLen, datalen);
    ASSERT_EQ(0, memcmp(plainText.get(), data, datalen));

    // dataprotector uses masterkey to encrypt data so provide empty string to select correct key
    // for decryption
    ASSERT_OK(hooks->unprotectTmpData(protectorText.get(),
                                      protectorTextLen,
                                      plainText.get(),
                                      protectorTextLen,
                                      &plainLen,
                                      std::string()));
    ASSERT_EQ(plainLen, datalen);
    ASSERT_EQ(0, memcmp(plainText.get(), data, datalen));
}

TEST(WiredTigerEncryptionTest, EncryptionCBC) {
    EncryptionHarness eKeyDB{"AES256-CBC"};
    WiredTigerEncryptionHooksCBC hooks{eKeyDB.getKeyDB()};
    test_encryption_hooks(&hooks);
}

TEST(WiredTigerEncryptionTest, EncryptionGCM) {
    EncryptionHarness eKeyDB{"AES256-GCM"};
    WiredTigerEncryptionHooksGCM hooks{eKeyDB.getKeyDB()};
    test_encryption_hooks(&hooks);
}

}  // namespace
}  // namespace mongo
