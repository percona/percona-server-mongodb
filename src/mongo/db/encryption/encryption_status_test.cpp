/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2025-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/db/commands/server_status.h"
#include "mongo/db/concurrency/locker_noop_client_observer.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/encryption/key_id.h"

#include "mongo/unittest/assert.h"
#include "mongo/unittest/framework.h"

namespace mongo {

namespace {

class EncryptionStatusTest : public unittest::Test {
public:
    static constexpr auto kTestCipherMode = "AES256-CBC";
    static constexpr auto kTestKeyId = "testKeyId";
    static constexpr auto kTestKeyFilePath = "/path/to/keyfile";
    static constexpr auto kTestVaultSecretPath = "/some/path";
    static constexpr uint64_t kTestVaultSecretVersion = 1234;
    static constexpr auto kEncryptionEnabledField = "encryptionEnabled";
    static constexpr auto kEncryptionCipherModeField = "encryptionCipherMode";
    static constexpr auto kEncryptionKeyIdField = "encryptionKeyId";

    // Expected BSON objects for the keyId field in the generated section
    static const BSONObj expectedKeyIdField_null;
    static const BSONObj expectedKeyIdField_KeyFile;
    static const BSONObj expectedKeyIdField_Vault;
    static const BSONObj expectedKeyIdField_KMIP;

    EncryptionStatusTest()
        : _section(nullptr),
          _serviceContext(std::make_unique<ServiceContext>()),
          _client(_serviceContext->makeClient("EncryptionStatusTestClient")),
          _operationContext() {

        _serviceContext->registerClientObserver(std::make_unique<LockerNoopClientObserver>());
        _operationContext = _serviceContext->makeOperationContext(_client.get());

        // Find the 'encryptionAtRest' section in the server status registry.
        auto registry = ServerStatusSectionRegistry::get();
        for (auto i = registry->begin(); i != registry->end(); ++i) {
            if (i->second->getSectionName() == "encryptionAtRest") {
                _section = i->second;
                break;
            }
        }

        invariant(_section,
                  "EncryptionStatusTest requires the 'encryptionAtRest' section to be registered");
    }

    void setUp() override {
        encryptionGlobalParams.enableEncryption = false;
        encryptionGlobalParams.encryptionCipherMode = "";
        encryptionGlobalParams.encryptionKeyFile = "";

        encryption::WtKeyIds::instance().configured.reset();
        encryption::WtKeyIds::instance().decryption.reset();
        encryption::WtKeyIds::instance().futureConfigured.reset();
    }

    // Run the basic test:
    // - enable encryption,
    // - set cipher mode,
    // - generate the section,
    // - check that the result contains the expected fields and values,
    //
    // NOTE: This test assumes the encryption::WtKeyIds instance is already set up if required.
    void runTest(const BSONObj& expectedKeyId) {
        encryptionGlobalParams.enableEncryption = true;
        encryptionGlobalParams.encryptionCipherMode = kTestCipherMode;

        const auto result = generate();

        ASSERT_TRUE(result.hasField(kEncryptionEnabledField));
        ASSERT_TRUE(result.hasField(kEncryptionCipherModeField));
        ASSERT_TRUE(result.hasField(kEncryptionKeyIdField));

        ASSERT_TRUE(expectedKeyId.hasField(kEncryptionKeyIdField));

        ASSERT_TRUE(result[kEncryptionEnabledField].Bool());
        ASSERT_EQ(result[kEncryptionCipherModeField].String(), kTestCipherMode);
        ASSERT_BSONELT_EQ(result[kEncryptionKeyIdField], expectedKeyId[kEncryptionKeyIdField]);
    }

    // Run the test with setting the keyId in the 'decryption' field of the WtKeyIds instance.
    void runTest_decryption(std::unique_ptr<encryption::KeyId> keyId,
                            const BSONObj& expectedKeyId) {
        encryption::WtKeyIds::instance().decryption = std::move(keyId);
        runTest(expectedKeyId);
    }

    // Run the test with setting the keyId in the 'configured' field of the WtKeyIds instance.
    void runTest_configured(std::unique_ptr<encryption::KeyId> keyId,
                            const BSONObj& expectedKeyId) {
        encryption::WtKeyIds::instance().configured = std::move(keyId);
        runTest(expectedKeyId);
    }

    // Run the test with setting the keyId in the 'futureConfigured' field of the WtKeyIds instance.
    void runTest_futureConfigured(std::unique_ptr<encryption::KeyId> keyId,
                                  const BSONObj& expectedKeyId) {
        encryption::WtKeyIds::instance().futureConfigured = std::move(keyId);
        runTest(expectedKeyId);
    }

protected:
    BSONObj generate() {
        BSONElement configElement;
        return _section->generateSection(_operationContext.get(), configElement);
    }

    ServerStatusSection* _section;

private:
    std::unique_ptr<ServiceContext> _serviceContext;
    ServiceContext::UniqueClient _client;
    ServiceContext::UniqueOperationContext _operationContext;
};

// { encryptionKeyId : null }
const BSONObj EncryptionStatusTest::expectedKeyIdField_null =
    BSON(kEncryptionKeyIdField << BSONNULL);

// { encryptionKeyId : 'local' }
const BSONObj EncryptionStatusTest::expectedKeyIdField_KeyFile =
    BSON(kEncryptionKeyIdField << "local");

// {
//      encryptionKeyId : {
//          vault: {
//              path: <kTestVaultSecretPath>,
//              version: <kTestVaultSecretVersion>
//          }
//      }
// }
const BSONObj EncryptionStatusTest::expectedKeyIdField_Vault =
    BSON(kEncryptionKeyIdField << BSON(
             "vault" << BSON(
                 "path" << kTestVaultSecretPath << "version"
                        << static_cast<StringData>(str::stream() << kTestVaultSecretVersion))));

// {
//      encryptionKeyId : {
//          kmip: {
//              keyId: <kTestKeyId>,
//          }
//      }
// }
const BSONObj EncryptionStatusTest::expectedKeyIdField_KMIP =
    BSON(kEncryptionKeyIdField << BSON("kmip" << BSON("keyId" << kTestKeyId)));

TEST_F(EncryptionStatusTest, includeByDefault) {
    ASSERT_TRUE(_section->includeByDefault());
}

TEST_F(EncryptionStatusTest, encryptionDisabled) {
    const auto result = generate();
    // expect only the 'encryptionEnabled' field ...
    ASSERT_TRUE(result.hasField(kEncryptionEnabledField));
    ASSERT_FALSE(result.hasField(kEncryptionCipherModeField));
    ASSERT_FALSE(result.hasField(kEncryptionKeyIdField));

    // ... and it should be false
    ASSERT_FALSE(result[kEncryptionEnabledField].Bool());
}

// No key ID is set up and thus the 'encryptionKeyId' field should be null.
TEST_F(EncryptionStatusTest, encryptionEnabled_noKeyId) {
    runTest(expectedKeyIdField_null);
}

// No key ID is set up but the 'encryptionKeyFile' is set so the 'encryptionKeyId' field
// should be set to 'local'.
TEST_F(EncryptionStatusTest, encryptionEnabled_keyFile) {
    encryptionGlobalParams.encryptionKeyFile = "/some/path/to/keyfile";
    runTest(expectedKeyIdField_KeyFile);
}

// Test for setting the 'decryption' field with the KMIP key identifier.
TEST_F(EncryptionStatusTest, encryptionEnabled_decryption_KMIP) {
    runTest_decryption(std::make_unique<encryption::KmipKeyId>(kTestKeyId),
                       expectedKeyIdField_KMIP);
}

// Test for setting the 'configured' field with the KMIP key identifier.
TEST_F(EncryptionStatusTest, encryptionEnabled_configured_KMIP) {
    runTest_configured(std::make_unique<encryption::KmipKeyId>(kTestKeyId),
                       expectedKeyIdField_null);
}

// Test for setting the 'futureConfigured' field with the KMIP key identifier.
TEST_F(EncryptionStatusTest, encryptionEnabled_futureConfigured_KMIP) {
    runTest_futureConfigured(std::make_unique<encryption::KmipKeyId>(kTestKeyId),
                             expectedKeyIdField_KMIP);
}

// Test for setting the 'decryption' field with the Vault key identifier.
TEST_F(EncryptionStatusTest, encryptionEnabled_decryption_Vault) {
    runTest_decryption(
        std::make_unique<encryption::VaultSecretId>(kTestVaultSecretPath, kTestVaultSecretVersion),
        expectedKeyIdField_Vault);
}

// Test for setting the 'configured' field with the Vault key identifier.
TEST_F(EncryptionStatusTest, encryptionEnabled_configured_Vault) {
    runTest_configured(
        std::make_unique<encryption::VaultSecretId>(kTestVaultSecretPath, kTestVaultSecretVersion),
        expectedKeyIdField_null);
}

// Test for setting the 'futureConfigured' field with the Vault key identifier.
TEST_F(EncryptionStatusTest, encryptionEnabled_futureConfigured_Vault) {
    runTest_futureConfigured(
        std::make_unique<encryption::VaultSecretId>(kTestVaultSecretPath, kTestVaultSecretVersion),
        expectedKeyIdField_Vault);
}

// Test for setting the 'decryption' field with the key file.
TEST_F(EncryptionStatusTest, encryptionEnabled_decryption_KeyFilePath) {
    runTest_decryption(std::make_unique<encryption::KeyFilePath>(kTestKeyFilePath),
                       expectedKeyIdField_KeyFile);
}

// Test for setting the 'configured' field with the key file.
TEST_F(EncryptionStatusTest, encryptionEnabled_configured_KeyFilePath) {
    runTest_configured(std::make_unique<encryption::KeyFilePath>(kTestKeyFilePath),
                       expectedKeyIdField_null);
}

// Test for setting the 'futureConfigured' field with the key file.
TEST_F(EncryptionStatusTest, encryptionEnabled_futureConfigured_KeyFilePath) {
    runTest_futureConfigured(std::make_unique<encryption::KeyFilePath>(kTestKeyFilePath),
                             expectedKeyIdField_KeyFile);
}

// Test that the 'decryption' field has a priority over the 'futureConfigured' field.
TEST_F(EncryptionStatusTest, encryptionEnabled_decrytion_and_futureConfigured) {
    encryption::WtKeyIds::instance().futureConfigured =
        std::make_unique<encryption::KmipKeyId>(kTestKeyId);
    encryption::WtKeyIds::instance().decryption =
        std::make_unique<encryption::VaultSecretId>(kTestVaultSecretPath, kTestVaultSecretVersion);
    runTest(expectedKeyIdField_Vault);
}

}  // namespace
}  // namespace mongo
