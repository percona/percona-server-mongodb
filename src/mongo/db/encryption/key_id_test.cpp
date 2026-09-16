/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2023-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/db/encryption/key_id.h"

#include <memory>
#include <ostream>
#include <string>

#include "mongo/bson/bsonmisc.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/unittest/unittest.h"

namespace mongo {
namespace encryption {
std::ostream& operator<<(std::ostream& os, const VaultSecretId& id) {
    os << "{path : " << id.path() << ", version : " << id.version() << "}";
    return os;
}

std::ostream& operator<<(std::ostream& os, const KmipKeyId& id) {
    os << id.toString();
    return os;
}
}  // namespace encryption
namespace {
using namespace encryption;

TEST(KeyIdTest, CreateWithValidBsonIsOk) {
    ASSERT_EQ(*VaultSecretId::create(BSON("path"
                                          << "sierra"
                                          << "version"
                                          << "1")),
              VaultSecretId("sierra", 1));
    ASSERT_EQ(*VaultSecretId::create(BSON("path"
                                          << "sierra/tango/uniform"
                                          << "version"
                                          << "42")),
              VaultSecretId("sierra/tango/uniform", 42));
    ASSERT_EQ(*VaultSecretId::create(BSON("path"
                                          << "sierra/tango/uniform"
                                          << "version"
                                          << "42"
                                          << "bravo"
                                          << "charlie")),
              VaultSecretId("sierra/tango/uniform", 42));

    ASSERT_EQ(*KmipKeyId::create(BSON("keyId"
                                      << "42")),
              KmipKeyId("42"));
    ASSERT_EQ(*KmipKeyId::create(BSON("keyId"
                                      << "sierra")),
              KmipKeyId("sierra"));
    ASSERT_EQ(*KmipKeyId::create(BSON("keyId"
                                      << "sierra"
                                      << "bravo"
                                      << "charlie")),
              KmipKeyId("sierra"));
}

TEST(KeyIdTest, CrateWithInvalidBsonIsNotOk) {
    ASSERT_THROWS(VaultSecretId::create(BSON("bravo"
                                             << "charlie")),
                  std::runtime_error);
    ASSERT_THROWS(VaultSecretId::create(BSON("version"
                                             << "1")),
                  std::runtime_error);
    ASSERT_THROWS(VaultSecretId::create(BSON("path" << 42 << "version"
                                                    << "1")),
                  std::runtime_error);
    ASSERT_THROWS(VaultSecretId::create(BSON("path"
                                             << ""
                                             << "version"
                                             << "1")),
                  std::runtime_error);
    ASSERT_THROWS(VaultSecretId::create(BSON("path"
                                             << "sierra")),
                  std::runtime_error);
    ASSERT_THROWS(VaultSecretId::create(BSON("path"
                                             << "sierra"
                                             << "version" << 1)),
                  std::runtime_error);

    ASSERT_THROWS(KmipKeyId::create(BSON("bravo"
                                         << "charlie")),
                  std::runtime_error);
    ASSERT_THROWS(KmipKeyId::create(BSON("keyId" << 42)), std::runtime_error);
}

TEST(KeyIdTest, Serialize) {
    auto toJsonText = [](const KeyId& id) {
        BSONObjBuilder b;
        id.serialize(&b);
        return b.obj().jsonString();
    };

    ASSERT_EQ(toJsonText(KeyFilePath("key.txt")), R"json({"encryptionKeyFilePath":"key.txt"})json");
    ASSERT_EQ(toJsonText(KeyFilePath("relative/path/to/key.txt")),
              R"json({"encryptionKeyFilePath":"relative/path/to/key.txt"})json");

    ASSERT_EQ(toJsonText(KeyFilePath("/absolute/path/to/key.txt")),
              R"json({"encryptionKeyFilePath":"/absolute/path/to/key.txt"})json");

    ASSERT_EQ(toJsonText(VaultSecretId("sierra", 0)),
              R"json({"vaultSecretIdentifier":{"path":"sierra","version":"0"}})json");
    ASSERT_EQ(
        toJsonText(VaultSecretId("sierra/tango/uniform", 42)),
        R"json({"vaultSecretIdentifier":{"path":"sierra/tango/uniform","version":"42"}})json");

    ASSERT_EQ(toJsonText(KmipKeyId("1")), R"json({"kmipKeyIdentifier":"1"})json");
    ASSERT_EQ(toJsonText(KmipKeyId("42")), R"json({"kmipKeyIdentifier":"42"})json");
    ASSERT_EQ(toJsonText(KmipKeyId("sierra")), R"json({"kmipKeyIdentifier":"sierra"})json");
}

TEST(KeyIdTest, SerializeToStorageEngineEncryptionOptions) {
    auto toJsonText = [](const KeyId& id) {
        BSONObjBuilder b;
        id.serializeToStorageEngineEncryptionOptions(&b);
        return b.obj().jsonString();
    };

    ASSERT_EQ(toJsonText(VaultSecretId("sierra/tango/uniform", 42)),
              R"json({"vault":{"path":"sierra/tango/uniform","version":"42"}})json");
    ASSERT_EQ(toJsonText(KmipKeyId("42")), R"json({"kmip":{"keyId":"42"}})json");
}

class WtKeyIdsAdoptTest : public unittest::Test {
protected:
    void setUp() override {
        encryptionGlobalParams = EncryptionGlobalParams();
        WtKeyIds::instance().clear();
    }
    void tearDown() override {
        setUp();
    }

    void assertParamsUnchanged(const EncryptionGlobalParams& before) const {
        ASSERT_EQ(encryptionGlobalParams.kmipKeyIdentifier, before.kmipKeyIdentifier);
        ASSERT_EQ(encryptionGlobalParams.vaultSecret, before.vaultSecret);
        ASSERT_EQ(encryptionGlobalParams.vaultSecretVersion.has_value(),
                  before.vaultSecretVersion.has_value());
        if (before.vaultSecretVersion) {
            ASSERT_EQ(*encryptionGlobalParams.vaultSecretVersion, *before.vaultSecretVersion);
        }
        ASSERT_EQ(encryptionGlobalParams.kmipRotateMasterKey, before.kmipRotateMasterKey);
        ASSERT_EQ(encryptionGlobalParams.vaultRotateMasterKey, before.vaultRotateMasterKey);
    }
};

TEST_F(WtKeyIdsAdoptTest, NullptrIsNoop) {
    const auto before = encryptionGlobalParams;
    WtKeyIds::instance().setFutureConfigured(std::make_unique<KmipKeyId>("stale"));
    WtKeyIds::instance().adoptFromStorageMetadata(nullptr);
    ASSERT_TRUE(WtKeyIds::instance().hasFutureConfigured());
    ASSERT_FALSE(WtKeyIds::instance().hasConfigured());
    assertParamsUnchanged(before);
}

TEST_F(WtKeyIdsAdoptTest, KmipIdClearsStaleFutureConfigured) {
    const auto before = encryptionGlobalParams;
    WtKeyIds::instance().setFutureConfigured(std::make_unique<KmipKeyId>("stale"));
    const KmipKeyId source("1");
    WtKeyIds::instance().adoptFromStorageMetadata(&source);
    auto configured = WtKeyIds::instance().cloneConfigured();
    ASSERT_TRUE(configured);
    ASSERT_EQ(*dynamic_cast<const KmipKeyId*>(configured.get()), source);
    ASSERT_FALSE(WtKeyIds::instance().hasFutureConfigured());
    assertParamsUnchanged(before);
}

TEST_F(WtKeyIdsAdoptTest, ReplacesPreviouslyAdoptedConfiguredId) {
    const auto before = encryptionGlobalParams;
    const KmipKeyId source("source");
    WtKeyIds::instance().adoptFromStorageMetadata(&source);
    auto first = WtKeyIds::instance().cloneConfigured();
    ASSERT_EQ(*dynamic_cast<const KmipKeyId*>(first.get()), source);

    const KmipKeyId local("local");
    WtKeyIds::instance().adoptFromStorageMetadata(&local);
    auto second = WtKeyIds::instance().cloneConfigured();
    ASSERT_EQ(*dynamic_cast<const KmipKeyId*>(second.get()), local);
    assertParamsUnchanged(before);
}

TEST_F(WtKeyIdsAdoptTest, DoesNotModifyOperatorSetKmipKeyIdentifier) {
    encryptionGlobalParams.kmipKeyIdentifier = "operator-set";
    const auto before = encryptionGlobalParams;
    const KmipKeyId source("1");
    WtKeyIds::instance().adoptFromStorageMetadata(&source);
    auto configured = WtKeyIds::instance().cloneConfigured();
    ASSERT_EQ(*dynamic_cast<const KmipKeyId*>(configured.get()), source);
    ASSERT_FALSE(WtKeyIds::instance().hasFutureConfigured());
    assertParamsUnchanged(before);
}

TEST_F(WtKeyIdsAdoptTest, NullptrPreservesConfigured) {
    const auto before = encryptionGlobalParams;
    const KmipKeyId source("source");
    WtKeyIds::instance().adoptFromStorageMetadata(&source);
    ASSERT_TRUE(WtKeyIds::instance().hasConfigured());

    WtKeyIds::instance().adoptFromStorageMetadata(nullptr);
    auto configured = WtKeyIds::instance().cloneConfigured();
    ASSERT_EQ(*dynamic_cast<const KmipKeyId*>(configured.get()), source);
    assertParamsUnchanged(before);
}

TEST_F(WtKeyIdsAdoptTest, SetsConfiguredDuringMasterKeyRotation) {
    encryptionGlobalParams.kmipRotateMasterKey = true;
    const auto before = encryptionGlobalParams;
    const KmipKeyId source("1");
    WtKeyIds::instance().adoptFromStorageMetadata(&source);
    auto configured = WtKeyIds::instance().cloneConfigured();
    ASSERT_EQ(*dynamic_cast<const KmipKeyId*>(configured.get()), source);
    assertParamsUnchanged(before);
}

TEST_F(WtKeyIdsAdoptTest, VaultAdoptSetsConfigured) {
    const auto before = encryptionGlobalParams;
    const VaultSecretId source("charlie/delta", 2);
    WtKeyIds::instance().adoptFromStorageMetadata(&source);
    auto configured = WtKeyIds::instance().cloneConfigured();
    ASSERT_EQ(*dynamic_cast<const VaultSecretId*>(configured.get()), source);
    assertParamsUnchanged(before);
}

TEST_F(WtKeyIdsAdoptTest, VaultReplacesPreviouslyAdoptedConfigured) {
    const auto before = encryptionGlobalParams;
    const VaultSecretId first("alpha/path", 1);
    WtKeyIds::instance().adoptFromStorageMetadata(&first);
    const VaultSecretId second("bravo/path", 2);
    WtKeyIds::instance().adoptFromStorageMetadata(&second);
    auto configured = WtKeyIds::instance().cloneConfigured();
    ASSERT_EQ(*dynamic_cast<const VaultSecretId*>(configured.get()), second);
    assertParamsUnchanged(before);
}

TEST_F(WtKeyIdsAdoptTest, DoesNotModifyOperatorSetVaultParams) {
    encryptionGlobalParams.vaultSecret = "operator/path";
    encryptionGlobalParams.vaultSecretVersion = 3;
    const auto before = encryptionGlobalParams;
    const VaultSecretId source("charlie/delta", 7);
    WtKeyIds::instance().adoptFromStorageMetadata(&source);
    auto configured = WtKeyIds::instance().cloneConfigured();
    ASSERT_EQ(*dynamic_cast<const VaultSecretId*>(configured.get()), source);
    assertParamsUnchanged(before);
}

TEST_F(WtKeyIdsAdoptTest, KeyFilePathDoesNotTouchEncryptionParams) {
    const auto before = encryptionGlobalParams;
    const KeyFilePath path("/tmp/ekf");
    WtKeyIds::instance().adoptFromStorageMetadata(&path);
    ASSERT_TRUE(WtKeyIds::instance().hasConfigured());
    ASSERT_FALSE(WtKeyIds::instance().hasFutureConfigured());
    assertParamsUnchanged(before);
}

TEST_F(WtKeyIdsAdoptTest, CloneKeyIdForServerStatusSurvivesLaterMutation) {
    const KmipKeyId first("first");
    WtKeyIds::instance().setDecryption(first.clone());
    auto snapshot = WtKeyIds::instance().cloneKeyIdForServerStatus();
    ASSERT_TRUE(snapshot);
    ASSERT_EQ(*dynamic_cast<const KmipKeyId*>(snapshot.get()), first);

    WtKeyIds::instance().setDecryption(std::make_unique<KmipKeyId>("second"));
    ASSERT_EQ(*dynamic_cast<const KmipKeyId*>(snapshot.get()), first);
}

}  // namespace
}  // namespace mongo
