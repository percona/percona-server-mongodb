/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2022-present Percona and/or its affiliates. All rights reserved.

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

#include <string.h>    // for `::strerror`
#include <sys/stat.h>  // for `::chmod`

#include <cstdint>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "mongo/base/string_data.h"
#include "mongo/bson/bsonmisc.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/encryption/error.h"
#include "mongo/db/encryption/key.h"
#include "mongo/db/encryption/key_entry.h"
#include "mongo/db/encryption/key_id.h"
#include "mongo/db/encryption/key_operations.h"
#include "mongo/db/encryption/master_key_provider.h"
#include "mongo/db/service_context_test_fixture.h"
#include "mongo/db/storage/master_key_rotation_completed.h"
#include "mongo/db/storage/wiredtiger/encryption_keydb.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_kv_engine.h"
#include "mongo/logv2/log_component.h"
#include "mongo/unittest/temp_dir.h"
#include "mongo/unittest/unittest.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/assert_util_core.h"
#include "mongo/util/clock_source_mock.h"
#include "mongo/util/duration.h"
#include "mongo/util/mock_periodic_runner.h"

namespace mongo {
namespace encryption {
std::ostream& operator<<(std::ostream& os, const Key& key) {
    os << key.base64();
    return os;
}
}  // namespace encryption
namespace {
using namespace encryption;

EncryptionGlobalParams encryptionParamsKeyFile(const std::string& keyFilePath) {
    EncryptionGlobalParams params;
    params.enableEncryption = true;
    params.encryptionKeyFile = keyFilePath;
    return params;
}

EncryptionGlobalParams encryptionParamsKeyFile(const KeyFilePath& keyFilePath) {
    return encryptionParamsKeyFile(keyFilePath.toString());
}

EncryptionGlobalParams encryptionParamsVault(
    const std::string& secretPath = "", std::optional<std::uint64_t> secretVersion = std::nullopt) {
    EncryptionGlobalParams params;
    params.enableEncryption = true;
    params.vaultServerName = "vault.com";
    params.vaultPort = 1;
    params.vaultToken = "nonsese";
    if (!secretPath.empty()) {
        params.vaultSecret = secretPath;
        if (secretVersion) {
            params.vaultSecretVersion = secretVersion;
        }
    }
    return params;
}

EncryptionGlobalParams encryptionParamsVault(const VaultSecretId& id) {
    return encryptionParamsVault(id.path(), id.version());
}

EncryptionGlobalParams encryptionParamsKmip(const std::string& keyId = "") {
    EncryptionGlobalParams params;
    params.enableEncryption = true;
    params.kmipServerName = "kmip.com";
    params.kmipPort = 1;
    if (!keyId.empty()) {
        params.kmipKeyIdentifier = keyId;
    }
    return params;
}

EncryptionGlobalParams encryptionParamsKmip(const KmipKeyId& id) {
    return encryptionParamsKmip(id.toString());
}

class FakeVaultServer {
public:
    std::pair<std::string, std::uint64_t> readRawKey(const VaultSecretId& id) const noexcept {
        auto engine = _keys.find(id.path());
        if (engine == _keys.end() || engine->second.empty() ||
            engine->second.size() < id.version()) {
            return {std::string(), 0};
        }
        if (id.version() == 0) {
            return {*engine->second.rbegin(), engine->second.size()};
        }
        return {engine->second.at(id.version() - 1), id.version()};
    }

    std::optional<Key> readKey(const VaultSecretId& id) const noexcept {
        auto [encryptedKey, version] = readRawKey(id);
        return encryptedKey.empty() ? std::nullopt : std::optional<Key>(Key(encryptedKey));
    }

    VaultSecretId saveKey(const std::string& path, const Key& key) {
        auto& v = _keys[path];
        v.push_back(key.base64());
        return VaultSecretId(path, v.size());
    }

    void clear() noexcept {
        _keys.clear();
    }

private:
    std::map<std::string, std::vector<std::string>> _keys;
};

class FakeReadVaultSecret : public ReadVaultSecret {
public:
    FakeReadVaultSecret(FakeVaultServer& server, const VaultSecretId& id)
        : ReadVaultSecret(id), _server(server) {}


    std::pair<std::string, std::uint64_t> _read(const VaultSecretId& id) const override {
        return _server.readRawKey(id);
    }

private:
    FakeVaultServer& _server;
};

class FakeSaveVaultSecret : public SaveVaultSecret {
public:
    FakeSaveVaultSecret(FakeVaultServer& server, const std::string& secretPath)
        : SaveVaultSecret(secretPath), _server(server) {}

    std::unique_ptr<KeyId> operator()(const Key& key) const override {
        return std::make_unique<VaultSecretId>(_server.saveKey(secretPath(), key));
    }

private:
    FakeVaultServer& _server;
};

class FakeVaultSecretOperationFactory : public VaultSecretOperationFactory {
public:
    FakeVaultSecretOperationFactory(FakeVaultServer& server,
                                    bool rotateMasterKey,
                                    const std::string& providedSecretPath,
                                    const std::optional<std::uint64_t>& providedSecretVersion)
        : VaultSecretOperationFactory(rotateMasterKey, providedSecretPath, providedSecretVersion),
          _server(server) {}

private:
    std::unique_ptr<ReadKey> _doCreateRead(const VaultSecretId& id) const override {
        return std::make_unique<FakeReadVaultSecret>(_server, id);
    }

    std::unique_ptr<SaveKey> _doCreateSave(const std::string& secretPath) const override {
        return std::make_unique<FakeSaveVaultSecret>(_server, secretPath);
    }

    FakeVaultServer& _server;
};

class FakeKmipServer {
public:
    std::optional<std::pair<Key, KeyState>> readKey(const KmipKeyId& id) const {
        std::size_t i = std::stoull(id.toString());
        if (i == 0 || _keys.size() <= --i) {
            return std::nullopt;
        }
        return std::make_pair(_keys[i], _keyStates[i]);
    }

    std::optional<KeyState> getKeyState(const KmipKeyId& id) {
        _getKeyStateLog.push_back(id);
        std::size_t i = std::stoull(id.toString());
        if (i == 0 || _keys.size() <= --i) {
            return std::nullopt;
        }
        return _keyStates[i];
    }

    const std::vector<KmipKeyId>& getGetKeyStateLog() const noexcept {
        return _getKeyStateLog;
    }
    void clearGetKeyStateLog() {
        _getKeyStateLog.clear();
    }

    void deactivateKey(const KmipKeyId& id) {
        _keyStates.at(std::stoull(id.toString()) - 1) = KeyState::kDeactivated;
    }

    KmipKeyId saveKey(const Key& key, bool activate = true) {
        _keys.push_back(key);
        _keyStates.push_back(activate ? KeyState::kActive : KeyState::kPreActive);
        return KmipKeyId(std::to_string(_keys.size()));
    }

    void clear() noexcept {
        _keys.clear();
        _keyStates.clear();
        _getKeyStateLog.clear();
    }

private:
    std::vector<Key> _keys;
    std::vector<KeyState> _keyStates;
    std::vector<KmipKeyId> _getKeyStateLog;
};

class FakeReadKmipKey : public ReadKmipKey {
public:
    FakeReadKmipKey(FakeKmipServer& server, const KmipKeyId& id, bool verifyState)
        : ReadKmipKey(id, verifyState), _server(server) {}

    std::variant<KeyEntry, NotFound, BadKeyState> operator()() const override {
        std::optional<std::pair<Key, KeyState>> keyKeyStatePair = _server.readKey(_id);
        if (!keyKeyStatePair) {
            return NotFound();
        }
        auto [key, keyState] = *keyKeyStatePair;
        if (!_verifyState || keyState == KeyState::kActive) {
            return KeyEntry{key, _id.clone()};
        }
        return BadKeyState(keyState);
    }

private:
    FakeKmipServer& _server;
};

class FakeSaveKmipKey : public SaveKmipKey {
public:
    FakeSaveKmipKey(FakeKmipServer& server, bool activate)
        : SaveKmipKey(activate), _server(server) {}

    std::unique_ptr<KeyId> operator()(const Key& key) const override {
        return std::make_unique<KmipKeyId>(_server.saveKey(key, _activate));
    }

private:
    FakeKmipServer& _server;
};

class FakeGetKmipKeyState : public GetKmipKeyState {
public:
    FakeGetKmipKeyState(FakeKmipServer& server, const KmipKeyId& id, Seconds period)
        : GetKmipKeyState(id, period), _server(server) {}

    std::optional<KeyState> operator()() const override {
        return _server.getKeyState(_id);
    }

private:
    FakeKmipServer& _server;
};

class FakeKmipKeyOperationFactory : public KmipKeyOperationFactory {
public:
    FakeKmipKeyOperationFactory(FakeKmipServer& server,
                                bool rotateMasterKey,
                                const std::string& providedKeyId,
                                bool activateKeys,
                                Seconds keyStatePollingPeriod)
        : KmipKeyOperationFactory(
              rotateMasterKey, providedKeyId, activateKeys, keyStatePollingPeriod),
          _server(server) {}

private:
    std::unique_ptr<ReadKey> _doCreateRead(const KmipKeyId& id, bool verifyState) const override {
        return std::make_unique<FakeReadKmipKey>(_server, id, verifyState);
    }
    std::unique_ptr<SaveKey> _doCreateSave(bool activate) const override {
        return std::make_unique<FakeSaveKmipKey>(_server, activate);
    }
    std::unique_ptr<GetKeyState> _doCreateGetState(const KmipKeyId& id,
                                                   Seconds period) const override {
        return std::make_unique<FakeGetKmipKeyState>(_server, id, period);
    }

    FakeKmipServer& _server;
};

class FakeMasterKeyProviderFactory {
public:
    FakeMasterKeyProviderFactory(FakeVaultServer& vaultServer, FakeKmipServer& kmipServer)
        : _vaultServer(vaultServer), _kmipServer(kmipServer) {}

    std::unique_ptr<MasterKeyProvider> operator()(const EncryptionGlobalParams& params,
                                                  const logv2::LogComponent logComponent) {
        return std::make_unique<MasterKeyProvider>(
            createFakeKeyOperationFactory(_vaultServer, _kmipServer, params),
            WtKeyIds::instance(),
            logComponent);
    }

private:
    static std::unique_ptr<KeyOperationFactory> createFakeKeyOperationFactory(
        FakeVaultServer& vaultServer,
        FakeKmipServer& kmipServer,
        const EncryptionGlobalParams& params) {
        if (!params.encryptionKeyFile.empty()) {
            return std::make_unique<KeyFileOperationFactory>(params.encryptionKeyFile);
        } else if (!params.vaultServerName.empty()) {
            return std::make_unique<FakeVaultSecretOperationFactory>(vaultServer,
                                                                     params.vaultRotateMasterKey,
                                                                     params.vaultSecret,
                                                                     params.vaultSecretVersion);
        } else if (!params.kmipServerName.empty()) {
            return std::make_unique<FakeKmipKeyOperationFactory>(
                kmipServer,
                params.kmipRotateMasterKey,
                params.kmipKeyIdentifier,
                params.kmipActivateKeys,
                Seconds(params.kmipKeyStatePollingSeconds));
        }
        invariant(false && "Should not reach this point");
        return nullptr;
    }

    FakeVaultServer& _vaultServer;
    FakeKmipServer& _kmipServer;
};


std::string toJsonText(const KeyId& id) {
    BSONObjBuilder b;
    id.serialize(&b);
    return b.obj().jsonString();
}

class FakePeriodicRunner : public MockPeriodicRunner {
public:
    JobAnchor makeJob(PeriodicJob job) override {
        JobAnchor jobAnchor = MockPeriodicRunner::makeJob(job);
        _hasJob = true;
        return jobAnchor;
    }

    bool hasJob() const noexcept {
        return _hasJob;
    }

private:
    bool _hasJob{false};
};

class WiredTigerKVEngineEncryptionKeyTest : public ServiceContextTest {
public:
    void setUp() override {
        _tempDir = std::make_unique<unittest::TempDir>("wt_kv_key");

        _key = std::make_unique<Key>();
        _keyFilePath = std::make_unique<KeyFilePath>(_createKeyFile("key.txt", *_key));

        _vaultServer.saveKey("charlie/delta", Key());
        _vaultServer.saveKey("charlie/delta", Key());

        _kmipServer.saveKey(Key());
        _kmipServer.saveKey(Key());

        _clockSource = std::make_unique<ClockSourceMock>();
        _runner = std::make_unique<FakePeriodicRunner>();

        _setUpPreconfiguredEngine();
    }

    void tearDown() override {
        _engine.reset();
        _runner.reset();
        _clockSource.reset();
        _kmipServer.clear();
        _vaultServer.clear();
        _keyFilePath.reset();
        _key.reset();
        _tempDir.reset();

        WtKeyIds::instance().configured.reset();
        WtKeyIds::instance().decryption.reset();
        WtKeyIds::instance().futureConfigured.reset();

        encryptionGlobalParams = EncryptionGlobalParams();
    }

protected:
    virtual void _setUpPreconfiguredEngine() {
        _setUpEncryptionParams();
        _engine = _createWiredTigerKVEngine();
        WtKeyIds::instance().configured = std::move(WtKeyIds::instance().futureConfigured);
        _engine.reset();
        _runner = std::make_unique<FakePeriodicRunner>();
    }

    virtual void _setUpEncryptionParams() {
        encryptionGlobalParams = EncryptionGlobalParams();
    }

    std::unique_ptr<WiredTigerKVEngine> _createWiredTigerKVEngine() {
        WiredTigerKVEngine::WiredTigerConfig wtConfig;
        wtConfig.extraOpenOptions = "log=(file_max=1m,prealloc=false)";
        wtConfig.cacheSizeMB = 1;

        auto engine = std::make_unique<WiredTigerKVEngine>(
            "wiredTiger",
            _tempDir->path(),
            _clockSource.get(),
            std::move(wtConfig),
            false,
            false,
            _runner.get(),
            FakeMasterKeyProviderFactory(_vaultServer, _kmipServer));
        engine->notifyStorageStartupRecoveryComplete();
        return engine;
    }

    std::string _createKeyFile(const std::string& path, const Key& key) {
        std::string fullpath = _tempDir->path() + "/" + path;
        std::ofstream f(fullpath);
        if (f) {
            f << key.base64();
        } else {
            FAIL("Can't create the encryption key file");
        }
        f.close();
        if (::chmod(fullpath.c_str(), S_IRUSR | S_IWUSR) != 0) {
            std::string msg = "Can't set permissions on the encryption key file: ";
            msg.append(::strerror(errno));
            FAIL(msg);
        }
        return fullpath;
    }

    std::unique_ptr<unittest::TempDir> _tempDir;
    std::unique_ptr<Key> _key;
    std::unique_ptr<KeyFilePath> _keyFilePath;
    FakeVaultServer _vaultServer;
    FakeKmipServer _kmipServer;
    std::unique_ptr<ClockSource> _clockSource;
    std::unique_ptr<FakePeriodicRunner> _runner;
    std::unique_ptr<WiredTigerKVEngine> _engine;
};

#define ASSERT_CREATE_ENGINE_THROWS_WHAT(EXPECTED_WHAT) \
    ASSERT_THROWS_WHAT(_createWiredTigerKVEngine(), encryption::Error, EXPECTED_WHAT)

#define ASSERT_CREATE_ENGINE_THROWS_REASON_CONTAINS(EXPECTED_REASON)                     \
    ASSERT_THROWS_WITH_CHECK(                                                            \
        _createWiredTigerKVEngine(), encryption::Error, [](const encryption::Error& e) { \
            ASSERT_STRING_CONTAINS(e.toBSON()["reason"]["reason"].valueStringData(),     \
                                   EXPECTED_REASON);                                     \
        });

#define ASSERT_CREATE_ENGINE_THROWS_REASON_REGEX(EXPECTED_REASON)                        \
    ASSERT_THROWS_WITH_CHECK(                                                            \
        _createWiredTigerKVEngine(), encryption::Error, [](const encryption::Error& e) { \
            ASSERT_STRING_SEARCH_REGEX(e.toBSON()["reason"]["reason"].valueStringData(), \
                                       EXPECTED_REASON);                                 \
        });

#define ASSERT_KEY_STATE_POLLING_DISABLED() ASSERT_FALSE(_runner->hasJob())

#define ASSERT_KEY_STATE_POLLING_ENABLED(id) \
    ASSERT_TRUE(_runner->hasJob());          \
    _kmipServer.clearGetKeyStateLog();       \
    _runner->run(getClient());               \
    _runner->run(getClient());               \
    _runner->run(getClient());               \
    ASSERT_EQ(_kmipServer.getGetKeyStateLog(), std::vector({id, id, id}));


class WiredTigerKVEngineEncryptionKeyNewEngineTest : public WiredTigerKVEngineEncryptionKeyTest {
protected:
    void _setUpPreconfiguredEngine() override {}
};

TEST_F(WiredTigerKVEngineEncryptionKeyNewEngineTest, KeyFileIsUsedIfItIsInParams) {
    encryptionGlobalParams = encryptionParamsKeyFile(*_keyFilePath);
    _engine = _createWiredTigerKVEngine();

    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), *_key);
    ASSERT_FALSE(WtKeyIds::instance().futureConfigured);
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyNewEngineTest, ErrorIfVaultRotation) {
    VaultSecretId id = _vaultServer.saveKey("charlie/delta", Key());
    encryptionGlobalParams = encryptionParamsVault(id);
    encryptionGlobalParams.vaultRotateMasterKey = true;

    ASSERT_CREATE_ENGINE_THROWS_WHAT(
        "Master key rotation is in effect but there is no existing encryption key database.");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyNewEngineTest, ErrorIfNoVaultSecretPathInParams) {
    VaultSecretId id = _vaultServer.saveKey("charlie/delta", Key());
    encryptionGlobalParams = encryptionParamsVault();

    ASSERT_CREATE_ENGINE_THROWS_REASON_CONTAINS("No Vault secret path is provided");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyNewEngineTest, VaultSecretIsGeneratedIfVersionIsNotInParams) {
    encryptionGlobalParams = encryptionParamsVault("charlie/delta");

    _engine = _createWiredTigerKVEngine();
    // versions 1 and 2 are established in the `setUp` function
    VaultSecretId id("charlie/delta", 3);
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), *_vaultServer.readKey(id));
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().futureConfigured), toJsonText(id));
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyNewEngineTest, VaultSecretVersionIsUsedIfItIsInParams) {
    _vaultServer.saveKey("charlie/delta", Key());
    VaultSecretId id = _vaultServer.saveKey("charlie/delta", Key());
    encryptionGlobalParams = encryptionParamsVault(id);

    _engine = _createWiredTigerKVEngine();
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), *_vaultServer.readKey(id));
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().futureConfigured), toJsonText(id));
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyNewEngineTest, ErrorIfKmipRotation) {
    KmipKeyId id = _kmipServer.saveKey(Key());
    encryptionGlobalParams = encryptionParamsKmip(id);
    encryptionGlobalParams.kmipRotateMasterKey = true;

    ASSERT_CREATE_ENGINE_THROWS_WHAT(
        "Master key rotation is in effect but there is no existing encryption key database.");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyNewEngineTest, KmipKeyIsGeneratedIfNoIdInParams) {
    encryptionGlobalParams = encryptionParamsKmip();

    _engine = _createWiredTigerKVEngine();
    // keys with IDs 1 and 2 are established in the `setUp` function
    KmipKeyId id("3");
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), _kmipServer.readKey(id)->first);
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().futureConfigured), toJsonText(id));
}

TEST_F(WiredTigerKVEngineEncryptionKeyNewEngineTest,
       KeyStatePollingIsEnabledByDefaultForGeneratedKmipKey) {
    encryptionGlobalParams = encryptionParamsKmip();

    _engine = _createWiredTigerKVEngine();

    ASSERT_KEY_STATE_POLLING_ENABLED(KmipKeyId("3"));
}

TEST_F(WiredTigerKVEngineEncryptionKeyNewEngineTest, KmipKeyIdIsUsedIfItIsInParams) {
    _kmipServer.saveKey(Key());
    KmipKeyId id = _kmipServer.saveKey(Key());
    encryptionGlobalParams = encryptionParamsKmip(id);

    _engine = _createWiredTigerKVEngine();
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), _kmipServer.readKey(id)->first);
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().futureConfigured), toJsonText(id));
}

TEST_F(WiredTigerKVEngineEncryptionKeyNewEngineTest,
       KeyStatePollingIsEnabledByDefaultForKmipKeyFromParams) {
    _kmipServer.saveKey(Key());
    KmipKeyId id = _kmipServer.saveKey(Key());
    encryptionGlobalParams = encryptionParamsKmip(id);

    _engine = _createWiredTigerKVEngine();

    ASSERT_KEY_STATE_POLLING_ENABLED(id);
}

class WiredTigerKVEngineEncryptionKeyFileTest : public WiredTigerKVEngineEncryptionKeyTest {
protected:
    void _setUpEncryptionParams() override {
        encryptionGlobalParams = encryptionParamsKeyFile(*_keyFilePath);
    }
};

TEST_F(WiredTigerKVEngineEncryptionKeyFileTest, SameKeyFileIsOk) {
    encryptionGlobalParams = encryptionParamsKeyFile(*_keyFilePath);
    _engine = _createWiredTigerKVEngine();
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), *_key);
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(*_keyFilePath));
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyFileTest, SameKeyInAnotherFileIsOk) {
    KeyFilePath anotherKeyFilePath(_createKeyFile("another_key", *_key));
    encryptionGlobalParams = encryptionParamsKeyFile(anotherKeyFilePath);
    _engine = _createWiredTigerKVEngine();
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), *_key);
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(anotherKeyFilePath));
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyFileTest, ErrorIfVaultWithoutSecretIdInParams) {
    encryptionGlobalParams = encryptionParamsVault();
    ASSERT_CREATE_ENGINE_THROWS_REASON_CONTAINS("the system was not configured using Vault");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyFileTest,
       LatestKeyIsReadIfVaultWithtouSecretVersionInParams) {
    _vaultServer.saveKey("charlie/delta", Key());
    _vaultServer.saveKey("charlie/delta", Key());
    VaultSecretId id = _vaultServer.saveKey("charlie/delta", *_key);
    _key.reset();

    encryptionGlobalParams = encryptionParamsVault("charlie/delta");
    _engine = _createWiredTigerKVEngine();

    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), *_vaultServer.readKey(id));
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(id));
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyFileTest, ErrorIfVaultRotationInParams) {
    VaultSecretId id = _vaultServer.saveKey("charlie/delta", *_key);
    _key.reset();
    encryptionGlobalParams = encryptionParamsVault(id);
    encryptionGlobalParams.vaultRotateMasterKey = true;

    ASSERT_CREATE_ENGINE_THROWS_REASON_CONTAINS("the system was not configured using Vault");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyFileTest, VaultSecretIdIsUsedIfItIsInParams) {
    VaultSecretId id = _vaultServer.saveKey("charlie/delta", *_key);
    _key.reset();
    encryptionGlobalParams = encryptionParamsVault(id);
    _engine = _createWiredTigerKVEngine();

    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), *_vaultServer.readKey(id));
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(id));
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyFileTest, ErrorIfKmipWithtouKeyIdInParams) {
    encryptionGlobalParams = encryptionParamsKmip();

    ASSERT_CREATE_ENGINE_THROWS_REASON_CONTAINS("the system was not configured using KMIP");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyFileTest, ErrorIfKmipRotationInParams) {
    encryptionGlobalParams = encryptionParamsKmip("1");
    encryptionGlobalParams.kmipRotateMasterKey = true;

    ASSERT_CREATE_ENGINE_THROWS_REASON_CONTAINS("the system was not configured using KMIP");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyFileTest, KmipKeyIdIsUsedIfItIsInParams) {
    KmipKeyId id = _kmipServer.saveKey(*_key);
    _key.reset();
    encryptionGlobalParams = encryptionParamsKmip(id);
    _engine = _createWiredTigerKVEngine();

    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), _kmipServer.readKey(id)->first);
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(id));
}

class WiredTigerKVEngineEncryptionKeyVaultTest : public WiredTigerKVEngineEncryptionKeyTest {
protected:
    void _setUpEncryptionParams() override {
        encryptionGlobalParams = encryptionParamsVault("charlie/delta");
    }
};

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest, EncryptionKeyFileIsUsedIfItIsInParams) {
    Key key = *_vaultServer.readKey(VaultSecretId("charlie/delta", 3));
    // Make sure the engine won't read the key from the Vault server
    _vaultServer.clear();

    KeyFilePath path(_createKeyFile("my_key.txt", key));
    encryptionGlobalParams = encryptionParamsKeyFile(path);
    _engine = _createWiredTigerKVEngine();

    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), key);
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(path));
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest, ErrorIfKmipInParams) {
    Key key = *_vaultServer.readKey(VaultSecretId("charlie/delta", 3));
    KmipKeyId kmipKeyId = _kmipServer.saveKey(key);
    encryptionGlobalParams = encryptionParamsKmip(kmipKeyId);

    ASSERT_CREATE_ENGINE_THROWS_REASON_CONTAINS(
        "Trying to decrypt the data-at-rest with the key from a KMIP server "
        "but the system was configured with a key from a Vault server.");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

/// @brief Verify that the engine uses specific Vault secret
///
/// @param id identifier of the expected Vault secret
#define ASSERT_KEY_ID(id)                                                             \
    _engine = _createWiredTigerKVEngine();                                            \
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), *_vaultServer.readKey(id)); \
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(id));          \
    ASSERT_KEY_STATE_POLLING_DISABLED();

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest, ConfiguredSecretIdIsUsedIfNoSecretIdInParams) {
    encryptionGlobalParams = encryptionParamsVault();
    ASSERT_KEY_ID(VaultSecretId("charlie/delta", 3));
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
       ConfiguredSecretIdIsUsedIfNoSecretVersionInParams) {
    encryptionGlobalParams = encryptionParamsVault("charlie/delta");
    ASSERT_KEY_ID(VaultSecretId("charlie/delta", 3));
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest, ConfiguredSecretIdIsUsedIfSameSecretIdInParams) {
    encryptionGlobalParams = encryptionParamsVault("charlie/delta", 3);
    ASSERT_KEY_ID(VaultSecretId("charlie/delta", 3));
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
       UpgradeFromOlderMongodVersionWiththouSecretVersionUsesLatestKey) {
    // there can't be configured key id for the older `mongod` versions
    WtKeyIds::instance().configured.reset();

    encryptionGlobalParams = encryptionParamsVault("charlie/delta");
    ASSERT_KEY_ID(VaultSecretId("charlie/delta", 3));
}

#undef ASSERT_KEY_ID

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest, ErrorIfDifferentSecretVersionInParams) {
    encryptionGlobalParams = encryptionParamsVault("charlie/delta", 1);

    ASSERT_CREATE_ENGINE_THROWS_REASON_CONTAINS(
        "Vault secret identifier is not equal to that the system is already configured with");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest, ErrorIfDifferentSecretPathInParams) {
    encryptionGlobalParams = encryptionParamsVault("foo/bar", 3);

    ASSERT_CREATE_ENGINE_THROWS_REASON_CONTAINS(
        "Vault secret identifier is not equal to that the system is already configured with");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest, ErrorIfDifferentSecretPathWithoutVersionInParams) {
    encryptionGlobalParams = encryptionParamsVault("foo/bar");

    ASSERT_CREATE_ENGINE_THROWS_REASON_CONTAINS(
        "Vault secret path is not equal to that the system is already configured with");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

/// @brief Verify that master key rotation completes successfully and
/// the engine uses new master key (i.e. Vault secret)
///
/// @param id identifier of the expected Vault secret
#define ASSERT_ROTATION_NEW_KEY_ID(id)                                                  \
    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);             \
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().futureConfigured), toJsonText(id));      \
    ASSERT_KEY_STATE_POLLING_DISABLED();                                                \
                                                                                        \
    WtKeyIds::instance().configured = std::move(WtKeyIds::instance().futureConfigured); \
    encryptionGlobalParams = encryptionParamsVault();                                   \
    _engine = _createWiredTigerKVEngine();                                              \
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), *_vaultServer.readKey(id));   \
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(id));            \
    ASSERT_KEY_STATE_POLLING_DISABLED();


TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
       RotationUsesConfiguredSecretPathIfNoSecretIdInParams) {
    encryptionGlobalParams = encryptionParamsVault();
    encryptionGlobalParams.vaultRotateMasterKey = true;

    ASSERT_ROTATION_NEW_KEY_ID(VaultSecretId("charlie/delta", 4));
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
       RotationUsesConfiguredSecretPathIfSameSecretPathInParams) {
    encryptionGlobalParams = encryptionParamsVault("charlie/delta");
    encryptionGlobalParams.vaultRotateMasterKey = true;

    ASSERT_ROTATION_NEW_KEY_ID(VaultSecretId("charlie/delta", 4));
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
       RotationUsesProvidedSecretIdIfItsSecretPathIsSameToConfigured) {
    encryptionGlobalParams = encryptionParamsVault("charlie/delta", 1);
    encryptionGlobalParams.vaultRotateMasterKey = true;

    ASSERT_ROTATION_NEW_KEY_ID(VaultSecretId("charlie/delta", 1));
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest, RotationErrorIfProvidedSecretIdEqualToConfigured) {
    encryptionGlobalParams = encryptionParamsVault("charlie/delta", 3);
    encryptionGlobalParams.vaultRotateMasterKey = true;

    ASSERT_CREATE_ENGINE_THROWS_REASON_REGEX(
        "master encryption key rotation is in effect but the provided .* key identifier "
        "is equal to that the system is already configured with");
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
       RotationUsesProvidedSecretPathIfItDiffersFromConfigured) {
    encryptionGlobalParams = encryptionParamsVault("foxtrot/golf");
    encryptionGlobalParams.vaultRotateMasterKey = true;

    ASSERT_ROTATION_NEW_KEY_ID(VaultSecretId("foxtrot/golf", 1));
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
       RotationUsesProvidedSecretIdIfItDiffersFromConfigured) {
    _vaultServer.saveKey("kilo/lima", Key());
    _vaultServer.saveKey("kilo/lima", Key());
    VaultSecretId id("kilo/lima", 2);

    encryptionGlobalParams = encryptionParamsVault(id);
    encryptionGlobalParams.vaultRotateMasterKey = true;

    ASSERT_ROTATION_NEW_KEY_ID(id);
}

#undef ASSERT_ROTATION_NEW_KEY_ID

class WiredTigerKVEngineEncryptionKeyKmipTest : public WiredTigerKVEngineEncryptionKeyTest {
protected:
    void _setUpEncryptionParams() override {
        encryptionGlobalParams = encryptionParamsKmip();
    }
};

TEST_F(WiredTigerKVEngineEncryptionKeyKmipTest, EncryptionKeyFileIsUsedIfItIsInParams) {
    Key key = _kmipServer.readKey(KmipKeyId("3"))->first;
    // Make sure the engine won't read the key from the KMIP server
    _kmipServer.clear();

    KeyFilePath path(_createKeyFile("my_key.txt", key));
    encryptionGlobalParams = encryptionParamsKeyFile(path);
    _engine = _createWiredTigerKVEngine();

    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), key);
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(path));
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipTest, ErrorIfVaultInParams) {
    Key key = _kmipServer.readKey(KmipKeyId("3"))->first;
    VaultSecretId id = _vaultServer.saveKey("hotel/juliett", key);
    encryptionGlobalParams = encryptionParamsVault(id);

    ASSERT_CREATE_ENGINE_THROWS_REASON_CONTAINS(
        "Trying to decrypt the data-at-rest with the key from a Vault server "
        "but the system was configured with a key from a KMIP server.");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

/// @brief Verify that the engine uses specific KMIP key
///
/// @param id identifier of the expected KMIP key
#define ASSERT_KEY_ID(id)                                                                  \
    _engine = _createWiredTigerKVEngine();                                                 \
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), _kmipServer.readKey(id)->first); \
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(id));               \
    ASSERT_KEY_STATE_POLLING_ENABLED(id);


TEST_F(WiredTigerKVEngineEncryptionKeyKmipTest, ConfiguredKeyIdIsUsedIfNoKeyIdInParams) {
    encryptionGlobalParams = encryptionParamsKmip();
    ASSERT_KEY_ID(KmipKeyId("3"));
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipTest, ConfiguredKeyIdIsUsedIfSameKeyIdInParams) {
    encryptionGlobalParams = encryptionParamsKmip("3");
    ASSERT_KEY_ID(KmipKeyId("3"));
}

#undef ASSERT_KEY_ID

TEST_F(WiredTigerKVEngineEncryptionKeyKmipTest, ErrorIfDifferentKeyIdInParams) {
    encryptionGlobalParams = encryptionParamsKmip("2");

    ASSERT_CREATE_ENGINE_THROWS_REASON_CONTAINS(
        "KMIP keyIdentifier is not equal to that the system is already configured with");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

/// @brief Verify that master key rotation completes successfully and
/// the engine uses new master key (i.e. KMIP key)
///
/// @param id identifier of the expected KMIP key
#define ASSERT_ROTATION_NEW_KEY_ID(id)                                                     \
    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);                \
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().futureConfigured), toJsonText(id));         \
    ASSERT_KEY_STATE_POLLING_DISABLED();                                                   \
                                                                                           \
    WtKeyIds::instance().configured = std::move(WtKeyIds::instance().futureConfigured);    \
    encryptionGlobalParams = encryptionParamsKmip();                                       \
    _engine = _createWiredTigerKVEngine();                                                 \
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), _kmipServer.readKey(id)->first); \
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(id));               \
    ASSERT_KEY_STATE_POLLING_ENABLED(id);

TEST_F(WiredTigerKVEngineEncryptionKeyKmipTest, RotationCreatesKeyIdIfNoKeyIdInParams) {
    encryptionGlobalParams = encryptionParamsKmip();
    encryptionGlobalParams.kmipRotateMasterKey = true;

    ASSERT_ROTATION_NEW_KEY_ID(KmipKeyId("4"));
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipTest, RotationUsesKeyIdIfItIsInParams) {
    encryptionGlobalParams = encryptionParamsKmip("1");
    encryptionGlobalParams.kmipRotateMasterKey = true;

    ASSERT_ROTATION_NEW_KEY_ID(KmipKeyId("1"));
}

#undef ASSERT_ROTATION_NEW_KEY_ID

TEST_F(WiredTigerKVEngineEncryptionKeyKmipTest, RotationErrorIfProvidedKeyIdEqualToConfigured) {
    encryptionGlobalParams = encryptionParamsKmip("3");
    encryptionGlobalParams.kmipRotateMasterKey = true;

    ASSERT_CREATE_ENGINE_THROWS_REASON_REGEX(
        "master encryption key rotation is in effect but the provided .* key identifier "
        "is equal to that the system is already configured with");
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

class WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnStartUpTest
    : public WiredTigerKVEngineEncryptionKeyTest {
protected:
    void _setUpPreconfiguredEngine() override {}
};

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnStartUpTest,
       KeyStateVerificationIsOffNewKeyIsOk) {
    encryptionGlobalParams = encryptionParamsKmip();
    encryptionGlobalParams.kmipActivateKeys = false;

    _engine = _createWiredTigerKVEngine();

    KmipKeyId id("3");
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), _kmipServer.readKey(id)->first);
    ASSERT_KEY_STATE_POLLING_DISABLED();
    ASSERT_EQ(_kmipServer.getKeyState(id), KeyState::kPreActive);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnStartUpTest,
       KeyStateVerificationIsOffExistingActiveKeyIsOk) {
    KmipKeyId id = _kmipServer.saveKey(*_key, /* activate = */ true);
    encryptionGlobalParams = encryptionParamsKmip(id);
    encryptionGlobalParams.kmipActivateKeys = false;

    _engine = _createWiredTigerKVEngine();

    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), _kmipServer.readKey(id)->first);
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnStartUpTest,
       KeyStateVerificationIsOffExistingPreActiveKeyIsOk) {
    KmipKeyId id = _kmipServer.saveKey(*_key, /* activate = */ false);
    encryptionGlobalParams = encryptionParamsKmip(id);
    encryptionGlobalParams.kmipActivateKeys = false;

    _engine = _createWiredTigerKVEngine();

    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), _kmipServer.readKey(id)->first);
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnStartUpTest,
       KeyStateVerificationIsOffExistingDeactivatedKeyIsOk) {
    KmipKeyId id = _kmipServer.saveKey(*_key, /* activate = */ true);
    _kmipServer.deactivateKey(id);
    encryptionGlobalParams = encryptionParamsKmip(id);
    encryptionGlobalParams.kmipActivateKeys = false;

    _engine = _createWiredTigerKVEngine();

    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), _kmipServer.readKey(id)->first);
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnStartUpTest,
       KeyStateVerificationIsOnNewKeyIsOk) {
    encryptionGlobalParams = encryptionParamsKmip();
    encryptionGlobalParams.kmipActivateKeys = true;

    _engine = _createWiredTigerKVEngine();

    KmipKeyId id("3");
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), _kmipServer.readKey(id)->first);
    ASSERT_TRUE(_runner->hasJob());
    ASSERT_EQ(_kmipServer.getKeyState(id), KeyState::kActive);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnStartUpTest,
       KeyStateVerificationIsOnExistingActiveKeyIsOk) {
    KmipKeyId id = _kmipServer.saveKey(*_key, /* activate = */ true);
    encryptionGlobalParams = encryptionParamsKmip(id);
    encryptionGlobalParams.kmipActivateKeys = true;

    _engine = _createWiredTigerKVEngine();

    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), _kmipServer.readKey(id)->first);
    ASSERT_TRUE(_runner->hasJob());
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnStartUpTest,
       KeyStateVerificationIsOnExistingPreActiveKeyIsNotOk) {
    KmipKeyId id = _kmipServer.saveKey(*_key, /* activate = */ false);
    encryptionGlobalParams = encryptionParamsKmip(id);
    encryptionGlobalParams.kmipActivateKeys = true;

    // clang-format off
    ASSERT_THROWS_WITH_CHECK(
        _createWiredTigerKVEngine(),
        encryption::Error,
        ([this, &id](const encryption::Error& e) {
            auto expected = BSON(
                "what" << "Can't create encryption key database" <<
                "reason" << BSON(
                    "what" << "key reading failed" <<
                    "reason" << "Master encryption key is not in the active state "
                                "on the key management facility." <<
                    "keyManagementFacilityType" << "KMIP server" <<
                    "keyIdentifier" << BSON("kmipKeyIdentifier" << id.toString()) <<
                    "keyState" << encryption::toString(encryption::KeyState::kPreActive)) <<
                "encryptionKeyDatabaseDirectory" << _tempDir->path() + "/key.db");
            ASSERT_BSONOBJ_EQ(e.toBSON(), expected);
        }));
    // clang-format on
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnStartUpTest,
       KeyStateVerificationIsOnExistingDeactivatedKeyIsNotOk) {
    KmipKeyId id = _kmipServer.saveKey(*_key, /* activate = */ true);
    _kmipServer.deactivateKey(id);
    encryptionGlobalParams = encryptionParamsKmip(id);
    encryptionGlobalParams.kmipActivateKeys = true;

    // clang-format off
    ASSERT_THROWS_WITH_CHECK(
        _createWiredTigerKVEngine(),
        encryption::Error,
        ([this, &id](const encryption::Error& e) {
            auto expected = BSON(
                "what" << "Can't create encryption key database" <<
                "reason" << BSON(
                    "what" << "key reading failed" <<
                    "reason" << "Master encryption key is not in the active state "
                                "on the key management facility." <<
                    "keyManagementFacilityType" << "KMIP server" <<
                    "keyIdentifier" << BSON("kmipKeyIdentifier" << id.toString()) <<
                    "keyState" << encryption::toString(encryption::KeyState::kDeactivated)) <<
                "encryptionKeyDatabaseDirectory" << _tempDir->path() + "/key.db");
            ASSERT_BSONOBJ_EQ(e.toBSON(), expected);
        }));
    // clang-format on
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnStartUpTest,
       KeyStateVerificationIsDefaultNewKeyIsOk) {
    encryptionGlobalParams = encryptionParamsKmip();

    _engine = _createWiredTigerKVEngine();

    KmipKeyId id("3");
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), _kmipServer.readKey(id)->first);
    ASSERT_TRUE(_runner->hasJob());
    ASSERT_EQ(_kmipServer.getKeyState(id), KeyState::kActive);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnStartUpTest,
       KeyStateVerificationIsDefaultExistingActiveKeyIsOk) {
    KmipKeyId id = _kmipServer.saveKey(*_key, /* activate = */ true);
    encryptionGlobalParams = encryptionParamsKmip(id);

    _engine = _createWiredTigerKVEngine();

    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), _kmipServer.readKey(id)->first);
    ASSERT_TRUE(_runner->hasJob());
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnStartUpTest,
       KeyStateVerificationIsDefaultExistingPreActiveKeyIsNotOk) {
    KmipKeyId id = _kmipServer.saveKey(*_key, /* activate = */ false);
    encryptionGlobalParams = encryptionParamsKmip(id);

    // clang-format off
    ASSERT_THROWS_WITH_CHECK(
        _createWiredTigerKVEngine(),
        encryption::Error,
        ([this, &id](const encryption::Error& e) {
            auto expected = BSON(
                "what" << "Can't create encryption key database" <<
                "reason" << BSON(
                    "what" << "key reading failed" <<
                    "reason" << "Master encryption key is not in the active state "
                                "on the key management facility." <<
                    "keyManagementFacilityType" << "KMIP server" <<
                    "keyIdentifier" << BSON("kmipKeyIdentifier" << id.toString()) <<
                    "keyState" << encryption::toString(encryption::KeyState::kPreActive)) <<
                "encryptionKeyDatabaseDirectory" << _tempDir->path() + "/key.db");
            ASSERT_BSONOBJ_EQ(e.toBSON(), expected);
        }));
    // clang-format on
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnStartUpTest,
       KeyStateVerificationIsDefaultExistingDeactivatedKeyIsNotOk) {
    KmipKeyId id = _kmipServer.saveKey(*_key, /* activate = */ true);
    _kmipServer.deactivateKey(id);
    encryptionGlobalParams = encryptionParamsKmip(id);

    // clang-format off
    ASSERT_THROWS_WITH_CHECK(
        _createWiredTigerKVEngine(),
        encryption::Error,
        ([this, &id](const encryption::Error& e) {
            auto expected = BSON(
                "what" << "Can't create encryption key database" <<
                "reason" << BSON(
                    "what" << "key reading failed" <<
                    "reason" << "Master encryption key is not in the active state "
                                "on the key management facility." <<
                    "keyManagementFacilityType" << "KMIP server" <<
                    "keyIdentifier" << BSON("kmipKeyIdentifier" << id.toString()) <<
                    "keyState" << encryption::toString(encryption::KeyState::kDeactivated)) <<
                "encryptionKeyDatabaseDirectory" << _tempDir->path() + "/key.db");
            ASSERT_BSONOBJ_EQ(e.toBSON(), expected);
        }));
    // clang-format on
    ASSERT_KEY_STATE_POLLING_DISABLED();
}

class WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationTest
    : public WiredTigerKVEngineEncryptionKeyTest {
protected:
    WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationTest()
        : _oldId(_kmipServer.saveKey(Key(), /* activate = */ true)) {}

    void _setUpEncryptionParams() override {
        encryptionGlobalParams = encryptionParamsKmip();
        encryptionGlobalParams.kmipKeyIdentifier = _oldId.toString();
    }

    void setUp() override {
        WiredTigerKVEngineEncryptionKeyTest::setUp();
        encryptionGlobalParams = encryptionParamsKmip();
        encryptionGlobalParams.kmipRotateMasterKey = true;
    }

    KmipKeyId _oldId;
};

class WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDisabledActivationTest
    : public WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationTest {
public:
    void setUp() override {
        WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationTest::setUp();
        encryptionGlobalParams.kmipActivateKeys = false;
    }
};

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDisabledActivationTest,
       ReplacingExistingInactiveKeyWithNewKeyIsOk) {
    _kmipServer.deactivateKey(_oldId);

    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
    ASSERT_EQ(_kmipServer.getKeyState(KmipKeyId("4")), KeyState::kPreActive);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDisabledActivationTest,
       ReplacingExistingInactiveKeyWithExistingPreActiveKeyIsOk) {
    _kmipServer.deactivateKey(_oldId);
    encryptionGlobalParams.kmipKeyIdentifier =
        _kmipServer.saveKey(Key(), /* activate = */ false).toString();

    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDisabledActivationTest,
       ReplacingExistingInactiveKeyWithExistingActiveKeyIsOk) {
    _kmipServer.deactivateKey(_oldId);
    encryptionGlobalParams.kmipKeyIdentifier =
        _kmipServer.saveKey(Key(), /* activate = */ true).toString();

    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDisabledActivationTest,
       ReplacingExistingInactiveKeyWithExistingDeactivatedKeyIsOk) {
    _kmipServer.deactivateKey(_oldId);
    KmipKeyId id = _kmipServer.saveKey(Key(), /* activate = */ true);
    _kmipServer.deactivateKey(id);
    encryptionGlobalParams.kmipKeyIdentifier = id.toString();

    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDisabledActivationTest,
       ReplacingExistingActiveKeyWithNewKeyIsOk) {
    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
    ASSERT_EQ(_kmipServer.getKeyState(KmipKeyId("4")), KeyState::kPreActive);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDisabledActivationTest,
       ReplacingExistingActiveKeyWithExistingPreActiveKeyIsOk) {
    encryptionGlobalParams.kmipKeyIdentifier =
        _kmipServer.saveKey(Key(), /* activate = */ false).toString();

    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDisabledActivationTest,
       ReplacingExistingActiveKeyWithExistingActiveKeyIsOk) {
    encryptionGlobalParams.kmipKeyIdentifier =
        _kmipServer.saveKey(Key(), /* activate = */ true).toString();

    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDisabledActivationTest,
       ReplacingExistingActiveKeyWithExistingDeactivatedKeyIsOk) {
    KmipKeyId id = _kmipServer.saveKey(Key(), /* activate = */ true);
    _kmipServer.deactivateKey(id);
    encryptionGlobalParams.kmipKeyIdentifier = id.toString();

    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
}

class WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationEnabledActivationTest
    : public WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationTest {
public:
    void setUp() override {
        WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationTest::setUp();
        encryptionGlobalParams.kmipActivateKeys = true;
    }
};

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationEnabledActivationTest,
       ReplacingExistingInactiveKeyWithNewKeyIsOk) {
    _kmipServer.deactivateKey(_oldId);

    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
    ASSERT_EQ(_kmipServer.getKeyState(KmipKeyId("4")), KeyState::kActive);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationEnabledActivationTest,
       ReplacingExistingInactiveWithExistingPreActiveKeyIsNotOk) {
    _kmipServer.deactivateKey(_oldId);
    KmipKeyId id = _kmipServer.saveKey(Key(), /* activate = */ false);
    encryptionGlobalParams.kmipKeyIdentifier = id.toString();

    // clang-format off
    ASSERT_THROWS_WITH_CHECK(
        _createWiredTigerKVEngine(),
        encryption::Error,
        ([this, &id](const encryption::Error& e) {
            auto expected = BSON(
                "what" << "Can't rotate master encryption key" <<
                "reason" << BSON(
                    "what" << "key reading failed" <<
                    "reason" << "Master encryption key is not in the active state "
                                "on the key management facility." <<
                    "keyManagementFacilityType" << "KMIP server" <<
                    "keyIdentifier" << BSON("kmipKeyIdentifier" << id.toString()) <<
                    "keyState" << encryption::toString(encryption::KeyState::kPreActive)));
            ASSERT_BSONOBJ_EQ(e.toBSON(), expected);
        }));
    // clang-format on
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationEnabledActivationTest,
       ReplacingExistingInactiveKeyWithExistingActiveKeyIsOk) {
    _kmipServer.deactivateKey(_oldId);
    encryptionGlobalParams.kmipKeyIdentifier =
        _kmipServer.saveKey(Key(), /* activate = */ true).toString();

    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationEnabledActivationTest,
       ReplacingExistingInactiveWithExistingDeactivatedKeyIsNotOk) {
    _kmipServer.deactivateKey(_oldId);
    KmipKeyId id = _kmipServer.saveKey(Key(), /* activate = */ true);
    _kmipServer.deactivateKey(id);
    encryptionGlobalParams.kmipKeyIdentifier = id.toString();

    // clang-format off
    ASSERT_THROWS_WITH_CHECK(
        _createWiredTigerKVEngine(),
        encryption::Error,
        ([this, &id](const encryption::Error& e) {
            auto expected = BSON(
                "what" << "Can't rotate master encryption key" <<
                "reason" << BSON(
                    "what" << "key reading failed" <<
                    "reason" << "Master encryption key is not in the active state "
                                "on the key management facility." <<
                    "keyManagementFacilityType" << "KMIP server" <<
                    "keyIdentifier" << BSON("kmipKeyIdentifier" << id.toString()) <<
                    "keyState" << encryption::toString(encryption::KeyState::kDeactivated)));
            ASSERT_BSONOBJ_EQ(e.toBSON(), expected);
        }));
    // clang-format on
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationEnabledActivationTest,
       ReplacingExistingActiveKeyWithNewKeyIsOk) {
    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
    ASSERT_EQ(_kmipServer.getKeyState(KmipKeyId("4")), KeyState::kActive);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationEnabledActivationTest,
       ReplacingExistingActiveKeyWithExistingPreActiveKeyIsNotOk) {
    KmipKeyId id = _kmipServer.saveKey(Key(), /* activate = */ false);
    encryptionGlobalParams.kmipKeyIdentifier = id.toString();

    // clang-format off
    ASSERT_THROWS_WITH_CHECK(
        _createWiredTigerKVEngine(),
        encryption::Error,
        ([this, &id](const encryption::Error& e) {
            auto expected = BSON(
                "what" << "Can't rotate master encryption key" <<
                "reason" << BSON(
                    "what" << "key reading failed" <<
                    "reason" << "Master encryption key is not in the active state "
                                "on the key management facility." <<
                    "keyManagementFacilityType" << "KMIP server" <<
                    "keyIdentifier" << BSON("kmipKeyIdentifier" << id.toString()) <<
                    "keyState" << encryption::toString(encryption::KeyState::kPreActive)));
            ASSERT_BSONOBJ_EQ(e.toBSON(), expected);
        }));
    // clang-format on
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationEnabledActivationTest,
       ReplacingExistingActiveKeyWithExistingActiveKeyIsOk) {
    encryptionGlobalParams.kmipKeyIdentifier =
        _kmipServer.saveKey(Key(), /* activate = */ true).toString();

    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationEnabledActivationTest,
       ReplacingExistingActiveWithExistingDeactivatedKeyIsNotOk) {
    KmipKeyId id = _kmipServer.saveKey(Key(), /* activate = */ true);
    _kmipServer.deactivateKey(id);
    encryptionGlobalParams.kmipKeyIdentifier = id.toString();

    // clang-format off
    ASSERT_THROWS_WITH_CHECK(
        _createWiredTigerKVEngine(),
        encryption::Error,
        ([this, &id](const encryption::Error& e) {
            auto expected = BSON(
                "what" << "Can't rotate master encryption key" <<
                "reason" << BSON(
                    "what" << "key reading failed" <<
                    "reason" << "Master encryption key is not in the active state "
                                "on the key management facility." <<
                    "keyManagementFacilityType" << "KMIP server" <<
                    "keyIdentifier" << BSON("kmipKeyIdentifier" << id.toString()) <<
                    "keyState" << encryption::toString(encryption::KeyState::kDeactivated)));
            ASSERT_BSONOBJ_EQ(e.toBSON(), expected);
        }));
    // clang-format on
}

class WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDefaultedActivationTest
    : public WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationTest {
public:
    void setUp() override {
        WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationTest::setUp();
    }
};

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDefaultedActivationTest,
       ReplacingExistingInactiveKeyWithNewKeyIsOk) {
    _kmipServer.deactivateKey(_oldId);

    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
    ASSERT_EQ(_kmipServer.getKeyState(KmipKeyId("4")), KeyState::kActive);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDefaultedActivationTest,
       ReplacingExistingInactiveWithExistingPreActiveKeyIsNotOk) {
    _kmipServer.deactivateKey(_oldId);
    KmipKeyId id = _kmipServer.saveKey(Key(), /* activate = */ false);
    encryptionGlobalParams.kmipKeyIdentifier = id.toString();

    // clang-format off
    ASSERT_THROWS_WITH_CHECK(
        _createWiredTigerKVEngine(),
        encryption::Error,
        ([this, &id](const encryption::Error& e) {
            auto expected = BSON(
                "what" << "Can't rotate master encryption key" <<
                "reason" << BSON(
                    "what" << "key reading failed" <<
                    "reason" << "Master encryption key is not in the active state "
                                "on the key management facility." <<
                    "keyManagementFacilityType" << "KMIP server" <<
                    "keyIdentifier" << BSON("kmipKeyIdentifier" << id.toString()) <<
                    "keyState" << encryption::toString(encryption::KeyState::kPreActive)));
            ASSERT_BSONOBJ_EQ(e.toBSON(), expected);
        }));
    // clang-format on
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDefaultedActivationTest,
       ReplacingExistingInactiveKeyWithExistingActiveKeyIsOk) {
    _kmipServer.deactivateKey(_oldId);
    encryptionGlobalParams.kmipKeyIdentifier =
        _kmipServer.saveKey(Key(), /* activate = */ true).toString();

    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDefaultedActivationTest,
       ReplacingExistingInactiveWithExistingDeactivatedKeyIsNotOk) {
    _kmipServer.deactivateKey(_oldId);
    KmipKeyId id = _kmipServer.saveKey(Key(), /* activate = */ true);
    _kmipServer.deactivateKey(id);
    encryptionGlobalParams.kmipKeyIdentifier = id.toString();

    // clang-format off
    ASSERT_THROWS_WITH_CHECK(
        _createWiredTigerKVEngine(),
        encryption::Error,
        ([this, &id](const encryption::Error& e) {
            auto expected = BSON(
                "what" << "Can't rotate master encryption key" <<
                "reason" << BSON(
                    "what" << "key reading failed" <<
                    "reason" << "Master encryption key is not in the active state "
                                "on the key management facility." <<
                    "keyManagementFacilityType" << "KMIP server" <<
                    "keyIdentifier" << BSON("kmipKeyIdentifier" << id.toString()) <<
                    "keyState" << encryption::toString(encryption::KeyState::kDeactivated)));
            ASSERT_BSONOBJ_EQ(e.toBSON(), expected);
        }));
    // clang-format on
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDefaultedActivationTest,
       ReplacingExistingActiveKeyWithNewKeyIsOk) {
    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
    ASSERT_EQ(_kmipServer.getKeyState(KmipKeyId("4")), KeyState::kActive);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDefaultedActivationTest,
       ReplacingExistingActiveKeyWithExistingPreActiveKeyIsNotOk) {
    KmipKeyId id = _kmipServer.saveKey(Key(), /* activate = */ false);
    encryptionGlobalParams.kmipKeyIdentifier = id.toString();

    // clang-format off
    ASSERT_THROWS_WITH_CHECK(
        _createWiredTigerKVEngine(),
        encryption::Error,
        ([this, &id](const encryption::Error& e) {
            auto expected = BSON(
                "what" << "Can't rotate master encryption key" <<
                "reason" << BSON(
                    "what" << "key reading failed" <<
                    "reason" << "Master encryption key is not in the active state "
                                "on the key management facility." <<
                    "keyManagementFacilityType" << "KMIP server" <<
                    "keyIdentifier" << BSON("kmipKeyIdentifier" << id.toString()) <<
                    "keyState" << encryption::toString(encryption::KeyState::kPreActive)));
            ASSERT_BSONOBJ_EQ(e.toBSON(), expected);
        }));
    // clang-format on
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDefaultedActivationTest,
       ReplacingExistingActiveKeyWithExistingActiveKeyIsOk) {
    encryptionGlobalParams.kmipKeyIdentifier =
        _kmipServer.saveKey(Key(), /* activate = */ true).toString();

    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipVerifyStateOnRotationDefaultedActivationTest,
       ReplacingExistingActiveWithExistingDeactivatedKeyIsNotOk) {
    KmipKeyId id = _kmipServer.saveKey(Key(), /* activate = */ true);
    _kmipServer.deactivateKey(id);
    encryptionGlobalParams.kmipKeyIdentifier = id.toString();

    // clang-format off
    ASSERT_THROWS_WITH_CHECK(
        _createWiredTigerKVEngine(),
        encryption::Error,
        ([this, &id](const encryption::Error& e) {
            auto expected = BSON(
                "what" << "Can't rotate master encryption key" <<
                "reason" << BSON(
                    "what" << "key reading failed" <<
                    "reason" << "Master encryption key is not in the active state "
                                "on the key management facility." <<
                    "keyManagementFacilityType" << "KMIP server" <<
                    "keyIdentifier" << BSON("kmipKeyIdentifier" << id.toString()) <<
                    "keyState" << encryption::toString(encryption::KeyState::kDeactivated)));
            ASSERT_BSONOBJ_EQ(e.toBSON(), expected);
        }));
    // clang-format on
}

class WiredTigerKVEngineEncryptionKeyKmipPollStateTest
    : public WiredTigerKVEngineEncryptionKeyTest {
protected:
    void _setUpPreconfiguredEngine() override {}
};

TEST_F(WiredTigerKVEngineEncryptionKeyKmipPollStateTest, KeyStatePollingIsEnabledByDefault) {
    encryptionGlobalParams = encryptionParamsKmip();

    _engine = _createWiredTigerKVEngine();

    ASSERT_KEY_STATE_POLLING_ENABLED(KmipKeyId("3"));
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipPollStateTest,
       TrueActivateKeysAndPositivePollingSecondsEnableKeyStatePolling) {
    encryptionGlobalParams = encryptionParamsKmip();
    encryptionGlobalParams.kmipActivateKeys = true;
    encryptionGlobalParams.kmipKeyStatePollingSeconds = 1;

    _engine = _createWiredTigerKVEngine();

    ASSERT_KEY_STATE_POLLING_ENABLED(KmipKeyId("3"));
}

// Ideally, here should be the test case checking that deactivating the
// data-at-rest master encryption key on a KMIP server triggers the process
// shutdown. Unfortunately, such a test case can't be written using the present
// unit testing framework. Its `DEATH_TEST` group of macros relies on the
// process under test using the `fassert` function to stop execution, while the
// job that monitors the key state uses normal `cleanExit` with the special
// exit code.

TEST_F(WiredTigerKVEngineEncryptionKeyKmipPollStateTest, FalseActivateKeysDisablesKeyStatePolling) {
    encryptionGlobalParams = encryptionParamsKmip();
    encryptionGlobalParams.kmipActivateKeys = false;
    encryptionGlobalParams.kmipKeyStatePollingSeconds = 1;

    _engine = _createWiredTigerKVEngine();

    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipPollStateTest,
       ZeroPollingSecondsDisablesKeyStatePolling) {
    encryptionGlobalParams = encryptionParamsKmip();
    encryptionGlobalParams.kmipActivateKeys = true;
    encryptionGlobalParams.kmipKeyStatePollingSeconds = 0;

    _engine = _createWiredTigerKVEngine();

    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipPollStateTest,
       NegativePollingSecondsDisablesKeyStatePolling) {
    encryptionGlobalParams = encryptionParamsKmip();
    encryptionGlobalParams.kmipActivateKeys = true;
    encryptionGlobalParams.kmipKeyStatePollingSeconds = -1;

    _engine = _createWiredTigerKVEngine();

    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipPollStateTest,
       FalseActivateKeysAndZeroPollingSecondsDisablesKeyStatePolling) {
    encryptionGlobalParams = encryptionParamsKmip();
    encryptionGlobalParams.kmipActivateKeys = false;
    encryptionGlobalParams.kmipKeyStatePollingSeconds = 0;

    _engine = _createWiredTigerKVEngine();

    ASSERT_KEY_STATE_POLLING_DISABLED();
}

TEST_F(WiredTigerKVEngineEncryptionKeyKmipPollStateTest,
       FalseActivateKeysAndNegativePollingSecondsDisablesKeyStatePolling) {
    encryptionGlobalParams = encryptionParamsKmip();
    encryptionGlobalParams.kmipActivateKeys = false;
    encryptionGlobalParams.kmipKeyStatePollingSeconds = -1;

    _engine = _createWiredTigerKVEngine();

    ASSERT_KEY_STATE_POLLING_DISABLED();
}

#undef ASSERT_KEY_STATE_POLLING_DISABLED
#undef ASSERT_KEY_STATE_POLLING_ENABLED
#undef ASSERT_CREATE_ENGINE_THROWS_REASON_REGEX
#undef ASSERT_CREATE_ENGINE_THROWS_REASON_CONTAINS
#undef ASSERT_CREATE_ENGINE_THROWS_WHAT

}  // namespace
}  // namespace mongo
