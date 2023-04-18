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

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kDefault

#include "mongo/db/encryption/master_key_provider.h"

#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/encryption/error_builder.h"
#include "mongo/db/encryption/key.h"
#include "mongo/db/encryption/key_id.h"
#include "mongo/db/encryption/key_operations.h"
#include "mongo/logv2/log.h"
#include "mongo/logv2/log_options.h"

namespace mongo::encryption {
MasterKeyProvider::~MasterKeyProvider() = default;

MasterKeyProvider::MasterKeyProvider(std::unique_ptr<const KeyOperationFactory>&& factory,
                                     WtKeyIds& wtKeyIds,
                                     logv2::LogComponent logComponent)
    : _factory(std::move(factory)), _wtKeyIds(wtKeyIds), _logComponent(logComponent) {}

std::unique_ptr<MasterKeyProvider> MasterKeyProvider::create(const EncryptionGlobalParams& params,
                                                             logv2::LogComponent logComponent) {
    return std::make_unique<MasterKeyProvider>(
        KeyOperationFactory::create(params), WtKeyIds::instance(), logComponent);
}

KeyKeyIdPair MasterKeyProvider::_readMasterKey(const ReadKey& read, bool updateKeyIds) const {
    auto keyKeyId = read();
    if (!keyKeyId) {
        KeyErrorBuilder b(
            KeyOperationType::read,
            "Cannot start. Master encryption key is absent on the key management facility. "
            "Check configuration options.");
        b.append("keyManagementFacilityType", read.facilityType());
        b.append("keyIdentifier", read.keyId());
        throw b.error();
    }
    if (updateKeyIds) {
        _wtKeyIds.decryption = keyKeyId->keyId->clone();
        if (!_wtKeyIds.configured &&
            _wtKeyIds.decryption->needsSerializationToStorageEngineEncryptionOptions()) {
            _wtKeyIds.futureConfigured = _wtKeyIds.decryption->clone();
        }
    }
    LOGV2_OPTIONS(29115,
                  logv2::LogOptions(_logComponent),
                  "Master encryption key has been read from the key management facility.",
                  "keyManagementFacilityType"_attr = read.facilityType(),
                  "keyIdentifier"_attr = *keyKeyId->keyId);
    return KeyKeyIdPair(std::move(*keyKeyId));
}

std::unique_ptr<KeyId> MasterKeyProvider::_saveMasterKey(const SaveKey& save,
                                                         const Key& key) const {
    std::unique_ptr<KeyId> keyId = save(key);
    invariant(keyId);
    if (keyId->needsSerializationToStorageEngineEncryptionOptions()) {
        _wtKeyIds.futureConfigured = keyId->clone();
    }
    LOGV2_OPTIONS(29116,
                  logv2::LogOptions(_logComponent),
                  "Master encryption key has been created on the key management facility",
                  "keyManagementFacilityType"_attr = keyId->facilityType(),
                  "keyIdentifier"_attr = *keyId);
    return keyId;
}

Key MasterKeyProvider::readMasterKey() const {
    return _readMasterKey(*_factory->createRead(_wtKeyIds.configured.get())).key;
}

std::pair<Key, std::unique_ptr<KeyId>> MasterKeyProvider::obtainMasterKey(bool saveKey) const {
    if (auto read = _factory->createProvidedRead(); read) {
        auto keyKeyId = _readMasterKey(*read, false);
        if (keyKeyId.keyId->needsSerializationToStorageEngineEncryptionOptions()) {
            _wtKeyIds.futureConfigured = keyKeyId.keyId->clone();
        }
        return {keyKeyId.key, std::move(keyKeyId.keyId)};
    }

    Key key;
    std::unique_ptr<KeyId> keyId;
    if (saveKey) {
        keyId = _saveMasterKey(*_factory->createSave(_wtKeyIds.configured.get()), key);
    }
    return {key, std::move(keyId)};
}

void MasterKeyProvider::saveMasterKey(const Key& key) const {
    _saveMasterKey(*_factory->createSave(_wtKeyIds.configured.get()), key);
}
}  // namespace mongo::encryption
