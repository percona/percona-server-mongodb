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

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include "mongo/base/string_data.h"

namespace mongo {
class BSONObj;
class BSONObjBuilder;
class EncryptionGlobalParams;

namespace encryption {
class KeyIdConstVisitor;
class ReadKey;

class KeyId {
public:
    // @todo Consider introducing the macro which, given a class name, would
    // declare all the six special member functions with default definitions,
    // making the destructor virtual.
    // Using the macro may eliminate boilerplate code.
    // @see the `KeyIdConstVisitor` classes where
    // boilerplate code is about half of the definition;
    virtual ~KeyId() = default;
    KeyId() = default;
    KeyId(const KeyId&) = default;
    KeyId(KeyId&&) = default;
    KeyId& operator=(const KeyId&) = default;
    KeyId& operator=(KeyId&&) = default;

    virtual std::unique_ptr<KeyId> clone() const = 0;

    /// @brief Reads an encryption key identifier (if any) from the storage
    /// engine encryption options.
    ///
    /// @param options storage engine encryption options
    ///
    /// @returns pointer to the read key identifier, if any
    ///
    /// @throws std::runtime_error in case of invalid options format
    static std::unique_ptr<KeyId> fromStorageEngineEncryptionOptions(const BSONObj& options);
    /// @brief Serializes the encryption key identifier to the storage engine
    /// encryption options, which, in turn, are kept in storage engine metadata.
    void serializeToStorageEngineEncryptionOptions(BSONObjBuilder* b) const;
    virtual bool needsSerializationToStorageEngineEncryptionOptions() const noexcept = 0;

    /// @brief Makes the class and its subclasses loggable with LOGV2.
    virtual void serialize(BSONObjBuilder* b) const = 0;

    /// @brief Serializes the key identifier for the server status command with the given field name.
    virtual void serializeToServerStatus(BSONObjBuilder* b, StringData fieldName) const = 0;

    virtual void accept(KeyIdConstVisitor& v) const = 0;

    /// @brief Returns the type of the key management facility suitable for
    /// keeping the key this identifier points to.
    virtual const char* facilityType() const noexcept = 0;

private:
    /// @brief Returns field name under which this key identifier is serialized
    /// to the storage engine encryption opitons.
    ///
    /// @note seeo stands for storage engine encryption options.
    virtual const char* _seeoFieldName() const noexcept = 0;
    /// @brief Serializes the key identifier value itself to the storage engine
    /// encrypiton opitons.
    ///
    /// @note seeo stands for storage engine encryption options.
    /// @note This seiralization may differ from the serialization for logging.
    virtual void _serializeValueToSeeo(BSONObjBuilder* b) const = 0;
};

class KeyFilePath : public KeyId {
public:
    explicit KeyFilePath(const std::string& path) : _path(path) {}
    explicit KeyFilePath(std::string&& path) : _path(std::move(path)) {}
    std::unique_ptr<KeyId> clone() const override {
        return std::make_unique<KeyFilePath>(*this);
    }

    bool operator==(const KeyFilePath& that) const noexcept {
        return _path == that._path;
    }
    bool operator!=(const KeyFilePath& that) const noexcept {
        return !(*this == that);
    }

    const std::string& toString() const {
        return _path;
    }

    bool needsSerializationToStorageEngineEncryptionOptions() const noexcept override {
        return false;
    }

    void serialize(BSONObjBuilder* b) const override;
    void serializeToServerStatus(BSONObjBuilder* b, StringData fieldName) const override;
    void accept(KeyIdConstVisitor& v) const override;

    static constexpr const char* kFacilityType = "encryption key file";
    const char* facilityType() const noexcept override {
        return kFacilityType;
    }

private:
    const char* _seeoFieldName() const noexcept override;
    void _serializeValueToSeeo(BSONObjBuilder* b) const override;

    std::string _path;
};

class VaultSecretId : public KeyId {
public:
    VaultSecretId(const std::string& path, std::uint64_t version)
        : _path(path), _version(version) {}
    VaultSecretId(std::string&& path, std::uint64_t version)
        : _path(std::move(path)), _version(version) {}

    static std::unique_ptr<VaultSecretId> create(const BSONObj& o);

    std::unique_ptr<KeyId> clone() const override {
        return std::make_unique<VaultSecretId>(*this);
    }

    bool operator==(const VaultSecretId& that) const noexcept {
        return _path == that._path && _version == that._version;
    }
    bool operator!=(const VaultSecretId& that) const noexcept {
        return !(*this == that);
    }

    const std::string& path() const noexcept {
        return _path;
    }
    std::uint64_t version() const noexcept {
        return _version;
    }

    bool needsSerializationToStorageEngineEncryptionOptions() const noexcept override {
        return true;
    }

    void serialize(BSONObjBuilder* b) const override;
    void serializeToServerStatus(BSONObjBuilder* b, StringData fieldName) const override;
    void accept(KeyIdConstVisitor& v) const override;

    static constexpr const char* kFacilityType = "Vault server";
    const char* facilityType() const noexcept override {
        return kFacilityType;
    }

private:
    friend std::unique_ptr<KeyId> KeyId::fromStorageEngineEncryptionOptions(const BSONObj& options);

    static constexpr const char* _kSeeoFieldName = "vault";
    const char* _seeoFieldName() const noexcept override {
        return _kSeeoFieldName;
    }
    void _serializeValueToSeeo(BSONObjBuilder* b) const override;
    void _serializeImpl(BSONObjBuilder* b) const;

    std::string _path;
    std::uint64_t _version;
};

class KmipKeyId : public KeyId {
public:
    explicit KmipKeyId(std::string&& keyId) : _keyId(std::move(keyId)) {}
    explicit KmipKeyId(const std::string& keyId) : _keyId(keyId) {}

    static std::unique_ptr<KmipKeyId> create(const BSONObj& o);

    std::unique_ptr<KeyId> clone() const override {
        return std::make_unique<KmipKeyId>(*this);
    }

    bool operator==(const KmipKeyId& that) const noexcept {
        return _keyId == that._keyId;
    }
    bool operator!=(const KmipKeyId& that) const noexcept {
        return !(*this == that);
    }

    const std::string& toString() const {
        return _keyId;
    }

    bool needsSerializationToStorageEngineEncryptionOptions() const noexcept override {
        return true;
    }

    void serialize(BSONObjBuilder* b) const override;
    void serializeToServerStatus(BSONObjBuilder* b, StringData fieldName) const override;
    void accept(KeyIdConstVisitor& v) const override;

    static constexpr const char* kFacilityType = "KMIP server";
    const char* facilityType() const noexcept override {
        return kFacilityType;
    }

private:
    friend std::unique_ptr<KeyId> KeyId::fromStorageEngineEncryptionOptions(const BSONObj& options);

    static constexpr const char* _kSeeoFieldName = "kmip";
    const char* _seeoFieldName() const noexcept override {
        return _kSeeoFieldName;
    }
    void _serializeValueToSeeo(BSONObjBuilder* b) const override;

    std::string _keyId;
};

/// @brief Visitor that does not change a key identifier object.
class KeyIdConstVisitor {
public:
    virtual ~KeyIdConstVisitor() = default;
    KeyIdConstVisitor() = default;
    KeyIdConstVisitor(const KeyIdConstVisitor&) = default;
    KeyIdConstVisitor(KeyIdConstVisitor&&) = default;
    KeyIdConstVisitor& operator=(const KeyIdConstVisitor&) = default;
    KeyIdConstVisitor& operator=(KeyIdConstVisitor&&) = default;

    virtual void visit(const KeyFilePath& p) = 0;
    virtual void visit(const VaultSecretId& id) = 0;
    virtual void visit(const KmipKeyId& id) = 0;
};

/// @brief Collection of key identifiers which are used during
/// the construction of the `WiredTigerKVEngine` class.
///
/// @note Ideally, key identifiers should be passed between
/// source code components as function arguments and return values.
/// Unfortunately, that would further complicate the already problematic
/// process of syncing some code components with the upstream repository.
/// For instance, the `WiredTigerKVEngine` class constructor already has
/// _ten_ arguments and adding even more is not an option. Thus, having to
/// use some analog of a nasty global variable for now.
///
/// @warning Thread Safety: This singleton is NOT fully thread-safe.
/// The fields are set once during startup/initialization and
/// then read during runtime operations like server status generation.
/// Concurrent modifications may cause data races.
/// Consider adding synchronization if concurrent access patterns change.
///
/// @todo Refactor the code so that this singleton is eliminated.
class WtKeyIds {
public:
    static WtKeyIds& instance();

    /// @brief The present configured key identifier, if any.
    ///
    /// It is read from the storage engine metadata, specifically from the
    /// storage engine encryption options.
    std::unique_ptr<KeyId> configured;

    /// @brief The identifier of the key the encryption key database is
    /// decrypted with.
    ///
    /// It may either be equal to configured key identifier or read from the
    /// mongod configuration.
    std::unique_ptr<KeyId> decryption;

    /// @brief The future configured key identifier, if any.
    ///
    /// It may either be read from the mongod configuration or initialized
    /// during master key generation and subsequent saving to the key
    /// management facility.
    /// It is meant to be saved to the storage engine metadata (specifically,
    /// to storage engine encryption options) if differs from the present
    /// configured key identifier.
    std::unique_ptr<KeyId> futureConfigured;

private:
    ~WtKeyIds() = default;
    WtKeyIds() = default;
    WtKeyIds(const WtKeyIds&) = delete;
    WtKeyIds(WtKeyIds&&) = delete;
    WtKeyIds& operator=(const WtKeyIds&) = delete;
    WtKeyIds& operator=(WtKeyIds&&) = delete;
};
}  // namespace encryption
}  // namespace mongo
