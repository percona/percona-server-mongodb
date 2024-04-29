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
#include <optional>
#include <string>
#include <string_view>

#include "mongo/db/encryption/key.h"
#include "mongo/db/encryption/key_entry.h"
#include "mongo/db/encryption/key_id.h"

namespace mongo {
class EncryptionGlobalParams;

namespace encryption {

/// @brief The operation of reading an encryption key from a key management
/// facility.
///
/// Examples of a key management facility include an encrytion key file,
/// a Vault server, and a KMIP server. Individual implementations encapsulate
/// how a key is read from a particular facility.
class ReadKey {
public:
    virtual ~ReadKey() = default;
    ReadKey() = default;
    ReadKey(const ReadKey&) = default;
    ReadKey(ReadKey&&) = default;
    ReadKey& operator=(const ReadKey&) = default;
    ReadKey& operator=(ReadKey&&) = default;

    /// @brief Read an encryption key from a key management facility.
    ///
    /// @returns the copy of the key if it exists on the key management
    ///          facility and specific identifier of that key.
    ///
    /// @note In the most cases, the returned identifier is equal to the
    /// requested one, i.e. passed in the constructor of a specific
    /// implementation. However, the requested identifier may contain
    /// a metavalue, e.g. secret version 0 for Vault, which is the
    /// special value for "the key of the most recent version". In the latter
    /// case, the returned key identifier has concrete secret version which
    /// was the latest at the time of reading.
    ///
    /// @throws `std::runtime_error` on failure
    virtual std::optional<KeyEntry> operator()() const = 0;

    const char* facilityType() const noexcept {
        return keyId().facilityType();
    }

    virtual const KeyId& keyId() const noexcept = 0;
};

/// @brief The operation of saving an encryption key to a key management
/// facility.
///
/// Examples of a key management facility include a Vault server and
/// a KMIP server. Individual implementations encapsulate how a key is
/// saved to a particular facility. An implementation is not supposed to
/// overwrite an existing entry on a key management ficility. Instead,
/// it must always create a new one.
class SaveKey {
public:
    virtual ~SaveKey() = default;
    SaveKey() = default;
    SaveKey(const SaveKey&) = default;
    SaveKey(SaveKey&&) = default;
    SaveKey& operator=(const SaveKey&) = default;
    SaveKey& operator=(SaveKey&&) = default;

    /// @brief Saves an encryption key to a key management facility.
    ///
    /// @param key an encryption key whose copy should be saved
    ///            to a key management facility
    ///
    /// @return the identifier of the saved key; never equals to `nullptr`
    ///
    /// @throws `std::runtime_error` on failure
    virtual std::unique_ptr<KeyId> operator()(const Key& key) const = 0;

    virtual const char* facilityType() const noexcept = 0;
};

class ReadKeyFile : public ReadKey {
public:
    explicit ReadKeyFile(const KeyFilePath& path) : _path(path) {}
    explicit ReadKeyFile(KeyFilePath&& path) : _path(std::move(path)) {}

    std::optional<KeyEntry> operator()() const override;

    const KeyId& keyId() const noexcept override {
        return _path;
    }

private:
    KeyFilePath _path;
};

/// @note No save operation is supported for an encryption key file because
/// that would encourage a wider adoption of the non-secure file-based key
/// management facility in mongod users.

class ReadVaultSecret : public ReadKey {
public:
    explicit ReadVaultSecret(const VaultSecretId& id) : _id(id) {}
    explicit ReadVaultSecret(VaultSecretId&& id) : _id(std::move(id)) {}

    std::optional<KeyEntry> operator()() const override;

    const KeyId& keyId() const noexcept override {
        return _id;
    }

private:
    // The function is going to be overridden in the tests
    virtual std::pair<std::string, std::uint64_t> _read(const VaultSecretId& id) const;

    VaultSecretId _id;
};

class SaveVaultSecret : public SaveKey {
public:
    explicit SaveVaultSecret(const std::string& secretPath) : _secretPath(secretPath) {}
    explicit SaveVaultSecret(std::string&& secretPath) : _secretPath(std::move(secretPath)) {}

    std::unique_ptr<KeyId> operator()(const Key& k) const override;

    const char* facilityType() const noexcept override {
        return VaultSecretId::kFacilityType;
    }

    const std::string& secretPath() const noexcept {
        return _secretPath;
    }

private:
    std::string _secretPath;
};

class ReadKmipKey : public ReadKey {
public:
    explicit ReadKmipKey(const KmipKeyId& id) : _id(id) {}
    explicit ReadKmipKey(KmipKeyId&& id) : _id(std::move(id)) {}

    std::optional<KeyEntry> operator()() const override;

    const KeyId& keyId() const noexcept override {
        return _id;
    }

    /// @note Used in the unit tests
    const KmipKeyId& kmipKeyId() const noexcept {
        return _id;
    }

private:
    KmipKeyId _id;
};

class SaveKmipKey : public SaveKey {
public:
    std::unique_ptr<KeyId> operator()(const Key& k) const override;

    const char* facilityType() const noexcept override {
        return KmipKeyId::kFacilityType;
    }
};

/// @brief Factory to produce read and save operations for a key management
/// facility.
class KeyOperationFactory {
public:
    virtual ~KeyOperationFactory() = default;
    KeyOperationFactory() = default;
    KeyOperationFactory(const KeyOperationFactory&) = default;
    KeyOperationFactory(KeyOperationFactory&&) = default;
    KeyOperationFactory& operator=(const KeyOperationFactory&) = default;
    KeyOperationFactory& operator=(KeyOperationFactory&&) = default;

    /// @brief Creates the concrete factory which produces operations
    /// for the key management facility specified in the encryption paramsters.
    ///
    /// @param params encryption parameters
    ///
    /// @returns pointer to the key operation factory
    static std::unique_ptr<KeyOperationFactory> create(const EncryptionGlobalParams& params);

    /// @brief Creates the read operation which would retrieve the key
    /// identified in the encryption parameters, if any.
    ///
    /// @returns pointer to the read operation or `nullptr` if the encryption
    /// parameters doen't specify a key identifier
    virtual std::unique_ptr<ReadKey> createProvidedRead() const = 0;

    /// @brief Creates the read operation which would retrieve
    /// either the key the system was earlier configured with or the key
    /// specified in the encryption parameters.
    ///
    /// Which key is going to be retrieved is determined by the encryption
    /// parameters.
    ///
    /// If no read operation can be created or configured key identifier is
    /// not compatible with the one specified in the encrytion parameters,
    /// then initiates a gracefull exit from the program.
    ///
    /// @param configured Identifier of the encryption key the system was
    ///                   earlier configured with
    ///
    /// @returns the pointer to the read operation
    virtual std::unique_ptr<ReadKey> createRead(const KeyId* configured) const = 0;

    /// @brief Creates the save operation which would save an encryption key
    /// to the key management facility specified in the encryption parameters.
    ///
    /// May import some missing information (e.g. secret path for Vault)
    /// from the identifier of the key the system was earlier configured with.
    ///
    /// @param configured Identifier of the encryption key the system was
    ///                   earlier configured with
    ///
    /// @returns pointer to the save operation
    virtual std::unique_ptr<SaveKey> createSave(const KeyId* configured) const = 0;
};

class KeyFileOperationFactory : public KeyOperationFactory {
public:
    KeyFileOperationFactory(const std::string& encryptionKeyFilePath)
        : _encryptionKeyFilePath(encryptionKeyFilePath) {}

    std::unique_ptr<ReadKey> createProvidedRead() const override {
        return _doCreateRead(_encryptionKeyFilePath);
    }
    std::unique_ptr<ReadKey> createRead(const KeyId* configured) const override {
        return createProvidedRead();
    }
    std::unique_ptr<SaveKey> createSave(const KeyId* configured) const override;

private:
    // allow overriding to enable unit testing
    virtual std::unique_ptr<ReadKey> _doCreateRead(const std::string& encryptionKeyFilePath) const {
        return std::make_unique<ReadKeyFile>(KeyFilePath(encryptionKeyFilePath));
    }

    std::string _encryptionKeyFilePath;
};

namespace detail {
template <typename Derived>
class CreateReadImpl {
protected:
    std::unique_ptr<ReadKey> _createProvidedRead() const;
    std::unique_ptr<ReadKey> _createRead(const KeyId* configured) const;
};
}  // namespace detail

class VaultSecretOperationFactory : public KeyOperationFactory,
                                    private detail::CreateReadImpl<VaultSecretOperationFactory> {
public:
    VaultSecretOperationFactory(bool rotateMasterKey,
                                const std::string& providedSecretPath,
                                const std::optional<std::uint64_t>& providedSecretVersion);
    std::unique_ptr<ReadKey> createProvidedRead() const override;
    std::unique_ptr<ReadKey> createRead(const KeyId* configured) const override;
    std::unique_ptr<SaveKey> createSave(const KeyId* configured) const override;

private:
    friend class detail::CreateReadImpl<VaultSecretOperationFactory>;

    // allow overriding to enable unit testing
    virtual std::unique_ptr<ReadKey> _doCreateRead(const VaultSecretId& id) const {
        return std::make_unique<ReadVaultSecret>(id);
    }
    virtual std::unique_ptr<SaveKey> _doCreateSave(const std::string& secretPath) const {
        return std::make_unique<SaveVaultSecret>(secretPath);
    }

    bool _rotateMasterKey;
    std::optional<VaultSecretId> _provided;
    std::string _providedSecretPath;
    mutable const VaultSecretId* _configured;
};

class KmipKeyOperationFactory : public KeyOperationFactory,
                                private detail::CreateReadImpl<KmipKeyOperationFactory> {
public:
    KmipKeyOperationFactory(bool rotateMasterKey, const std::string& providedKeyId);
    std::unique_ptr<ReadKey> createProvidedRead() const override;
    std::unique_ptr<ReadKey> createRead(const KeyId* configured) const override;
    std::unique_ptr<SaveKey> createSave(const KeyId* configured) const override {
        return _doCreateSave();
    }

private:
    friend class detail::CreateReadImpl<KmipKeyOperationFactory>;

    // allow overriding to enable unit testing
    virtual std::unique_ptr<ReadKey> _doCreateRead(const KmipKeyId& id) const {
        return std::make_unique<ReadKmipKey>(id);
    }
    virtual std::unique_ptr<SaveKey> _doCreateSave() const {
        return std::make_unique<SaveKmipKey>();
    }

    bool _rotateMasterKey;
    std::optional<KmipKeyId> _provided;
    mutable const KmipKeyId* _configured;
};
}  // namespace encryption
}  // namespace mongo
