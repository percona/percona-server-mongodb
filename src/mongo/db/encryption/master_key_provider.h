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

#include <functional>
#include <memory>
#include <utility>

#include "mongo/logv2/log_component.h"

namespace mongo {
struct EncryptionGlobalParams;
class PeriodicJobAnchor;
class PeriodicRunner;
namespace encryption {
class Key;
struct KeyEntry;
class KeyId;
class KeyOperationFactory;
class ReadKey;
class SaveKey;
class WtKeyIds;

class MasterKeyProvider {
public:
    ~MasterKeyProvider();
    MasterKeyProvider(std::unique_ptr<const KeyOperationFactory>&& factory,
                      WtKeyIds& wtKeyIds,
                      logv2::LogComponent logComponent);

    /// @brief Creates the master key provider.
    ///
    /// The function is a customization point which enables unit tests.
    ///
    /// @param params encryption parameters whcih define
    /// @param logComponent the component errors are logged with
    ///
    /// @returns pointer the master key provider
    static std::unique_ptr<MasterKeyProvider> create(const EncryptionGlobalParams& params,
                                                     logv2::LogComponent logComponent);
    /// @brief Reads the master encryption key from the key management facility.
    ///
    /// Intended to be called for retrieving the master key for an _existing_
    /// encyption key database.
    ///
    /// @returns the master encryption key and its identifier
    ///
    /// @throws `encryption::Error` if can't unambiguously read the key from
    /// the key management facility
    KeyEntry readMasterKey() const;

    /// @brief Reads an existing master key from a key management factility or
    /// generates and saves a new one.
    ///
    /// Intendend to be called for obtaining the master key for
    /// a _just created_ encryption key database.
    ///
    /// @param saveKey if true, the generated key is immediately saved
    ///                to the key management facility
    /// @param raiseOnError if true, throws a `KeyError` exception when
    ///                     operation on the key fails; otherwise initiates
    ///                     a graceful exit from the program.
    ///
    /// @returns the read or generated encryption key and its identifier;
    ///          the latter is not `nullptr` if `saveKey` is `true`
    ///
    /// @throws `encryption::Error` if can't unambiguously read the key from or
    /// save the key to the key management facility
    KeyEntry obtainMasterKey(bool saveKey = true) const;

    /// @brief Saves the master key to a key manageent facitlity.
    ///
    /// @param key an encryption key to be saves
    ///
    /// @throws `encryption::Error` if can't unambiguously save the key to
    /// the key management facility
    void saveMasterKey(const Key& key) const;

    /// @brief If applicable, registers a periodic job for verifying that
    /// an encrypiton key is active.
    ///
    /// The function determines whether the key management facility specified
    /// in the configuration supports key states and, if so, registers a job
    /// for periodically verifying that a key is in the `Active` state.
    /// If the job detects the opposite, it logs an error and initiates
    /// process shutdown. Shutdown is not initiated if the job can't retrieve
    /// the key state from the key management factility, e.g. because the key
    /// server is unavailable. An error is log in that case, though.
    ///
    /// @param pr the periodic runner the job should be registered in
    /// @param keyId the identifier of the key whose state needs verification
    ///
    /// @return The anchor for the registered job or an invalid anchor if
    ///     no job was registered
    PeriodicJobAnchor registerKeyStateVerificationJob(PeriodicRunner& pr, const KeyId& keyId) const;

private:
    KeyEntry _readMasterKey(const ReadKey& read, bool updateKeyIds = true) const;
    std::unique_ptr<KeyId> _saveMasterKey(const SaveKey& save, const Key& key) const;

    std::unique_ptr<const KeyOperationFactory> _factory;
    WtKeyIds& _wtKeyIds;
    logv2::LogComponent _logComponent;
};

using MasterKeyProviderFactory = std::function<std::unique_ptr<MasterKeyProvider>(
    const EncryptionGlobalParams&, logv2::LogComponent)>;
}  // namespace encryption
}  // namespace mongo
