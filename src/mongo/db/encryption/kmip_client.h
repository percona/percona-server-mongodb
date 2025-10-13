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

#pragma once

#include <chrono>
#include <memory>
#include <string>

#include <boost/optional.hpp>

#include "mongo/db/encryption/key_state.h"

namespace mongo::encryption {
class Key;

class KmipClient {
public:
    ~KmipClient();

    KmipClient(const KmipClient&) = delete;
    KmipClient& operator=(const KmipClient&) = delete;

    KmipClient(KmipClient&&);
    KmipClient& operator=(KmipClient&&);

    KmipClient(const std::string& host,
               const std::string& port,
               const std::string& serverCaFile,
               const std::string& clientCertificateFile,
               const std::string& clientCertificatePassword,
               std::chrono::milliseconds timeout);

    /// @brief Registers a symmetric encryption key on the KMIP server.
    ///
    /// @param key the key to register
    /// @param activate whether the key should be transitioned to the `Active`
    ///     state
    ///
    /// @returns the identifier of the registered key
    ///
    /// @throws `std::runtime_error` if the key can't be registered or activated
    std::string registerSymmetricKey(const Key& key, bool activate = true);

    /// @brief Reads a symmetric encryption key from the KMIP server.
    ///
    /// @param keyId the identifier of the key to be read
    /// @param verifyState if true, verify that the key is in the `Active` state
    ///     before reading its data from the server
    ///
    /// @returns The key with the specified identifier. If no such a key exists,
    ///     `KeyDoesNot` is returned via the unique pointer. If `verifyState` is
    ///     `true` but the key is not in the `Active` state, then the function
    ///     returns a `KeyIsNotActive` object via the unique pointer.
    ///
    /// @throws `std::runtime_error` if any other error occurs
    std::pair<boost::optional<Key>, boost::optional<KeyState>> getSymmetricKey(
        const std::string& keyId, bool verifyState = true);

    /// @brief Reads the state of an encryption key.
    ///
    /// @param keyId the identifier of the key whose state needs to be read
    ///
    /// @returns the state of the key or uninitialized optional if the key with
    ///     the specifed identifier does not exist
    ///
    /// @throws `std::runtime_error` if any other error occurs
    boost::optional<KeyState> getKeyState(const std::string& keyId);

private:
    class Impl;
    std::unique_ptr<Impl> _impl;
};
}  // namespace mongo::encryption
