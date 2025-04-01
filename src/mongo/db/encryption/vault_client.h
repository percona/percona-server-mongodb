/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2024-present Percona and/or its affiliates. All rights reserved.

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
#include <utility>

namespace mongo::encryption {
class VaultClient {
public:
    ~VaultClient();

    VaultClient(const VaultClient&) = delete;
    VaultClient& operator=(const VaultClient&) = delete;

    VaultClient(VaultClient&&);
    VaultClient& operator=(VaultClient&&);

    VaultClient(const std::string& host,
                int port,
                const std::string& token,
                const std::string& tokenFile,
                const std::string& serverCaFile,
                bool checkMaxVersions,
                bool disableTls,
                long timeout);

    /// @brief Reads an encryption key from the Vault server.
    ///
    /// @param secretPath path to the encryption key on the Vault server
    /// @param secretVersion the version of the key;
    ///                      default is zero meaning the most recent version
    ///
    /// @returns If the key was successfully read from the Vault server,
    ///          its data (in base64 encoding) and specific version (never `0`)
    ///          are returned. Otherwise, the function returns the pair of an
    ///          empty string and zero integer.
    ///
    /// @throws std::runtime_error in case of issues
    std::pair<std::string, std::uint64_t> getKey(const std::string& secretPath,
                                                 std::uint64_t secretVersion = 0) const;

    /// @brief Creates a copy of the key on the Vault server.
    ///
    /// @param secretPath path to the encryption key on the Vault server
    /// @param key base64-encoded key data
    ///
    /// @returns the version of registered the key as a positive integer
    ///
    /// @throws std::runtime_error in case of issues
    std::uint64_t putKey(const std::string& secretPath, const std::string& key) const;

private:
    class Impl;
    std::unique_ptr<Impl> _impl;
};
}  // namespace mongo::encryption
