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

#include "mongo/db/encryption/vault_secret_metadata_locator.h"

#include <sstream>
#include <stdexcept>

namespace mongo::encryption::detail {
namespace {
std::string invalidSecretPathMsg(const std::string_view& secretPath) {
    std::ostringstream msg;
    msg << "Invalid Vault secret path: `" << secretPath << "`.";
    return msg.str();
}
}  // namespace

VaultSecretMetadataLocator::VaultSecretMetadataLocator(const std::string_view& secretPathOrig) {
    static constexpr std::string_view kData("/data/");
    static constexpr std::string_view kDataNoSlash("data/");
    static constexpr std::string_view kConfig{"/config"};
    static constexpr std::string_view kMetadata{"/metadata/"};

    std::string_view secretPath(secretPathOrig);
    while (secretPath.starts_with('/')) {
        secretPath.remove_prefix(1);
    }
    while (secretPath.ends_with('/')) {
        secretPath.remove_suffix(1);
    }
    std::size_t pos = secretPath.find(kData);
    if (pos == std::string_view::npos) {
        throw std::runtime_error(invalidSecretPathMsg(secretPathOrig));
    }

    std::string_view engineMountPath(secretPath.data(), pos);
    std::string_view secretRelativePath(secretPath.data() + pos + kData.size(),
                                        secretPath.data() + secretPath.size());
    if (engineMountPath.empty() || secretRelativePath.empty()) {
        throw std::runtime_error(invalidSecretPathMsg(secretPathOrig));
    }
    if (secretRelativePath.starts_with(kDataNoSlash) ||
        secretRelativePath.find(kData) != std::string_view::npos) {
        std::ostringstream msg;
        msg << "Ambiguous Vault secret path: `" << secretPathOrig << "` cannot be split into "
            << "an engine mount path and a secret path on that engine due to multiple `/data/` "
            << "components. Please specify an unambiguous secret path in the "
            << "`security.vault.secret` during master key rotation or initial node setup.";
        throw std::runtime_error(msg.str());
    }

    engineConfigPath.reserve(engineMountPath.size() + kConfig.size());
    engineConfigPath.append(engineMountPath).append(kConfig);
    metadataPath.reserve(engineMountPath.size() + kMetadata.size() + secretRelativePath.size());
    metadataPath.append(engineMountPath).append(kMetadata).append(secretRelativePath);
}
}  // namespace mongo::encryption::detail
