/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2018-present Percona and/or its affiliates. All rights reserved.

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
#include <optional>
#include <string>

namespace mongo {

struct EncryptionGlobalParams {
    bool enableEncryption{false};
    std::string encryptionCipherMode{"AES256-CBC"};
    std::string encryptionKeyFile;
    std::string vaultServerName;
    int vaultPort;
    std::string vaultTokenFile;
    std::string vaultToken;
    std::string vaultSecret;
    std::optional<std::uint64_t> vaultSecretVersion;
    bool vaultRotateMasterKey{false};
    std::string vaultServerCAFile;
    bool vaultCheckMaxVersions{true};
    bool vaultDisableTLS{false};
    long vaultTimeout{15L};
    std::string kmipServerName;
    int kmipPort{5696};
    std::string kmipServerCAFile;
    std::string kmipClientCertificateFile;
    std::string kmipClientCertificatePassword;
    unsigned kmipConnectRetries{0};
    int kmipConnectTimeoutMS{5000};
    std::string kmipKeyIdentifier;
    bool kmipRotateMasterKey{false};
    int kmipKeyStatePollingSeconds{900};

    bool shouldRotateMasterKey() const noexcept {
        return vaultRotateMasterKey || kmipRotateMasterKey;
    }

    void kmipActivateKeys(bool value) noexcept {
        _kmipActivateKeys = value;
        _kmipToleratePreActiveKeys = false;
    }
    bool kmipActivateKeys() const noexcept {
        return _kmipActivateKeys;
    }
    bool kmipToleratePreActiveKeys() const noexcept {
        return _kmipToleratePreActiveKeys;
    }

private:
    bool _kmipActivateKeys{true};
    /// The option implements a transitional period before all the keys are
    /// strictly checked for being in the `Active` state (since Percona Server
    /// for MongoDB version 8.0). Untill then, not specifying the
    /// `security.kmip.activateKeys` option results in the feature being eanbled
    /// but working in the "soft" mode, meaning that Percona Server for MongoDB:
    /// - activates newly generated keys;
    /// - checks that the exising keys it reads from a KMIP server is either in
    /// the `Active` _or `Pre-Active`_ state.
    ///
    /// In the latter case, `mongod` still uses the key but logs a warning
    /// informing that it won't accept pre-active keys since version 8.0.
    ///
    /// If the key state checking is explicitly enabled by setting
    /// `activateKeys` to `true` in either config file or CLI, then pre-active
    /// keys aren't allowed.
    ///
    /// @note The option is internal, that is its value is determined by
    /// `security.kmip.activateKeys` being present or absent and
    /// can't be set in the configuration file or command line directly.
    bool _kmipToleratePreActiveKeys{true};
};

extern EncryptionGlobalParams encryptionGlobalParams;

}  // namespace mongo
