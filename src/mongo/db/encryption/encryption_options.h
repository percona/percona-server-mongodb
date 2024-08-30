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
    bool kmipActivateKeys{true};
    int kmipKeyStatePollingSeconds{900};

    bool shouldRotateMasterKey() const noexcept {
        return vaultRotateMasterKey || kmipRotateMasterKey;
    }
};

extern EncryptionGlobalParams encryptionGlobalParams;

}  // namespace mongo
