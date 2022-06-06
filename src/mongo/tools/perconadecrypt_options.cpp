/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2019-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/tools/perconadecrypt_options.h"

#include <iostream>

#include "mongo/db/encryption/encryption_options.h"
#include "mongo/util/options_parser/startup_options.h"
#include "mongo/util/version.h"
#include "mongo/util/version_constants.h"

namespace mongo {

PerconaDecryptGlobalParams perconaDecryptGlobalParams;

void printPerconaDecryptHelp(std::ostream* out) {
    *out << "Usage:" << std::endl
         << "    perconadecrypt [options] --inputPath <src> --outputPath <dest> --encryptionKeyFile <key path>" << std::endl
         << "    perconadecrypt [options] --inputPath <src> --outputPath <dest> --vaultServerName <server name> [other Vault options]" << std::endl
         << "    perconadecrypt [options] --inputPath <src> --outputPath <dest> --kmipServerName <server name> [other KMIP options]" << std::endl
         << "    perconadecrypt --help" << std::endl;
    *out << moe::startupOptions.helpString();
    *out << std::flush;
}

void printPerconaDecryptVersion(std::ostream* out) {
    *out << "perconadecrypt version v" << version::kVersion << std::endl;
    *out << "git version: " << version::kGitVersion << std::endl;
    *out << std::flush;
}

bool handlePreValidationPerconaDecryptOptions(const moe::Environment& params) {
    if (params.count("help")) {
        printPerconaDecryptHelp(&std::cout);
        return false;
    }
    if (params.count("version")) {
        printPerconaDecryptVersion(&std::cout);
        return false;
    }
    return true;
}

Status storePerconaDecryptOptions(const moe::Environment& params,
                               const std::vector<std::string>& args) {
    if (!params.count("encryptionKeyFile") && !params.count("vaultServerName") && !params.count("kmipServerName")) {
        return {ErrorCodes::BadValue, "Missing required option: one of --encryptionKeyFile, --vaultServerName or --kmipServerName must be specified"};
    }

    if (params.count("encryptionKeyFile")) {
        encryptionGlobalParams.encryptionKeyFile = params["encryptionKeyFile"].as<std::string>();
    }

    if (params.count("vaultServerName")) {
        encryptionGlobalParams.vaultServerName = params["vaultServerName"].as<std::string>();
    }

    if (params.count("vaultPort")) {
        encryptionGlobalParams.vaultPort = params["vaultPort"].as<int>();
    }

    if (params.count("vaultTokenFile")) {
        encryptionGlobalParams.vaultTokenFile = params["vaultTokenFile"].as<std::string>();
    }

    if (params.count("vaultSecret")) {
        encryptionGlobalParams.vaultSecret = params["vaultSecret"].as<std::string>();
    }

    if (params.count("vaultServerCAFile")) {
        encryptionGlobalParams.vaultServerCAFile = params["vaultServerCAFile"].as<std::string>();
    }

    if (params.count("vaultDisableTLSForTesting")) {
        encryptionGlobalParams.vaultDisableTLS = params["vaultDisableTLSForTesting"].as<bool>();
    }

    if (params.count("kmipServerName")) {
        encryptionGlobalParams.kmipServerName = params["kmipServerName"].as<std::string>();
    }

    if (params.count("kmipPort")) {
        encryptionGlobalParams.kmipPort = params["kmipPort"].as<int>();
    }

    if (params.count("kmipServerCAFile")) {
        encryptionGlobalParams.kmipServerCAFile = params["kmipServerCAFile"].as<std::string>();
    }

    if (params.count("kmipClientCertificateFile")) {
        encryptionGlobalParams.kmipClientCertificateFile = params["kmipClientCertificateFile"].as<std::string>();
    }

    if (params.count("kmipClientCertificatePassword")) {
        encryptionGlobalParams.kmipClientCertificatePassword =
            params["kmipClientCertificatePassword"].as<std::string>();
    }

    if (params.count("kmipKeyIdentifier")) {
        encryptionGlobalParams.kmipKeyIdentifier = params["kmipKeyIdentifier"].as<std::string>();
    }

    if (params.count("encryptionCipherMode")) {
        encryptionGlobalParams.encryptionCipherMode = params["encryptionCipherMode"].as<std::string>();
    }

    if (!params.count("inputPath")) {
        return {ErrorCodes::BadValue, "Missing required option: --inputPath"};
    }
    perconaDecryptGlobalParams.inputPath = params["inputPath"].as<std::string>();

    if (!params.count("outputPath")) {
        return {ErrorCodes::BadValue, "Missing required option: --outputPath"};
    }
    perconaDecryptGlobalParams.outputPath = params["outputPath"].as<std::string>();

    return Status::OK();
}

}  // namespace mongo
