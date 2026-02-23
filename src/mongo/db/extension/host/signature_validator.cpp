/**
 *    Copyright (C) 2026-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */


#include "mongo/db/extension/host/signature_validator.h"

#include "mongo/db/extension/host/mongot_extension_signing_key.h"
#include "mongo/db/server_options.h"
#include "mongo/logv2/log.h"
#include "mongo/util/str.h"

#include <fstream>

#include <fmt/format.h>

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kExtension

namespace mongo::extension::host {

namespace {

// Note, this function should only be called if we are not skipping validation, since we expect a
// non-empty extensionValidationPublicKeyPath.
// TODO SERVER-115289: Revisit public key management depending on library implementation.
const std::string& getValidationPublicKey() {
#ifndef MONGO_CONFIG_EXT_SIG_SECURE
    static const std::string kPublicKey = []() {
        const auto& extensionValidationPublicKeyPath =
            serverGlobalParams.extensionsSignaturePublicKeyPath;
        tassert(11528801,
                "extensionsSignaturePublicKeyPath was empty!",
                !extensionValidationPublicKeyPath.empty());
        LOGV2_DEBUG(11528803,
                    4,
                    "SignatureValidator using public key path",
                    "extensionValidationPublicKeyPath"_attr = extensionValidationPublicKeyPath);
        std::ifstream in(extensionValidationPublicKeyPath);
        tassert(11528802,
                fmt::format("Failed to open signature file: {}", extensionValidationPublicKeyPath),
                in);
        std::string contents((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
        return contents;
    }();
#else
    static const std::string kPublicKey(kMongoExtensionSigningPublicKey);
#endif
    return kPublicKey;
}
}  // namespace

SignatureValidator::SignatureValidator()
    : _skipValidation([]() {
// TODO SERVER-115289: Remove ENABLE_SIGNATURE_VALIDATOR guard for skipValidation.
#ifdef ENABLE_SIGNATURE_VALIDATOR
#ifndef MONGO_CONFIG_EXT_SIG_SECURE
          return serverGlobalParams.extensionsSignaturePublicKeyPath.empty();
#else
          return false;
#endif
#else
          return true;
#endif
      }()) {
    LOGV2_DEBUG(11528804, 4, "Initializing SignatureValidator");

    if (_skipValidation) {
        LOGV2_DEBUG(11528805, 4, "Skipping signature validation");
        return;
    }
    // TODO SERVER-115289: Initialize implementation specific context and import key into keyring.
}

SignatureValidator::~SignatureValidator() {
    if (_skipValidation) {
        return;
    }
}

void SignatureValidator::validateExtensionSignature(const std::string& extensionName,
                                                    const std::string& extensionPath) const {
    if (_skipValidation) {
        LOGV2_DEBUG(11528806, 4, "Skipping signature validation");
        return;
    }
    // TODO SERVER-115289: Implement signature validation.
}
}  // namespace mongo::extension::host
