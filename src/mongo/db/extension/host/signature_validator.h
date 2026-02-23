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

#pragma once

#include "mongo/util/modules.h"

#include <string>

namespace mongo::extension::host {

/**
 * SignatureValidator is responsible for validating an extension's signature file against a public
 * key.
 *
 * This class respects the compile-time pre-processor flag MONGO_CONFIG_EXT_SIG_SECURE and server
 * options (i.e extensionsSignaturePublicKeyPath) when determining which validation public key to
 * use for signature verification. Note, this class is always safe to instantiate, even if signature
 * verification is disabled (i.e extensionsSignaturePublicKeyPath is empty).
 *
 * Note: SignatureValidator is currently always disabled for the time being.
 * TODO SERVER-115289: Update comment with implementation specific details regarding signature
 * verification library.
 */
class SignatureValidator {
public:
    SignatureValidator();
    SignatureValidator(const SignatureValidator&) = delete;
    SignatureValidator& operator=(const SignatureValidator&) = delete;

    ~SignatureValidator();
    /**
     * Validates the extension's detached signature file against the validation public key.
     * Note, extensionPath must be guaranteed to exist prior to calling this method. If the
     * signature is not validated succesfully, an exception is thrown.
     */
    void validateExtensionSignature(const std::string& extensionName,
                                    const std::string& extensionPath) const;

private:
    const bool _skipValidation;
};

}  // namespace mongo::extension::host
