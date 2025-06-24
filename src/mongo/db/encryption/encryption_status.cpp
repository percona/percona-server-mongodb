/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2025-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/db/commands/server_status.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/encryption/key_id.h"

namespace mongo::encryption {
namespace {

static constexpr auto kEncryptionSSSName = "encryptionAtRest"_sd;
static constexpr auto kEncryptionEnabledName = "encryptionEnabled"_sd;
static constexpr auto kEncryptionKeyIdName = "encryptionKeyId"_sd;
static constexpr auto kEncryptionCipherModeName = "encryptionCipherMode"_sd;
static constexpr auto kEncryptionKeyIdLocal = "local"_sd;

// Thread safety guaranteed because the global params are initialized at startup.
bool isEncryptionEnabled() {
    return encryptionGlobalParams.enableEncryption;
}

// Thread safety guaranteed because the global params are initialized at startup.
const std::string& getCipherMode() {
    return encryptionGlobalParams.encryptionCipherMode;
}

// Thread safety guaranteed because the global params are initialized at startup.
bool isKeyIdLocal() {
    return !encryptionGlobalParams.encryptionKeyFile.empty();
}

// Return 'decryption' if it is set, otherwise 'futureConfigured'.
// The 'decryption' field might not be set if the storage engine metadata was not yet stored.
// The 'futureConfigured' field should be set in such case.
// Returns nullptr if neither is available.
//
// Thread safety: Uses direct but safe access to the WtKeyIds singleton.
// Based on the usage patterns, the risk is mitigated because:
// 1. Key IDs are set once during initialization of the storage engine,
// 2. Key rotation is executed during initialization and the process finishes after that,
// 3. Server status is read-only operation.
const KeyId* getKeyIdPtr() {
    const auto& wtKeyIds = WtKeyIds::instance();

    if (wtKeyIds.decryption) {
        return wtKeyIds.decryption.get();
    }

    if (wtKeyIds.futureConfigured) {
        return wtKeyIds.futureConfigured.get();
    }

    // Return nullptr if neither 'decryption' nor 'futureConfigured' is set.
    return nullptr;
}

class EncryptionSSS : public ServerStatusSection {
public:
    EncryptionSSS() : 
        ServerStatusSection(kEncryptionSSSName.toString()) {}

    bool includeByDefault() const override {
        return true;
    }

    // Generates the 'encryptionAtRest' section of the server status,
    // with the following structure:
    //
    // {
    //   encryptionEnabled: false
    // }
    //
    // if encryption is disabled, or:
    //
    // {
    //   encryptionEnabled: true,
    //   encryptionCipherMode: <string>,
    //   encryptionKeyId: <value>
    // }
    //
    // if encryption is enabled.
    //
    // NOTE: The value of the 'encryptionKeyId' field can be either a primitive
    // value (e.g., string, number) or an object, depending on the type of key
    // identifier used.
    BSONObj generateSection(OperationContext*, const BSONElement&) const final {
        BSONObjBuilder builder;

        const bool encryptionEnabled = isEncryptionEnabled();

        builder.append(kEncryptionEnabledName, encryptionEnabled);

        if (encryptionEnabled) {
            builder.append(kEncryptionCipherModeName, getCipherMode());

            if (const KeyId* keyId = getKeyIdPtr(); keyId) {
                keyId->serializeToServerStatus(&builder, kEncryptionKeyIdName);
            } else if (isKeyIdLocal()) {
                // When the encryption with key file is used for the first time, the keyId will be
                // null. In such case we check if the 'encryptionKeyFile' param is set and return
                // the 'local' key ID.
                builder.append(kEncryptionKeyIdName, kEncryptionKeyIdLocal);
            } else {
                builder.appendNull(kEncryptionKeyIdName);
            }
        }

        return builder.obj();
    }
} gEncryptionSSS;

}  // namespace
}  // namespace mongo::encryption
