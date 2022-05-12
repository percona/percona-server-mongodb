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

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kNetwork

#include <kmippp/kmippp.h>

#include "mongo/db/encryption/encryption_kmip.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/json.h"
#include "mongo/logv2/log.h"

namespace mongo {

namespace {
kmippp::context kmipCreateContext() {
    std::string portStr = std::to_string(encryptionGlobalParams.kmipPort);
    return kmippp::context{encryptionGlobalParams.kmipServerName,
                           portStr,
                           encryptionGlobalParams.kmipClientCertificateFile,
                           encryptionGlobalParams.kmipServerCAFile};
}

}  // namespace

std::string kmipReadKey() {
    auto ctx = kmipCreateContext();

    const auto id = ctx.op_locate(encryptionGlobalParams.kmipKeyIdentifier);

    if (id.empty()) {
        LOGV2_DEBUG(29044, 4, "Encryption key doesn't exists on KMIP server");
        return "";
    }

    const auto key = ctx.op_get(id[0]);

    if (key.empty()) {
        LOGV2_DEBUG(
            29045, 4, "ID found on KMIP server, but not actual data. Internal server error?");
        return "";
    }

    return std::string(key.begin(), key.end());
}

bool kmipWriteKey(std::string const& key) {
    auto ctx = kmipCreateContext();

    auto ret = ctx.op_register(encryptionGlobalParams.kmipKeyIdentifier, "", kmippp::context::key_t(key.begin(), key.end()));

    if (ret == "") {
        LOGV2_ERROR(29046, "Couldn't save encryption key on KMIP server.");
        return false;
    }

    return true;
}

}  // namespace mongo
