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


#include <kmippp/kmippp.h>

#include <vector>

#include <boost/algorithm/string/split.hpp>

#include "mongo/db/encryption/encryption_kmip.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/json.h"
#include "mongo/logv2/log.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kNetwork


namespace mongo::encryption::detail {

namespace {
kmippp::context kmipCreateContext() {
    std::vector<std::string> serverNames;
    boost::algorithm::split(
        serverNames, encryptionGlobalParams.kmipServerName, [](char c) { return c == ','; });
    std::string portStr = std::to_string(encryptionGlobalParams.kmipPort);
    for (const auto& serverName : serverNames) {
        try {
            return kmippp::context{serverName,
                                   portStr,
                                   encryptionGlobalParams.kmipClientCertificateFile,
                                   encryptionGlobalParams.kmipClientCertificatePassword,
                                   encryptionGlobalParams.kmipServerCAFile};

        } catch (const kmippp::connection_error& e) {
            LOGV2_DEBUG(29106,
                        2,
                        "Cannot connect to the KMIP server",
                        "serverName"_attr = e.server_name,
                        "port"_attr = e.port,
                        "reason"_attr = e.reason);
            continue;
        }
    }
    throw std::runtime_error("Can't connect to any of KMIP servers specified in the configuration");
}

}  // namespace

std::vector<std::uint8_t> kmipReadKey(const std::string& keyId) {
    auto ctx = kmipCreateContext();
    const auto key = ctx.op_get(keyId);

    if (key.empty()) {
        LOGV2_DEBUG(29045, 4, "No key is found on the KMIP server");
    }
    return key;
}

std::string kmipWriteKey(const std::vector<std::uint8_t>& keyData) {
    auto ctx = kmipCreateContext();
    return ctx.op_register(keyData);
}

}  // namespace mongo::encryption::detail
