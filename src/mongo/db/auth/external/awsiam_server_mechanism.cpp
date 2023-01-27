/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2023-present Percona and/or its affiliates. All rights reserved.

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

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kAccessControl

#include "mongo/db/auth/external/awsiam_server_mechanism.h"

#include <algorithm>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <fmt/format.h>

#include "mongo/base/error_codes.h"
#include "mongo/base/status.h"
#include "mongo/base/status_with.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/client/sasl_aws_protocol_common.h"
#include "mongo/client/sasl_aws_protocol_common_gen.h"
#include "mongo/db/auth/sasl_mechanism_registry.h"
#include "mongo/logv2/log.h"
#include "mongo/platform/mutex.h"
#include "mongo/platform/random.h"
#include "mongo/stdx/mutex.h"
#include "mongo/util/base64.h"
#include "mongo/util/net/http_client.h"
#include "mongo/util/str.h"

namespace mongo {
namespace awsIam {
namespace {
// Secure Random for AWS SASL Nonce generation
Mutex saslAWSServerMutex = MONGO_MAKE_LATCH("AWSIAMServerMutex");
SecureRandom saslAWSServerGen;

StringData toString(const DataBuilder& builder) {
    ConstDataRange cdr = builder.getCursor();
    StringData str;
    cdr.readInto<StringData>(&str);
    return str;
}
}  // namespace

void ServerMechanism::appendExtraInfo(BSONObjBuilder* bob) const {
    static constexpr auto kAwsId = "awsId"_sd;
    static constexpr auto kAwsArn = "awsArn"_sd;
    bob->append(kAwsId, _userId);
    bob->append(kAwsArn, ServerMechanismBase::_principalName);
}

StatusWith<std::tuple<bool, std::string>> ServerMechanism::stepImpl(
    [[maybe_unused]] OperationContext* opCtx, StringData inputData) try {
    switch (++_step) {
        case 1:
            return _firstStep(inputData);
        case 2:
            return _secondStep(inputData);
        default:
            return Status(ErrorCodes::AuthenticationFailed,
                          str::stream() << "Invalid AWS authentication step: " << _step);
    }
} catch (...) {
    return exceptionToStatus();
}

StatusWith<std::tuple<bool, std::string>> ServerMechanism::_firstStep(StringData inputData) {
    auto clientFirst = awsIam::convertFromByteString<awsIam::AwsClientFirst>(inputData);
    auto clientNonce = clientFirst.getNonce();
    _gs2_cb_flag = clientFirst.getGs2_cb_flag();
    _serverNonce.resize(kServerFirstNonceLength);
    std::copy(clientNonce.data(), clientNonce.data() + clientNonce.length(), _serverNonce.begin());
    {
        stdx::lock_guard<Latch> lk(saslAWSServerMutex);
        saslAWSServerGen.fill(_serverNonce.data() + clientNonce.length(),
                              kServerFirstNoncePieceLength);
    }
    AwsServerFirst first;
    first.setServerNonce(_serverNonce);
    first.setStsHost(kAwsDefaultStsHost);
    return std::make_tuple(false, convertToByteString(first));
}

StatusWith<std::tuple<bool, std::string>> ServerMechanism::_secondStep(StringData inputData) {
    auto clientSecond = awsIam::convertFromByteString<awsIam::AwsClientSecond>(inputData);
    static constexpr auto kSTSGetCallerIdentityBody =
        "Action=GetCallerIdentity&Version=2011-06-15"_sd;

    auto http = HttpClient::create();
    std::vector<std::string> headers;
    headers.emplace_back(fmt::format("Content-Length: {}", kSTSGetCallerIdentityBody.size()));
    headers.emplace_back("Content-Type: application/x-www-form-urlencoded");
    headers.emplace_back("Authorization: " + clientSecond.getAuthHeader());
    headers.emplace_back("X-Amz-Date: " + clientSecond.getXAmzDate());
    headers.emplace_back(fmt::format(
        "{}: {}", kMongoGS2CBHeader, StringData{reinterpret_cast<const char*>(&_gs2_cb_flag), 1}));
    headers.emplace_back(fmt::format("{}: {}",
                                     kMongoServerNonceHeader,
                                     base64::encode(_serverNonce.data(), _serverNonce.size())));
    if (auto stoken = clientSecond.getXAmzSecurityToken()) {
        headers.emplace_back("X-Amz-Security-Token: " + *stoken);
    }
    http->setHeaders(headers);
    auto reply =
        http->request(HttpClient::HttpMethod::kPOST,
                      "https://" + kAwsDefaultStsHost,
                      {kSTSGetCallerIdentityBody.rawData(), kSTSGetCallerIdentityBody.size()});
    LOGV2_DEBUG(29114, 3, "STS GetCallerIdentity HTTP status", "code"_attr = reply.code);
    if (reply.code != 200) {
        return Status(ErrorCodes::AuthenticationFailed,
                      str::stream()
                          << "Unexpected GetCallerIdentity HTTP status code: " << reply.code);
    }
    _parseStsResponse(toString(reply.body));

    return std::make_tuple(true, std::string());
}

void ServerMechanism::_parseStsResponse(StringData body) {
    // Parse the XML string into a Boost Property Tree
    std::istringstream ss(body.toString());
    boost::property_tree::ptree pt;
    boost::property_tree::read_xml(ss, pt);

    _userId = pt.get<std::string>("GetCallerIdentityResponse.GetCallerIdentityResult.UserId");
    ServerMechanismBase::_principalName =
        pt.get<std::string>("GetCallerIdentityResponse.GetCallerIdentityResult.Arn");
}

namespace {
GlobalSASLMechanismRegisterer<ServerFactory> externalRegisterer;
}  // anonymous namespace
}  // namespace awsIam
}  // namespace mongo
