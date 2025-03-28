/**
 *    Copyright (C) 2025-present MongoDB, Inc.
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

#include "mongo/db/auth/external/sasl_oidc_server_mechanism.h"

// #include <jwt-cpp/jwt.h>

#define JWT_DISABLE_PICOJSON
#include <jwt-cpp/jwt.h>
#include "jwt-cpp/traits/boost-json/traits.h"
#include "jwt-cpp/traits/boost-json/defaults.h"

#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/auth/oidc/oidc_server_parameters_gen.h"
#include "mongo/db/auth/sasl_mechanism_registry.h"
#include "mongo/db/auth/sasl_plain_server_conversation.h"
#include "mongo/db/server_parameter.h"
#include "mongo/logv2/log.h"
#include "mongo/logv2/log_attr.h"
#include "mongo/logv2/log_component.h"
#include "mongo/util/assert_util.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kAccessControl

namespace mongo {
StatusWith<std::tuple<bool, std::string>> SaslOidcServerMechanism::stepImpl(OperationContext* opCtx,
                                                                            StringData input) {
    switch (++_step) {
        case 1:
            return step1(opCtx, input);
        case 2:
            return step2(opCtx, input);
        default:
            return Status(ErrorCodes::AuthenticationFailed,
                          str::stream() << "Invalid OIDC authentication step: " << _step);
    }
    MONGO_UNREACHABLE;
}

StatusWith<std::tuple<bool, std::string>> SaslOidcServerMechanism::step1(OperationContext* opCtx,
                                                                         StringData input) {
    LOGV2(77010, "SaslOidcServerMechanism::stepImpl", "input"_attr = input);
    if (Status s = validateBSON(input.data(), input.size()); !s.isOK()) {
        return Status(ErrorCodes::BadValue, "Not a valid BSON");
    }
    if (BSONObj obj(input.data()); !obj.isEmpty()) {
        return Status(ErrorCodes::BadValue, "Not an empty object");
    }

    auto serverParam =
        ServerParameterSet::getNodeParameterSet()->get<OidcIdentityProvidersServerParameter>(
            "oidcIdentityProviders");
    BSONObjBuilder b;
    const OidcIdentityProviderConfig& conf = serverParam->_data.at(0);
    b.append("issuer", conf.getIssuer());
    if (conf.getSupportsHumanFlows()) {
        b.append("clientId", *conf.getClientId());
    }
    BSONObj obj = b.done();
    return std::tuple(false, std::string(obj.objdata(), obj.objsize()));
}

template <typename T>
class trap;

StatusWith<std::tuple<bool, std::string>> SaslOidcServerMechanism::step2(OperationContext* opCtx,
                                                                         StringData input) {
    LOGV2(77010, "SaslOidcServerMechanism::stepImpl", "input"_attr = input);

    if (Status s = validateBSON(input.data(), input.size()); !s.isOK()) {
        return Status(ErrorCodes::BadValue, "Not a valid BSON");
    }

    BSONObj obj(input.data());
    LOGV2(77011, "OIDC step 2 input", "input"_attr = obj);

    BSONElement jwtElem = obj.getField("jwt");
    if (jwtElem.eoo()) {
        return Status(ErrorCodes::BadValue, "Input BSON has no `jwt` field");
    }
    if (jwtElem.type() != BSONType::String) {
        return Status(ErrorCodes::BadValue, "The `jwt` field is not a string");
    }

    try {
        // auto decoded = jwt::decode<jwt::traits::boost_json>(jwtElem.String());
        auto decoded = jwt::decode(jwtElem.String());
        auto subStr = decoded.get_payload_claim("sub").as_string();
        LOGV2(77012, "OIDC step 2 sub", "sub"_attr = subStr);
    } catch (const std::invalid_argument& e) {  // can be thrown by `jwt::decode`
        return Status(ErrorCodes::BadValue, str::stream() << "Invalid JWT: incorrect format: " << e.what());
    } catch  (const std::runtime_error& e) {  // can be thrown by `jwt::decode`
        return Status(ErrorCodes::BadValue, str::stream() << "Invalid JWT: base64 decoding failed or invalid json: " << e.what());
    }
    return std::tuple(true, std::string());
}

namespace {
GlobalSASLMechanismRegisterer<OidcServerFactory> oidcRegisterer;
}  // namespace
}  // namespace mongo
