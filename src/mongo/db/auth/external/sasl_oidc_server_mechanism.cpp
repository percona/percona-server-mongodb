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

#include "mongo/db/auth/external/sasl_oidc_server_mechanism.h"

#include <fmt/format.h>

#define JWT_DISABLE_PICOJSON
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/boost-json/traits.h>
#include <jwt-cpp/traits/boost-json/defaults.h>
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/auth/oidc/oidc_server_parameters_gen.h"
#include "mongo/db/auth/oidc_protocol_gen.h"
#include "mongo/db/auth/sasl_mechanism_registry.h"
#include "mongo/db/auth/sasl_plain_server_conversation.h"
#include "mongo/db/server_parameter.h"
#include "mongo/logv2/log.h"
#include "mongo/logv2/log_attr.h"
#include "mongo/logv2/log_component.h"
#include "mongo/util/assert_util.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kAccessControl

namespace mongo {
namespace {
const std::vector<OidcIdentityProviderConfig>& getIdPConfigs() {
    return ServerParameterSet::getNodeParameterSet()
            ->get<OidcIdentityProvidersServerParameter>("oidcIdentityProviders")
            ->_data;
}
}
StatusWith<std::tuple<bool, std::string>> SaslOidcServerMechanism::stepImpl(OperationContext*,
                                                                            StringData input) {
    if (Status s{validateBSON(input.data(), input.size())}; !s.isOK()) {
        return s;
    }
    BSONObj inputBson{input.data()};
    // Both `OIDCMechanismClientStep1` and `OIDCMechanismClientStep2` are
    // parsed in the non-strict mode, meaning unknown fields are allowed and
    // ignored (@see the `src/mongo/db/auth/oidc_protocol.idl` file).
    // Since `OIDCMechanismClientStep1` has only one optional field `n`,
    // non-strict parsing results in _any_ valid BSON object (including BSON
    // representation of `OIDCMechanismClientStep2`) being successfully
    // parsed into the `OIDCMechanismClientStep1` object, with or without the
    // `n` field. To avoid confusion, we first try to read the input as a
    // `OIDCMechanismClientStep2` object, which is not subject to the just
    // described issue because its only `jwt` field is mandatory.
    try {
        return step2(
            auth::OIDCMechanismClientStep2::parse(IDLParserContext("OIDCStep2Request"), inputBson));
    } catch (const DBException& e) {
        // Failed to parse the input as a step 2 request. It still can be
        // a step 1 request, so suppress the exception.
    }
    try {
        return step1(
            auth::OIDCMechanismClientStep1::parse(IDLParserContext("OIDCStep1Request"), inputBson));
    } catch (const DBException& e) {
        return e.toStatus();
    }
    MONGO_UNREACHABLE;
}

StatusWith<std::tuple<bool, std::string>> SaslOidcServerMechanism::step1(
    const auth::OIDCMechanismClientStep1& request) {
    _step = 1;
    const std::vector<OidcIdentityProviderConfig>& allIdPs{getIdPConfigs()};
    // `hfIdPs` stands for configurations of the identity providers that support human flows.
    // The correctness of the code below stems from the fact that server parameters validation
    // (@see the `src/mongo/db/auth/oidc/oidc_server_parameters.cpp` file) ensures that the
    // configurations of all identity providers that support human flows are listed _before_ those
    // without such support.
    std::ranges::subrange hfIdPs{allIdPs.begin(),
                                 std::ranges::find_if_not(allIdPs, [](const auto& conf) {
                                     return conf.getSupportsHumanFlows();
                                 })};
    if (hfIdPs.empty()) {
        Status{ErrorCodes::BadValue, "None of configured identity providers support human flows"};
    }
    boost::optional<StringData> principalName{request.getPrincipalName()};
    LOGV2(77012, "OIDC step 1", "principalName"_attr = principalName ? *principalName : "none");
    if (!principalName && hfIdPs.size() > 1) {
        Status{
            ErrorCodes::BadValue,
            "Multiple identity providers are known, provide a principal name for choosing a one"};
    }
    for (const auto& idp : hfIdPs) {
        if (const boost::optional<mongo::MatchPattern>& pattern{idp.getMatchPattern()};
            !principalName || !pattern ||
            std::regex_search(principalName->begin(), principalName->end(), pattern->toRegex())) {
            auth::OIDCMechanismServerStep1 response;
            response.setIssuer(idp.getIssuer());
            // Server parameters validation
            // (@see the `src/mongo/db/auth/oidc/oidc_server_parameters.cpp` file) ensures that
            // a client ID exists for the identity providers supporting human flows.
            response.setClientId(*idp.getClientId());
            BSONObj b{response.toBSON()};
            return std::tuple{false, std::string{b.objdata(), static_cast<std::size_t>(b.objsize())}};
        }
    }
    return Status{
        ErrorCodes::BadValue,
        fmt::format("No identity provider found matching principal name `{}`", *principalName)};
}

StatusWith<std::tuple<bool, std::string>> SaslOidcServerMechanism::step2(
    const auth::OIDCMechanismClientStep2& request) try {
    _step = 2;
    const std::vector<OidcIdentityProviderConfig>& allIdPs{getIdPConfigs()};
    auto token{jwt::decode(std::string{request.getJWT()})};
    std::string issuer{token.get_issuer()};
    std::set<std::string> audience{token.get_audience()};
    uassert(ErrorCodes::BadValue, "Invalid JWT: `audience` is an empty set", !audience.empty());

    auto idp{std::ranges::find_if(allIdPs, [&](const auto& idp) {
        return std::string_view{idp.getIssuer()} == issuer &&
            audience.contains(std::string{idp.getAudience()});
    })};
    uassert(
        ErrorCodes::BadValue, "Invalid JWT: Unsupported issuer or audience", idp != allIdPs.end());

    std::string authNamePrefix{idp->getAuthNamePrefix()};
    _principalName = authNamePrefix + "/" +
        token.get_payload_claim(std::string{idp->getPrincipalName()}).as_string();

    if (idp->getUseAuthorizationClaim()) {
        _roles.emplace();
        jwt::claim authClaim{token.get_payload_claim(std::string{*idp->getAuthorizationClaim()})};
        auto addRole = [&roles = this->_roles, &authNamePrefix](const std::string& claim) {
            roles->emplace(authNamePrefix + "/" + claim, "admin");
        };
        switch (authClaim.get_type()) {
            case jwt::json::type::string:
                addRole(authClaim.as_string());
                break;
            case jwt::json::type::array:
                for (const auto& c : authClaim.as_array()) {
                    // @todo improve the `jwt-cpp` library so that an array
                    // element can be converted to a C++ scalar data type
                    // in a json-library-agnostic way
                    addRole(jwt::traits::boost_json::as_string(c));
                }
                break;
            default:
                return Status{
                    ErrorCodes::BadValue,
                    fmt::format("Invalid JWT: `{}` is neither a string nor an array of strings",
                                OidcIdentityProviderConfig::kAuthorizationClaimFieldName)};
        }
    }

    LOGV2(77012, "OIDC step 2", "principalName"_attr = _principalName, "roles"_attr = _roles);

    // authentication succeeded
    return std::tuple{true, std::string{}};
    // // authentication failed
    // return Status{ErrorCodes::AuthenticationFailed, "auth failed"};
} catch (const std::bad_cast& e) {
    // @todo: improve the `jwt-cp` library so that it provides the name of the bad-typed claim
    return Status{ErrorCodes::BadValue, "Invalid JWT: Some claim has a wrong type"};
} catch (const jwt::error::claim_not_present_exception& e) {
    // @todo: improve the `jwt-cp` library so that it provides the name of the missing claim
    return Status{ErrorCodes::BadValue, "Invalid JWT: Some claims are missing"};
} catch (const std::invalid_argument& e) {  // can be thrown by `jwt::decode`
    return Status{ErrorCodes::BadValue, fmt::format("Invalid JWT: incorrect format: {}", e.what())};
} catch (const DBException& e) {
    return e.toStatus();
} catch (const std::runtime_error& e) {  // can be thrown by `jwt::decode`
    return Status{ErrorCodes::BadValue,
                  fmt::format("Invalid JWT: base64 decoding failed or invalid JSON: {}", e.what())};
}

UserRequest SaslOidcServerMechanism::getUserRequest() const {
    return UserRequest{UserName{getPrincipalName(), getAuthenticationDatabase()}, _roles};
}

namespace {
GlobalSASLMechanismRegisterer<OidcServerFactory> oidcRegisterer;
}  // namespace
}  // namespace mongo
