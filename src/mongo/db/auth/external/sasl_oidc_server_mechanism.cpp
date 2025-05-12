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

#include "mongo/bson/bsonobj.h"
#include "mongo/crypto/jws_validated_token.h"
#include "mongo/db/auth/oidc/oidc_identity_providers_registry.h"
#include "mongo/db/auth/oidc/oidc_server_parameters_gen.h"
#include "mongo/db/auth/oidc_protocol_gen.h"
#include "mongo/db/auth/sasl_mechanism_registry.h"
#include "mongo/db/server_parameter.h"
#include "mongo/logv2/log.h"
#include "mongo/logv2/log_attr.h"
#include "mongo/util/assert_util.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kAccessControl

namespace mongo {

StatusWith<std::tuple<bool, std::string>> SaslOidcServerMechanism::stepImpl(OperationContext* opCtx,
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
            opCtx->getServiceContext(),
            auth::OIDCMechanismClientStep2::parse(IDLParserContext("OIDCStep2Request"), inputBson));
    } catch (const DBException& e) {
        // Failed to parse the input as a step 2 request. Suppress the exception
        // if it still can be a step 1 request. Otherwise, return an error.
        // _step == 1 means the step 1 request was already processed.
        if (_step == 1) {
            return e.toStatus();
        }
    }
    try {
        return step1(
            opCtx->getServiceContext(),
            auth::OIDCMechanismClientStep1::parse(IDLParserContext("OIDCStep1Request"), inputBson));
    } catch (const DBException& e) {
        return e.toStatus();
    }
    MONGO_UNREACHABLE;
}

StatusWith<std::tuple<bool, std::string>> SaslOidcServerMechanism::step1(
    ServiceContext* serviceContext, const auth::OIDCMechanismClientStep1& request) {
    _step = 1;

    const auto& oidcIdPRegistry = OidcIdentityProvidersRegistry::get(serviceContext);

    // Check if there is any IdP with 'supportsHumanFlows'. If not, cannot proceed with step1.
    if (!oidcIdPRegistry.hasIdpWithHumanFlowsSupport()) {
        return Status{ErrorCodes::BadValue,
                      "None of configured identity providers support human flows"};
    }

    auto principalName =
        request.getPrincipalName().map([](const auto& str) -> std::string_view { return std::string_view{str}; });

    LOGV2(77012, "OIDC step 1", "principalName"_attr = principalName.value_or("none"));

    // If there are more than one IdP with human flows support, the client must provide a principal
    // name to choose a specific IdP. If there is only one IdP with human flows support, the client
    // can omit the principal name and the server will choose the only IdP available.
    if (!principalName && oidcIdPRegistry.numOfIdpsWithHumanFlowsSupport() > 1) {
        return Status{
            ErrorCodes::BadValue,
            "Multiple identity providers are known, provide a principal name for choosing a one"};
    }

    // Choose the IdP configuration for a given principal name.
    auto idp = oidcIdPRegistry.getIdpForPrincipalName(principalName);
    if (!idp.has_value()) {
        return Status{
            ErrorCodes::BadValue,
            fmt::format("No identity provider found for principal name `{}`", *principalName)};
    }

    // Reply with the 'issuer' and 'clientId' fields of the chosen IdP.
    auth::OIDCMechanismServerStep1 response;
    response.setIssuer(idp->getIssuer());

    // Server parameters validation
    // (@see the `src/mongo/db/auth/oidc/oidc_server_parameters.cpp` file) ensures that
    // a client ID exists for the identity providers supporting human flows.
    invariant(idp->getClientId().has_value());
    response.setClientId(*idp->getClientId());

    // add optional 'requestScopes' field to the response
    response.setRequestScopes(idp->getRequestScopes());

    BSONObj b{response.toBSON()};
    return std::tuple{false, std::string{b.objdata(), static_cast<std::size_t>(b.objsize())}};
}

StatusWith<std::tuple<bool, std::string>> SaslOidcServerMechanism::step2(
    ServiceContext* serviceContext, const auth::OIDCMechanismClientStep2& request) try {
    _step = 2;

    const auto& oidcIdPRegistry = OidcIdentityProvidersRegistry::get(serviceContext);

    // Parse the JWT and check for required claims, such as 'iss', 'aud', 'sub' and 'exp'.
    // Extract the issuer and audience claims which are essential for further processing of the
    // token.
    const auto issuerAudienceStatus =
        crypto::JWSValidatedToken::extractIssuerAndAudienceFromCompactSerialization(
            request.getJWT());
    uassert(ErrorCodes::BadValue,
            fmt::format("parsing failed: {}", issuerAudienceStatus.getStatus().reason()),
            issuerAudienceStatus.isOK());

    const auto& issuer = issuerAudienceStatus.getValue().issuer;
    const auto& audience = issuerAudienceStatus.getValue().audience;

    // Get the IdP configuration for a issuer/audience pair from the token
    auto idp = oidcIdPRegistry.getIdp(issuer, audience);
    uassert(ErrorCodes::BadValue, "unsupported issuer or audience", idp.has_value());

    // Get the JWKManager for a given issuer for token validation.
    auto jwkManager = oidcIdPRegistry.getJWKManager(issuer);
    invariant(jwkManager);  // if the issuer is valid, the JWKManager for the issuer must exist

    // Validate the token's signature, as well as 'exp' and 'nbf' claims.
    const crypto::JWSValidatedToken token{jwkManager.get(), std::string{request.getJWT()}};

    const auto principalNameField = token.getBodyBSON().getField(idp->getPrincipalName());
    // Check if the configured claim for principalName exists and is a string.
    uassert(ErrorCodes::BadValue,
            fmt::format("{} '{}' claim is missing",
                        OidcIdentityProviderConfig::kPrincipalNameFieldName,
                        idp->getPrincipalName()),
            principalNameField.ok());

    uassert(ErrorCodes::BadValue,
            fmt::format("{} '{}' claim format is not string",
                        OidcIdentityProviderConfig::kPrincipalNameFieldName,
                        idp->getPrincipalName()),
            principalNameField.type() == BSONType::String);

    std::string authNamePrefix{idp->getAuthNamePrefix()};

    // Store _principalName to return it in UserRequest for authorization manager.
    _principalName = authNamePrefix + "/" + principalNameField.String();

    // Store _expirationTime for authorization manager.
    _expirationTime = token.getBody().getExpiration();

    processAuthorizationClaim(*idp, token);

    LOGV2(77012, "OIDC step 2", "principalName"_attr = _principalName, "roles"_attr = _roles);

    // authentication succeeded
    return std::tuple{true, std::string{}};
} catch (const DBException& e) {
    return e.toStatus().withContext("Invalid JWT");
}

void SaslOidcServerMechanism::processAuthorizationClaim(const OidcIdentityProviderConfig& idp,
                                                        const crypto::JWSValidatedToken& token) {
    if (!idp.getUseAuthorizationClaim()) {
        return;
    }
    // Check if configured authorization claim exists, is of correct format and
    // store the roles.
    // The server parameters validation ensures the 'authorizationClaim' fields is
    // present if the 'useAuthorizationClaim=true'
    // (@see the `src/mongo/db/auth/oidc/oidc_server_parameters.cpp` file).
    invariant(idp.getAuthorizationClaim().has_value());
    std::string authorizationClaim{*idp.getAuthorizationClaim()};

    const auto authClaim = token.getBodyBSON().getField(authorizationClaim);

    uassert(ErrorCodes::BadValue,
            fmt::format("{} '{}' is missing",
                        OidcIdentityProviderConfig::kAuthorizationClaimFieldName,
                        *idp.getAuthorizationClaim()),
                        authClaim.ok());

    // The '_roles' is an optional set. Constructing an empty set if 'useAuthorizationClaim'
    // is true is essential to distinguish between 'useAuthorizationClaim=false' and
    // 'useAuthorizationClaim=true' when the claim has no roles. This makes a difference
    // in processing the UserRequest by the authorization manager.
    _roles.emplace();

    std::string authNamePrefix{idp.getAuthNamePrefix()};

    auto addRole = [&roles = this->_roles, &authNamePrefix](const std::string& claim) {
        roles->emplace(authNamePrefix + "/" + claim, "admin");
    };

    switch (authClaim.type()) {
        case BSONType::String:
            addRole(authClaim.String());
            break;
        case BSONType::Array:
            for (const auto& c : authClaim.Array()) {
                uassert(ErrorCodes::BadValue,
                        fmt::format("{} '{}' value is not a string",
                                    OidcIdentityProviderConfig::kAuthorizationClaimFieldName,
                                    authorizationClaim),
                        c.type() == BSONType::String);
                addRole(c.String());
            }
            break;
        default:
            uasserted(ErrorCodes::BadValue,
                      fmt::format("{} `{}` is neither a string nor an array of strings",
                                  OidcIdentityProviderConfig::kAuthorizationClaimFieldName,
                                  authorizationClaim));
    }
}

StatusWith<std::unique_ptr<UserRequest>> SaslOidcServerMechanism::makeUserRequest(OperationContext*) const  {
    return std::make_unique<UserRequestGeneral>(
        UserName{getPrincipalName(), getAuthenticationDatabase()}, _roles);
}

boost::optional<Date_t> SaslOidcServerMechanism::getExpirationTime() const {
    return _expirationTime;
}

namespace {
GlobalSASLMechanismRegisterer<OidcServerFactory> oidcRegisterer;
}  // namespace
}  // namespace mongo
