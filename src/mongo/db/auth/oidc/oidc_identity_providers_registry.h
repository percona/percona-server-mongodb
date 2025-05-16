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

#pragma once

#include <boost/optional.hpp>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "mongo/crypto/jwk_manager.h"
#include "mongo/db/auth/oidc/oidc_server_parameters_gen.h"
#include "mongo/db/service_context.h"

namespace mongo {

// Constructs and registers the OIDC identity providers registry in the given ServiceContext.
void initializeOidcIdentityProvidersRegistry(ServiceContext* serviceContext);

class OidcIdentityProvidersRegistry {
public:
    // Returns the registry instance from service context decoration.
    static OidcIdentityProvidersRegistry& get(ServiceContext* serviceContext);

    // Sets the registry instance in service context decoration.
    static void set(ServiceContext* serviceContext,
                    std::unique_ptr<OidcIdentityProvidersRegistry> registry);

    virtual ~OidcIdentityProvidersRegistry() = default;

    // Returns the OIDC identity provider configuration for the given issuer and audience.
    virtual boost::optional<const OidcIdentityProviderConfig&> getIdp(
        const std::string& issuer, const std::vector<std::string>& audience) const = 0;

    // Returns the identity provider configuration associated with the given principal name,
    // or boost::none if no match is found.
    virtual boost::optional<const OidcIdentityProviderConfig&> getIdpForPrincipalName(
        boost::optional<std::string_view> principalName) const = 0;

    // Returns true if there is at least one identity provider with human flows support.
    virtual bool hasIdpWithHumanFlowsSupport() const = 0;

    // Returns the number of identity providers with human flows support.
    virtual size_t numOfIdpsWithHumanFlowsSupport() const = 0;

    // Returns a JWKManager instance for a given issuer.
    virtual std::shared_ptr<crypto::JWKManager> getJWKManager(const std::string& issuer) const = 0;

    using JWKManagerVisitor =
        std::function<void(const std::string& issuer, std::shared_ptr<crypto::JWKManager> manager)>;

    // Visits all JWK managers in the registry and applies the visitor function to each.
    virtual void visitJWKManagers(JWKManagerVisitor visitor) const = 0;
};

}  // namespace mongo
