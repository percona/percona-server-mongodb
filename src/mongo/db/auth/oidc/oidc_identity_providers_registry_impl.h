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
#include <ranges>
#include <unordered_map>

#include "mongo/crypto/jwk_manager.h"
#include "mongo/crypto/jwks_fetcher_factory.h"
#include "mongo/db/auth/oidc/oidc_identity_providers_registry.h"
#include "mongo/db/auth/oidc/oidc_server_parameters_gen.h"
#include "mongo/util/periodic_runner.h"

namespace mongo {

/**
 * Holds and manages all configured OIDC identity providers, along with associated
 * JWK managers and periodic tasks.
 *
 * This registry is constructed once during server initialization and remains
 * immutable for the lifetime of the ServiceContext. The identity provider
 * configurations, associated JWK managers, and periodic jobs are fixed at
 * construction time and not meant to be modified at runtime.
 *
 * If support for dynamic updates or reloads is required in the future,
 * appropriate synchronization must be implemented to ensure thread safety.
 */
class OidcIdentityProvidersRegistryImpl final : public OidcIdentityProvidersRegistry {
public:
    /**
     * Constructs the OidcIdentityProvidersRegistryImpl with a const lvalue reference to the given
     * configuration list.
     *
     * The registry does not take ownership of the configuration vector and assumes it remains valid
     * for the entire lifetime of the registry instance. The caller must ensure that the passed-in
     * vector is not a temporary and that it outlives the registry.
     *
     * Binding a temporary (e.g., via `{}` or `std::vector<...>{}`) to this constructor will compile
     * but results in undefined behavior due to a dangling reference.
     */
    explicit OidcIdentityProvidersRegistryImpl(
        PeriodicRunner* periodicRunner,
        const JWKSFetcherFactory& jwksFetcherFactory,
        const std::vector<OidcIdentityProviderConfig>& configs);

    boost::optional<const OidcIdentityProviderConfig&> getIdp(
        const std::string& issuer, const std::vector<std::string>& audience) const override;

    boost::optional<const OidcIdentityProviderConfig&> getIdpForPrincipalName(
        boost::optional<std::string_view> principalName) const override;

    bool hasIdpWithHumanFlowsSupport() const override {
        return !_hfidps.empty();
    }

    size_t numOfIdpsWithHumanFlowsSupport() const override {
        return _hfidps.size();
    }

    std::shared_ptr<crypto::JWKManager> getJWKManager(const std::string& issuer) const override;

private:
    // All configured identity providers.
    const std::vector<OidcIdentityProviderConfig>& _idps;

    // Subset of identity providers that support human login flows.
    std::ranges::subrange<decltype(_idps.begin())> _hfidps;

    // JWK managers per issuer.
    std::unordered_map<std::string, std::shared_ptr<crypto::JWKManager>> _jwkManagers;

    // Anchors for periodic background jobs per identity provider.
    std::vector<PeriodicJobAnchor> _jobs;
};

}  // namespace mongo
