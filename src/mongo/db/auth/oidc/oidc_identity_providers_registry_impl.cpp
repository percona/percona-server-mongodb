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

#include "mongo/db/auth/oidc/oidc_identity_providers_registry_impl.h"

#include <memory>
#include <unordered_set>

#include "mongo/db/service_context.h"
#include "mongo/logv2/log.h"
#include "mongo/util/assert_util_core.h"
#include "mongo/util/periodic_runner.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kDefault

namespace mongo {

// `_hfidps` stands for configurations of the identity providers that support human flows.
// The correctness of the code below (see initialization list) stems from the fact that server
// parameters validation (@see the `src/mongo/db/auth/oidc/oidc_server_parameters.cpp` file) ensures
// that the configurations of all identity providers that support human flows are listed _before_
// those without such support.
OidcIdentityProvidersRegistryImpl::OidcIdentityProvidersRegistryImpl(
    PeriodicRunner* periodicRunner,
    const JWKSFetcherFactory& jwksFetcherFactory,
    const std::vector<OidcIdentityProviderConfig>& configs)
    : _idps(configs), _hfidps{_idps.begin(), std::ranges::find_if_not(_idps, [](const auto& idp) {
                                  return idp.getSupportsHumanFlows();
                              })} {
    invariant(periodicRunner);

    for (const auto& idp : _idps) {
        // create a JWKManager instance for each issuer
        auto res = _jwkManagers.try_emplace(
            idp.getIssuer().toString(),
            std::make_shared<crypto::JWKManager>(
                jwksFetcherFactory.makeJWKSFetcher(idp.getIssuer(), idp.getServerCAFile())));

        // Skip the periodic job creation if the issuer is already present in the map.
        if (!res.second) {
            continue;
        }

        auto loadKeys = [issuer = res.first->first, jwkManager = res.first->second](Client*) {
            Status status = jwkManager->loadKeys();
            if (!status.isOK()) {
                LOGV2_WARNING(29140,
                              "Failed to load JWKs from issuer",
                              "issuer"_attr = issuer,
                              "error"_attr = status);
            }
        };

        // If JWKSPollSecs is not configured, skip the periodic job creation but load the keys once.
        if (idp.getJWKSPollSecs() <= 0) {
            loadKeys(nullptr);
            continue;
        }

        // Create and start a periodic job which polls the JWKs from the issuer.
        const auto period = Milliseconds{Seconds(idp.getJWKSPollSecs())};

        _jobs.emplace_back(periodicRunner->makeJob(
            PeriodicRunner::PeriodicJob(fmt::format("JWKSPollJob[{}]", idp.getIssuer()),
                                        std::move(loadKeys),
                                        period,
                                        /* isKillableByStepdown = */ false)));
        _jobs.back().start();
    }
}

boost::optional<const OidcIdentityProviderConfig&> OidcIdentityProvidersRegistryImpl::getIdp(
    const std::string& issuer, const std::vector<std::string>& audience) const {

    // Iterate over the identity providers and check if the issuer matches the identity provider's
    // configuration and if the audience is in the list of given audiences.
    std::unordered_set<std::string_view> audienceSet{audience.begin(), audience.end()};
    auto idp{std::ranges::find_if(_idps, [&](const auto& idp) {
        return std::string_view{idp.getIssuer()} == issuer &&
            audienceSet.contains(std::string_view{idp.getAudience()});
    })};

    if (idp != _idps.end()) {
        return *idp;
    }
    return boost::none;
}

boost::optional<const OidcIdentityProviderConfig&>
OidcIdentityProvidersRegistryImpl::getIdpForPrincipalName(
    boost::optional<std::string_view> principalName) const {

    // Iterate over the identity providers that support human flows and check if
    // the principal name matches the match pattern of the identity provider.
    // If the principal name is not provided, return the first identity provider
    // that supports human flows.
    // If the principal name is provided, return the first identity provider
    // that matches the principal name, or the first identity provider that
    // has no match pattern. The server parameters validation ensures that
    // the identity providers without match pattern are listed after those
    // with match pattern.
    // (@see the `src/mongo/db/auth/oidc/oidc_server_parameters.cpp` file for details)
    for (const auto& idp : _hfidps) {
        if (const boost::optional<mongo::MatchPattern>& pattern{idp.getMatchPattern()};
            !principalName || !pattern ||
            std::regex_search(principalName->begin(), principalName->end(), pattern->toRegex())) {

            return idp;
        }
    }

    return boost::none;
}

// This method is thread-safe because '_jwkManagers' is fully initialized
// in the constructor and never modified afterward (read-only access).
std::shared_ptr<crypto::JWKManager> OidcIdentityProvidersRegistryImpl::getJWKManager(
    const std::string& issuer) const {

    if (auto it = _jwkManagers.find(issuer); it != _jwkManagers.end()) {
        return it->second;
    }

    return {};
}

void OidcIdentityProvidersRegistryImpl::visitJWKManagers(JWKManagerVisitor visitor) const {
    invariant(visitor);

    for (const auto& [issuer, manager] : _jwkManagers) {
        visitor(issuer, manager);
    }
}

}  // namespace mongo
