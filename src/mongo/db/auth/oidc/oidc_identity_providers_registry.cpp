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

#include "mongo/db/auth/oidc/oidc_identity_providers_registry.h"

#include <memory>

#include "mongo/crypto/jwks_fetcher_impl.h"
#include "mongo/db/auth/oidc/oidc_identity_providers_registry_impl.h"
#include "mongo/db/service_context.h"
#include "mongo/util/assert_util_core.h"
#include "mongo/util/system_clock_source.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kDefault

namespace mongo {

namespace {
// Decoration for the OIDC identity providers registry in the service context.
const auto getOidcIdentityProvidersRegistry =
    ServiceContext::declareDecoration<std::unique_ptr<OidcIdentityProvidersRegistry>>();

// Returns the list of OIDC identity provider configurations from the server parameters.
const std::vector<OidcIdentityProviderConfig>& getIdPConfigs() {
    return ServerParameterSet::getNodeParameterSet()
        ->get<OidcIdentityProvidersServerParameter>("oidcIdentityProviders")
        ->_data;
}

struct JWKSFetcherFactoryImpl : public JWKSFetcherFactory {
    std::unique_ptr<crypto::JWKSFetcher> makeJWKSFetcher(StringData issuer) const override {
        return std::make_unique<crypto::JWKSFetcherImpl>(SystemClockSource::get(), issuer);
    }
};
}  // namespace


// Instantiates the registry and registers it with the service context.
void initializeOidcIdentityProvidersRegistry(ServiceContext* serviceContext) {
    invariant(serviceContext->getPeriodicRunner());

    JWKSFetcherFactoryImpl jwksFetcherFactory;
    OidcIdentityProvidersRegistry::set(
        serviceContext,
        std::make_unique<OidcIdentityProvidersRegistryImpl>(
            serviceContext->getPeriodicRunner(), jwksFetcherFactory, getIdPConfigs()));
}

OidcIdentityProvidersRegistry& OidcIdentityProvidersRegistry::get(ServiceContext* serviceContext) {
    auto& uptr = getOidcIdentityProvidersRegistry(serviceContext);
    invariant(uptr);
    return *uptr;
}

void OidcIdentityProvidersRegistry::set(ServiceContext* serviceContext,
                                        std::unique_ptr<OidcIdentityProvidersRegistry> registry) {
    getOidcIdentityProvidersRegistry(serviceContext) = std::move(registry);
}

}  // namespace mongo
