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

#include <type_traits>

#include "mongo/crypto/jwks_fetcher_factory.h"
#include "mongo/db/auth/oidc/match_pattern.h"
#include "mongo/db/auth/oidc/oidc_identity_providers_registry.h"
#include "mongo/db/auth/oidc/oidc_server_parameters_gen.h"
#include "mongo/unittest/assert.h"
#include "mongo/util/base64.h"
#include "mongo/util/periodic_runner.h"
#include "mongo/stdx/unordered_set.h"

namespace mongo {

static inline bool operator==(const MatchPattern& lhs, const MatchPattern& rhs) {
    return lhs.toString() == rhs.toString();
}

// comparator for OidcIdentityProviderConfig objects required by ASSERT_EQ and similar macros
static inline bool operator==(const OidcIdentityProviderConfig& lhs,
                              const OidcIdentityProviderConfig& rhs) {
    return lhs.getIssuer() == rhs.getIssuer() && lhs.getAudience() == rhs.getAudience() &&
        lhs.getAuthNamePrefix() == rhs.getAuthNamePrefix() &&
        lhs.getSupportsHumanFlows() == rhs.getSupportsHumanFlows() &&
        lhs.getJWKSPollSecs() == rhs.getJWKSPollSecs() && lhs.getClientId() == rhs.getClientId() &&
        lhs.getRequestScopes() == rhs.getRequestScopes() &&
        lhs.getPrincipalName() == rhs.getPrincipalName() &&
        lhs.getUseAuthorizationClaim() == rhs.getUseAuthorizationClaim() &&
        lhs.getAuthorizationClaim() == rhs.getAuthorizationClaim() &&
        lhs.getLogClaims() == rhs.getLogClaims() && lhs.getMatchPattern() == rhs.getMatchPattern();
}

// Base class for OidcIdentityProviderConfig's field setters
class SetField {
public:
    virtual void set(OidcIdentityProviderConfig& config) = 0;
};

// Helper class for storing a value
template <typename T>
class SetFieldWithValue : public SetField {
public:
    explicit SetFieldWithValue(const T& value) : _value(value) {}

    const T& getValue() const {
        return _value;
    }

private:
    T _value;
};

// Setter for the 'matchPattern' field
struct SetMatchPattern : public SetFieldWithValue<std::string> {
    using SetFieldWithValue::SetFieldWithValue;

    void set(OidcIdentityProviderConfig& config) override {
        config.setMatchPattern(MatchPattern(getValue()));
    }
};

// Setter for the 'supportsHumanFlows' field
struct SetSupportsHumanFlows : public SetFieldWithValue<bool> {
    using SetFieldWithValue::SetFieldWithValue;

    void set(OidcIdentityProviderConfig& config) override {
        config.setSupportsHumanFlows(getValue());
    }
};

// Setter for the 'clientId' field
struct SetClientId : public SetFieldWithValue<std::string> {
    using SetFieldWithValue::SetFieldWithValue;

    void set(OidcIdentityProviderConfig& config) override {
        config.setClientId(StringData{getValue()});
    }
};

// Setter for the 'requestScopes' field
struct SetRequestScopes : public SetFieldWithValue<std::vector<std::string>> {
    using SetFieldWithValue::SetFieldWithValue;

    void set(OidcIdentityProviderConfig& config) override {
        std::vector<StringData> scopes;
        for (const auto& scope : getValue()) {
            scopes.emplace_back(scope);
        }
        config.setRequestScopes(scopes);
    }
};

// Setter for the 'JWKSPollSecs' field
struct SetJWKSPollSecs : public SetFieldWithValue<std::int32_t> {
    using SetFieldWithValue::SetFieldWithValue;

    void set(OidcIdentityProviderConfig& config) override {
        config.setJWKSPollSecs(getValue());
    }
};

// Creates an OidcIdentityProviderConfig object with the given required parameters
// and a list of optional field setters.
template <typename... Setters>
OidcIdentityProviderConfig create_config(const std::string& issuer,
                                         const std::string& authNamePrefix,
                                         const std::string& audience,
                                         Setters&&... setters) {
    static_assert((std::conjunction_v<std::is_base_of<SetField, std::decay_t<Setters>>...>),
                  "All setters must inherit from SetField");

    OidcIdentityProviderConfig config;
    config.setIssuer(issuer);
    config.setAuthNamePrefix(authNamePrefix);
    config.setAudience(audience);
    (setters.set(config), ...);
    return config;
}

// Mock for PeriodicRunner to control the job execution
// and to verify the job's state.
class PeriodicRunnerMock : public PeriodicRunner {
    class ControllableJobMock : public ControllableJob {
    public:
        explicit ControllableJobMock(PeriodicJob job) : _job(std::move(job)) {}
        void start() override {
            _started = true;
        }

        void pause() override {
            FAIL("pause() should not be called");
        }

        void resume() override {
            FAIL("resume() should not be called");
        }

        void stop() override {}

        Milliseconds getPeriod() const override {
            return _job.interval;
        }

        void setPeriod(Milliseconds ms) override {
            _job.interval = ms;
        }

        bool isStarted() const {
            return _started;
        }

        const std::string& name() const {
            return _job.name;
        }

    private:
        bool _started{false};
        PeriodicJob _job;
    };

public:
    PeriodicJobAnchor makeJob(PeriodicJob job) override {
        auto handle = std::make_shared<ControllableJobMock>(std::move(job));
        jobs.push_back(handle);
        return PeriodicJobAnchor{std::move(handle)};
    }

    bool allJobsHaveUniqueName() const {
        stdx::unordered_set<std::string> seen;
        for (const auto& job : jobs) {
            if (!seen.insert(job->name()).second) {
                return false;
            }
        }

        return true;
    }

    std::vector<std::shared_ptr<ControllableJobMock>> jobs;
};

// Creates a sample JWK with a given key ID (kid).
static inline BSONObj create_sample_jwk(const std::string& kid) {
    return BSON(
        "kty"
        << "RSA" << "kid" << kid << "e" << base64::encode(std::string("65537")) << "n"
        << base64::encode(std::string(
               "24103124269210325885589492824329390770718048842168962142231806759547199905121107605"
               "94374886945827242453049450562107993185150418939783092681992163632632151290783209654"
               "18352230527943678763421101519594031950994252594389212214899872192091788056182811967"
               "98430939959680125750299795475602936974900217121106342268992483243889312696878385819"
               "55673392694663071593917788291781797603817782254090438948798595932561632632291887171"
               "57520716800700827203965474651739259123217596332452187685582796501283479422535631481"
               "92541841520336257387940200105140554416886948992349899007018225316628212425389348153"
               "057853174003469420324123940820893803")));
}

// Mock for JWKSFetcherFactory to control the creation of JWKSFetcher instances.
// The makeJWKSFetcher returns an unique_ptr to a JWKSFetcher instance so it's
// not safe to keep a reference/pointer to it after the call. That is why the
// JWKSFetcheMock takes a reference to the JWKSFetcherFactoryMock instance and redirects
// all calls to the fetch method to the factory mock. This allows us to control the returned value
// without having to keep a reference to the JWKSFetcher instance.
struct JWKSFetcherFactoryMock : public JWKSFetcherFactory {
    class JWKSFetcherMock : public crypto::JWKSFetcher {
    public:
        explicit JWKSFetcherMock(const JWKSFetcherFactoryMock& factoryMock, std::string issuer)
            : _factoryMock(factoryMock), _issuer(issuer) {}

        crypto::JWKSet fetch() override {

            return _factoryMock.fetch(_issuer);
        }

        void setQuiesce(Date_t quiesce) override {
            FAIL("setQuiesce() should not be called");
        }

    private:
        const JWKSFetcherFactoryMock& _factoryMock;
        std::string _issuer;
    };

public:
    std::unique_ptr<crypto::JWKSFetcher> makeJWKSFetcher(StringData issuer,
                                                         StringData caFilePath) const override {
        (void)caFilePath;
        _issuers.emplace_back(issuer);
        return std::make_unique<JWKSFetcherMock>(*this, std::string{issuer});
    }
    std::unique_ptr<crypto::JWKSFetcher> makeJWKSFetcher(StringData issuer) const {
        return makeJWKSFetcher(issuer, {});
    }

    // Mocked fetch method to return a JWKSet for the given issuer
    crypto::JWKSet fetch(const std::string& issuer) const {
        // this will throw an exception which should be caught by the JWKManager.
        uassert(ErrorCodes::KeyNotFound,
                str::stream() << "No JWK for issuer " << issuer,
                _jwkSets.contains(issuer));

        auto& jwkPair = _jwkSets.at(issuer);
        jwkPair.second++;
        return jwkPair.first;
    }

    std::size_t getFetchCount(const std::string& issuer) const {
        uassert(ErrorCodes::KeyNotFound,
                str::stream() << "No JWK for issuer " << issuer,
                _jwkSets.contains(issuer));

        return _jwkSets.at(issuer).second;
    }

    // Sets the JWKSet for the given issuer to be returned by the fetch method
    void setJWKSet(const std::string& issuer, const crypto::JWKSet& jwkSet) {
        _jwkSets[issuer] = std::make_pair(jwkSet, 0);
    }

    // Returns true if a fetcher was created for the given issuer
    bool createdForIssuer(const std::string& issuer) const {
        return std::find(_issuers.begin(), _issuers.end(), issuer) != _issuers.end();
    }

    // Returns the number of created fetchers
    std::size_t count() const {
        return _issuers.size();
    }

private:
    mutable std::vector<std::string> _issuers;
    mutable std::unordered_map<std::string, std::pair<crypto::JWKSet, std::size_t>> _jwkSets;
};

// Mock for OidcIdentityProvidersRegistry to control the behavior of the registry
class OidcIdentityProvidersRegistryMock : public OidcIdentityProvidersRegistry {
public:
    void setIdp(const OidcIdentityProviderConfig& config) {
        _config = config;
    }

    void setNumOfIdpsWithHumanFlowsSupport(size_t numOfIdpsWithHumanFlowsSupport) {
        _numOfIdpsWithHumanFlowsSupport = numOfIdpsWithHumanFlowsSupport;
    }

    void setJWKManager(const std::string& issuer, std::shared_ptr<crypto::JWKManager> jwkManager) {
        _jwkManagers.emplace(make_pair(issuer, std::move(jwkManager)));
    }

    boost::optional<const OidcIdentityProviderConfig&> getIdp(
        const std::string& issuer, const std::vector<std::string>& audience) const override {
        return _config.map(
            [](const OidcIdentityProviderConfig& cfg) -> const OidcIdentityProviderConfig& {
                return cfg;
            });
    }

    boost::optional<const OidcIdentityProviderConfig&> getIdpForPrincipalName(
        boost::optional<std::string_view> principalName) const override {
        return _config.map(
            [](const OidcIdentityProviderConfig& cfg) -> const OidcIdentityProviderConfig& {
                return cfg;
            });
    }

    bool hasIdpWithHumanFlowsSupport() const override {
        return _numOfIdpsWithHumanFlowsSupport > 0;
    }

    size_t numOfIdpsWithHumanFlowsSupport() const override {
        return _numOfIdpsWithHumanFlowsSupport;
    }

    std::shared_ptr<crypto::JWKManager> getJWKManager(const std::string& issuer) const override {
        if (_jwkManagers.contains(issuer)) {
            return _jwkManagers.at(issuer);
        }
        return nullptr;
    }

    void visitJWKManagers(JWKManagerVisitor visitor) const override {
        invariant(visitor);
        for (const auto& [issuer, jwkManager] : _jwkManagers) {
            visitor(issuer, jwkManager);
        }
    }

protected:
    boost::optional<OidcIdentityProviderConfig> _config;
    size_t _numOfIdpsWithHumanFlowsSupport{0};
    // NOTE: Maintain alphabetical order, some tests can rely on it.
    std::map<std::string, std::shared_ptr<crypto::JWKManager>> _jwkManagers;
};

class OidcTestFixture : public unittest::Test {
public:
    OidcTestFixture()
        : _serviceContext(ServiceContext::make()),
          _client(_serviceContext->getService()->makeClient("OidcTestFixtureClient")),
          _operationContext(_serviceContext->makeOperationContext(_client.get())) {}

    void setUp() override {
        OidcIdentityProvidersRegistry::set(_serviceContext.get(),
                                           std::make_unique<OidcIdentityProvidersRegistryMock>());
    }

    void tearDown() override {
        OidcIdentityProvidersRegistry::set(_serviceContext.get(), nullptr);
    }

protected:
    OidcIdentityProvidersRegistryMock& registryMock() {
        return static_cast<OidcIdentityProvidersRegistryMock&>(
            OidcIdentityProvidersRegistry::get(_serviceContext.get()));
    }

    OperationContext* operationContext() {
        return _operationContext.get();
    }

    ServiceContext* serviceContext() {
        return _serviceContext.get();
    }

    Client* client() {
        return _client.get();
    }

private:
    ServiceContext::UniqueServiceContext _serviceContext;
    ServiceContext::UniqueClient _client;
    ServiceContext::UniqueOperationContext _operationContext;
};

}  // namespace mongo
