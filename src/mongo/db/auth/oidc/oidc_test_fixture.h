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
#include <unordered_set>

#include "mongo/crypto/jwks_fetcher_factory.h"
#include "mongo/db/auth/oidc/match_pattern.h"
#include "mongo/db/auth/oidc/oidc_identity_providers_registry.h"
#include "mongo/db/auth/oidc/oidc_server_parameters_gen.h"
#include "mongo/unittest/assert.h"
#include "mongo/util/periodic_runner.h"

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
        std::unordered_set<std::string> seen;
        for (const auto& job : jobs) {
            if (!seen.insert(job->name()).second) {
                return false;
            }
        }

        return true;
    }

    std::vector<std::shared_ptr<ControllableJobMock>> jobs;
};

// Mock for JWKSFetcherFactory to control the creation of JWKSFetcher instances
struct JWKSFetcherFactoryMock : public JWKSFetcherFactory {
    class JWKSFetcherMock : public crypto::JWKSFetcher {
    public:
        crypto::JWKSet fetch() override {
            FAIL("JWKSFetcherMock::fetch() is not implemented");
            return {};
        }
    };

public:
    std::unique_ptr<crypto::JWKSFetcher> makeJWKSFetcher(StringData issuer) const override {
        _issuers.emplace_back(issuer);
        return std::make_unique<JWKSFetcherMock>();
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

    void setJWKManager(std::shared_ptr<crypto::JWKManager> jwkManager) {
        _jwkManager = std::move(jwkManager);
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
        return _jwkManager;
    }

protected:
    boost::optional<OidcIdentityProviderConfig> _config;
    size_t _numOfIdpsWithHumanFlowsSupport{0};
    std::shared_ptr<crypto::JWKManager> _jwkManager{nullptr};
};

}  // namespace mongo
