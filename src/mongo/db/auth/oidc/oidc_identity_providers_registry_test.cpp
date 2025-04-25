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

#include <memory>
#include <vector>

#include "mongo/db/auth/oidc/oidc_identity_providers_registry.h"
#include "mongo/db/auth/oidc/oidc_server_parameters_gen.h"
#include "mongo/db/auth/oidc/oidc_test_fixture.h"
#include "mongo/db/service_context.h"
#include "mongo/unittest/assert.h"
#include "mongo/unittest/death_test.h"
#include "mongo/unittest/framework.h"


namespace mongo {

namespace {

// Helper class to safely convert a string to boost::optional<std::string_view>
// for use in calls like: getIdpForPrincipalName(PrincipalName("user1"));
class PrincipalName {
public:
    template <typename T>
    explicit PrincipalName(T&& arg) : _str{std::forward<T>(arg)} {}

    operator boost::optional<std::string_view>() const {
        return std::string_view{_str};
    }

private:
    std::string _str;
};

class OidcIdentityProvidersRegistryTest : public unittest::Test {
protected:
    std::unique_ptr<OidcIdentityProvidersRegistry> create_registry(
        const std::vector<OidcIdentityProviderConfig>& configs) {
        return std::make_unique<OidcIdentityProvidersRegistry>(
            &_periodicRunnerMock, _jwksFetcherFactoryMock, configs);
    }

    PeriodicRunnerMock _periodicRunnerMock;
    JWKSFetcherFactoryMock _jwksFetcherFactoryMock;
};

// Death test for getting the OIDC identity providers registry without setting it first.
DEATH_TEST_REGEX(OidcIdentityProvidersRegistryTest, Invariant_GetWithoutSet, "Invariant failure") {
    auto serviceContext = ServiceContext::make();

    OidcIdentityProvidersRegistry::get(serviceContext.get());
}

// Death test for creating the OIDC identity providers registry with nullptr as the periodic runner.
DEATH_TEST_REGEX(OidcIdentityProvidersRegistryTest, Invariant_PeriodicRunner, "Invariant failure") {
    JWKSFetcherFactoryMock jwksFetcherFactoryMock;
    std::vector<OidcIdentityProviderConfig> config{};

    OidcIdentityProvidersRegistry registry(nullptr, jwksFetcherFactoryMock, config);
}

// Test for setting and getting the OIDC identity providers registry with a service context.
TEST_F(OidcIdentityProvidersRegistryTest, SetAndGetWithServiceContext) {
    auto serviceContext = ServiceContext::make();

    std::vector configs{create_config("https://issuer", "prefix", "audience")};

    auto registry = create_registry(configs);
    OidcIdentityProvidersRegistry::set(serviceContext.get(), std::move(registry));

    auto& retrieved = OidcIdentityProvidersRegistry::get(serviceContext.get());
    ASSERT_TRUE(retrieved.hasIdpWithHumanFlowsSupport());
    ASSERT_EQ(retrieved.numOfIdpsWithHumanFlowsSupport(), 1);
}

// Test for creating registry with an empty config.
TEST_F(OidcIdentityProvidersRegistryTest, EmptyConfig) {
    std::vector<OidcIdentityProviderConfig> configs;

    auto registry = create_registry(configs);

    ASSERT_EQ(_periodicRunnerMock.jobs.size(), 0);
    ASSERT_EQ(_jwksFetcherFactoryMock.count(), 0);
    ASSERT_FALSE(registry->hasIdpWithHumanFlowsSupport());
    ASSERT_EQ(registry->numOfIdpsWithHumanFlowsSupport(), 0);
    ASSERT_FALSE(registry->getIdp("https://issuer", {"audience"}).has_value());
    ASSERT_FALSE(registry->getIdpForPrincipalName(PrincipalName("principal")).has_value());
    ASSERT_EQ(registry->getJWKManager("https://issuer"), nullptr);
}

// Successful case for getting the IdP by issuer and audience if there is only one IdP
// in the registry->
TEST_F(OidcIdentityProvidersRegistryTest, GetIdp_SingleIdp_Success) {
    std::vector configs{
        create_config("https://issuer", "prefix", "audience"),
    };

    auto registry = create_registry(configs);

    const auto idp = registry->getIdp("https://issuer", {"audience"});
    ASSERT_TRUE(idp.has_value());
    ASSERT_EQ(idp.value(), configs[0]);
}

// Failure case for getting the IdP by issuer and audience if there is only one IdP
// in the registry->
TEST_F(OidcIdentityProvidersRegistryTest, GetIdp_SingleIdp_Failure) {
    std::vector configs{
        create_config("https://issuer", "prefix", "audience"),
    };

    auto registry = create_registry(configs);

    ASSERT_FALSE(registry->getIdp("https://some_issuer", {"audience"}).has_value());
    ASSERT_FALSE(registry->getIdp("https://issuer", {"some_audience"}).has_value());
}

// Successful cases for getting the IdP by issuer and audience if there are multiple IdPs
// in the registry->
TEST_F(OidcIdentityProvidersRegistryTest, GetIdp_MultipleIdps_Success) {
    std::vector configs{
        create_config("https://issuer", "prefix", "audience"),
        create_config("https://some_issuer", "prefix", "some_audience"),
        create_config("https://another_issuer", "prefix", "another_audience"),
    };

    auto registry = create_registry(configs);

    {
        const auto idp = registry->getIdp("https://issuer", {"audience"});
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
    {
        const auto idp = registry->getIdp("https://some_issuer", {"some_audience"});
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[1]);
    }
    {
        const auto idp = registry->getIdp("https://another_issuer", {"another_audience"});
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[2]);
    }
}

// Successful case for getting the IdP by issuer and vector of audiences if there is
// only one IdP in the registry->
TEST_F(OidcIdentityProvidersRegistryTest, GetIdp_MultipleAudiences_Success) {
    std::vector configs{
        create_config("https://issuer", "prefix", "audience"),
    };

    auto registry = create_registry(configs);

    const auto idp = registry->getIdp("https://issuer", {"audience1", "audience2", "audience"});
    ASSERT_TRUE(idp.has_value());
    ASSERT_EQ(idp.value(), configs[0]);
}

// Failure case for getting the IdP by issuer and audience if there are multiple IdPs
// in the registry->
TEST_F(OidcIdentityProvidersRegistryTest, GetIdp__MultipleIdps_Failure) {
    std::vector configs{
        create_config("https://issuer", "prefix", "audience"),
        create_config("https://some_issuer", "prefix", "some_audience"),
    };

    auto registry = create_registry(configs);

    ASSERT_FALSE(registry->getIdp("https://some_issuer", {"some_audience1"}).has_value());
    ASSERT_FALSE(registry->getIdp("https://issuer", {"some_audience"}).has_value());
    ASSERT_FALSE(registry->getIdp("https://some_issuer", {"audience"}).has_value());
    ASSERT_FALSE(
        registry->getIdp("https://issuer", {"some_audience1", "audienceX", "some_audience"})
            .has_value());
    ASSERT_FALSE(
        registry->getIdp("https://some_issuer", {"audience", "some_audience1"}).has_value());
}

// Test for getting the IdP by issuer and audience if there are multiple IdPs
// with the same issuer but different audiences in the registry->
TEST_F(OidcIdentityProvidersRegistryTest, GetIdp_OneIssuerMultipleAudiences) {
    std::vector configs{
        create_config("https://issuer", "prefix", "audience1"),
        create_config("https://issuer", "prefix", "audience2"),
        create_config("https://issuer", "prefix", "audience3"),
    };

    auto registry = create_registry(configs);

    ASSERT_FALSE(registry->getIdp("https://issuer", {"audience"}).has_value());

    {
        const auto idp = registry->getIdp("https://issuer", {"audience1"});
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
    {
        const auto idp = registry->getIdp("https://issuer", {"audience2"});
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[1]);
    }
    {
        const auto idp = registry->getIdp("https://issuer", {"audience3"});
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[2]);
    }
}

// Successful cases for getting the IdP by principal name if there are multiple IdPs
// in the registry and none of them has the match pattern.
TEST_F(OidcIdentityProvidersRegistryTest, GetIdpForPrincipalName_AllWithoutMatchPattern_Success) {
    std::vector configs{
        create_config("https://issuer1", "prefix1", "audience1"),
        create_config("https://issuer2", "prefix2", "audience2"),
    };

    auto registry = create_registry(configs);

    {
        const auto idp = registry->getIdpForPrincipalName(PrincipalName("user1"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }

    {
        const auto idp = registry->getIdpForPrincipalName(PrincipalName("user2"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }

    {
        const auto idp = registry->getIdpForPrincipalName(boost::none);
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
}

// Successful case for getting the IdP by principal name if there are multiple IdPs
// in the registry and all of them have the match pattern.
TEST_F(OidcIdentityProvidersRegistryTest, GetIdpForPrincipalName_AllWithMatchPattern_Success) {
    std::vector configs{
        create_config("https://issuer1", "prefix1", "audience1", SetMatchPattern("1$")),
        create_config("https://issuer2", "prefix2", "audience2", SetMatchPattern("2$")),
    };

    auto registry = create_registry(configs);

    {
        const auto idp = registry->getIdpForPrincipalName(PrincipalName("user1"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }

    {
        const auto idp = registry->getIdpForPrincipalName(PrincipalName("user2"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[1]);
    }

    {
        const auto idp = registry->getIdpForPrincipalName(boost::none);
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
}

// Failure case for getting the IdP by principal name if there are multiple IdPs
// in the registry and all of them have the match pattern.
TEST_F(OidcIdentityProvidersRegistryTest, GetIdpForPrincipalName_AllWithMatchPattern_Failure) {
    std::vector configs{
        create_config("https://issuer1", "prefix1", "audience1", SetMatchPattern("1$")),
        create_config("https://issuer2", "prefix2", "audience2", SetMatchPattern("2$")),
    };

    auto registry = create_registry(configs);

    ASSERT_FALSE(registry->getIdpForPrincipalName(PrincipalName("user3")).has_value());
    ASSERT_FALSE(registry->getIdpForPrincipalName(PrincipalName("1user")).has_value());
    ASSERT_FALSE(registry->getIdpForPrincipalName(PrincipalName("2user")).has_value());
}

// Test for getting the IdP by principal name if there are multiple IdPs
// in the registry and none of them supports human flows.
TEST_F(OidcIdentityProvidersRegistryTest, GetIdpForPrincipalName_NoneWithSupportHumanFlows) {
    std::vector configs{
        create_config("https://issuer1",
                      "prefix1",
                      "audience1",
                      SetSupportsHumanFlows(false),
                      SetMatchPattern("1$")),
        create_config("https://issuer2",
                      "prefix2",
                      "audience2",
                      SetSupportsHumanFlows(false),
                      SetMatchPattern("2$")),
    };

    auto registry = create_registry(configs);

    ASSERT_FALSE(registry->hasIdpWithHumanFlowsSupport());
    ASSERT_EQ(registry->numOfIdpsWithHumanFlowsSupport(), 0);

    // No IdP supports human flows, expect no idp config to be returned
    {
        const auto idp = registry->getIdpForPrincipalName(boost::none);
        ASSERT_FALSE(idp.has_value());
    }
    {
        const auto idp = registry->getIdpForPrincipalName(PrincipalName("user1"));
        ASSERT_FALSE(idp.has_value());
    }
    {
        const auto idp = registry->getIdpForPrincipalName(PrincipalName("user2"));
        ASSERT_FALSE(idp.has_value());
    }
}

// Test for getting the IdP by principal name if there are multiple IdPs
// in the registry and only one of them supports human flows.
TEST_F(OidcIdentityProvidersRegistryTest, GetIdpForPrincipalName_OneWithSupportHumanFlows) {
    std::vector configs{
        create_config("https://issuer1", "prefix1", "audience1", SetSupportsHumanFlows(true)),
        create_config("https://issuer2",
                      "prefix2",
                      "audience2",
                      SetSupportsHumanFlows(false),
                      SetMatchPattern("2$")),
    };

    auto registry = create_registry(configs);

    ASSERT_TRUE(registry->hasIdpWithHumanFlowsSupport());
    ASSERT_EQ(registry->numOfIdpsWithHumanFlowsSupport(), 1);

    {
        // Expect first IdP if no principal name provided
        const auto idp = registry->getIdpForPrincipalName(boost::none);
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
    {
        // Only the first IdP supports human flows, so it should be returned regardless of input.
        const auto idp = registry->getIdpForPrincipalName(PrincipalName("user1"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
    {
        // Only the first IdP supports human flows, so it should be returned regardless of input.
        const auto idp = registry->getIdpForPrincipalName(PrincipalName("user2"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
}

// Test for getting the IdP by principal name if there are multiple IdPs
// in the registry, some of them support human flows and some do not.
TEST_F(OidcIdentityProvidersRegistryTest, GetIdPForPrincipalName_SupportsHumanFlows_PartialList) {
    std::vector configs{
        create_config("https://issuer1",
                      "prefix",
                      "audience1",
                      SetSupportsHumanFlows(true),
                      SetMatchPattern("1$")),
        create_config("https://issuer2", "prefix", "audience2", SetSupportsHumanFlows(true)),
        create_config("https://issuer3", "prefix", "audience3", SetSupportsHumanFlows(false)),
        create_config("https://issuer4", "prefix", "audience4", SetSupportsHumanFlows(false)),
    };

    auto registry = create_registry(configs);

    ASSERT_TRUE(registry->hasIdpWithHumanFlowsSupport());
    ASSERT_EQ(registry->numOfIdpsWithHumanFlowsSupport(), 2);

    {
        // First IdP matches user1
        auto idp = registry->getIdpForPrincipalName(PrincipalName("user1"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
    {
        // No match for user2, expect second IdP
        auto idp = registry->getIdpForPrincipalName(PrincipalName("user2"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[1]);
    }
    {
        // No principal name provided, expect first IdP
        auto idp = registry->getIdpForPrincipalName(boost::none);
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
}

// Test for getting the IdP by principal name if there are multiple IdPs
// in the registry, all of them have the match pattern and the last one
// matches all principal names.
TEST_F(OidcIdentityProvidersRegistryTest,
       GetIdpForPrincipalName_MultipleMatchPatterns_LastMatchingAll) {
    std::vector configs{
        create_config("https://issuer1", "prefix1", "audience1", SetMatchPattern("1$")),
        create_config("https://issuer2", "prefix2", "audience2", SetMatchPattern("2$")),
        create_config("https://issuer3",
                      "prefix3",
                      "audience3",
                      SetMatchPattern(".*")),  // matches all
    };

    auto registry = create_registry(configs);

    {
        // Expect first IdP if no principal name provided
        const auto idp = registry->getIdpForPrincipalName(boost::none);
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
    {
        // Expect first IdP since principal name matches first IdP
        const auto idp = registry->getIdpForPrincipalName(PrincipalName("user1"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[0]);
    }
    {
        // Expect second idp since principal name matches second idp
        const auto idp = registry->getIdpForPrincipalName(PrincipalName("user2"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[1]);
    }
    {
        // Expect third IdP since third IdP's match pattern matches all
        const auto idp = registry->getIdpForPrincipalName(PrincipalName("user3"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[2]);
    }
    {
        // Expect third IdP since third IdP's match pattern matches all
        const auto idp = registry->getIdpForPrincipalName(PrincipalName("user4"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[2]);
    }
    {
        // Expect third IdP since third IdP's match pattern matches all
        const auto idp = registry->getIdpForPrincipalName(PrincipalName("some_user"));
        ASSERT_TRUE(idp.has_value());
        ASSERT_EQ(idp.value(), configs[2]);
    }
}

// Test for getting the JWKManager by issuer
TEST_F(OidcIdentityProvidersRegistryTest, GetJWKManager_Success) {
    std::vector configs{
        create_config("https://issuer1", "prefix1", "audience1", SetSupportsHumanFlows(true)),
        create_config("https://issuer2", "prefix1", "audience2", SetSupportsHumanFlows(false)),
    };

    auto registry = create_registry(configs);

    // expect two fetchers created for each unique issuer
    ASSERT_EQ(_jwksFetcherFactoryMock.count(), 2);
    ASSERT_TRUE(_jwksFetcherFactoryMock.createdForIssuer("https://issuer1"));
    ASSERT_TRUE(_jwksFetcherFactoryMock.createdForIssuer("https://issuer2"));

    // expect JWKManager for both issuers
    ASSERT_NE(registry->getJWKManager("https://issuer1"), nullptr);
    ASSERT_NE(registry->getJWKManager("https://issuer2"), nullptr);

    // expect no JWKManager for unknown issuer
    ASSERT_EQ(registry->getJWKManager("https://issuer3"), nullptr);
}

// Test for not starting the JWKSPolling jobs if the JWKSPollSecs is not set.
TEST_F(OidcIdentityProvidersRegistryTest, JWKSPollSecs_NoJobsStarted) {
    std::vector configs{
        create_config("https://issuer1", "prefix", "audience1", SetJWKSPollSecs(0)),
        create_config("https://issuer2", "prefix", "audience3", SetJWKSPollSecs(0)),
    };

    auto registry = create_registry(configs);

    // expect no jobs created
    ASSERT_EQ(_periodicRunnerMock.jobs.size(), 0);
}

// Test for starting the JWKSPolling jobs with correct periods
TEST_F(OidcIdentityProvidersRegistryTest, JWKSPollSecs_JobsStarted) {
    std::vector configs{
        create_config("https://issuer1", "prefix", "audience1", SetJWKSPollSecs(1)),
        create_config("https://issuer1", "prefix", "audience2", SetJWKSPollSecs(1)),  // same issuer
        create_config("https://issuer2", "prefix", "audience3", SetJWKSPollSecs(2)),
    };

    auto registry = create_registry(configs);

    // expect 2 jobs created, one for each unique issuer
    ASSERT_EQ(_periodicRunnerMock.jobs.size(), 2);
    ASSERT_TRUE(_periodicRunnerMock.allJobsHaveUniqueName());

    // expect both jobs have correct periods and are started
    ASSERT_EQ(_periodicRunnerMock.jobs[0]->getPeriod(), Milliseconds(Seconds(1)));
    ASSERT_TRUE(_periodicRunnerMock.jobs[0]->isStarted());

    ASSERT_EQ(_periodicRunnerMock.jobs[1]->getPeriod(), Milliseconds(Seconds(2)));
    ASSERT_TRUE(_periodicRunnerMock.jobs[1]->isStarted());
}

}  // namespace
}  // namespace mongo
