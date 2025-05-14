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

#include "mongo/db/auth/oidc/oidc_identity_providers_registry.h"

#include "mongo/db/auth/oidc/oidc_test_fixture.h"
#include "mongo/db/service_context.h"
#include "mongo/unittest/assert.h"
#include "mongo/unittest/framework.h"

namespace mongo {

class SaslOidcServerMechanismTest : public unittest::Test {
public:
    SaslOidcServerMechanismTest()
        : _serviceContext(std::make_unique<ServiceContext>()),
          _client(_serviceContext->getService()->makeClient("SaslOidcServerMechanismTestClient")),
          _operationContext(_serviceContext->makeOperationContext(_client.get())) {}

    void setUp() override {
        OidcIdentityProvidersRegistry::set(_serviceContext.get(),
                                           std::make_unique<OidcIdentityProvidersRegistryMock>());
    }

    void tearDown() override {
        OidcIdentityProvidersRegistry::set(_serviceContext.get(), nullptr);
    }

protected:
    // Runs the step and transforms the result to BSONObj.
    StatusWith<BSONObj> runStep(const BSONObj& input) {
        StringData bsonData(input.objdata(), input.objsize());
        auto result = _mech.step(_operationContext.get(), bsonData);
        if (!result.isOK()) {
            return result.getStatus();
        }
        return BSONObj(result.getValue().data()).getOwned();
    }

    OidcIdentityProvidersRegistryMock& registryMock() {
        return static_cast<OidcIdentityProvidersRegistryMock&>(
            OidcIdentityProvidersRegistry::get(_serviceContext.get()));
    }

    SaslOidcServerMechanism _mech{"admin"};
    std::unique_ptr<ServiceContext> _serviceContext;
    ServiceContext::UniqueClient _client;
    ServiceContext::UniqueOperationContext _operationContext;
};

// Test for proper handling input BSON object parsing error.
TEST_F(SaslOidcServerMechanismTest, invalid_input) {
    auto result = _mech.step(_operationContext.get(), "");
    ASSERT_FALSE(result.isOK());
    ASSERT_EQ(result.getStatus().code(), ErrorCodes::InvalidBSON);
}

// Test for step1 with no requestScopes configuration.
TEST_F(SaslOidcServerMechanismTest, requestScopes_empty) {
    registryMock().setIdp(
        create_config("https://issuer", "prefix", "audience", SetClientId("clientId")));
    registryMock().setNumOfIdpsWithHumanFlowsSupport(1);

    BSONObj input{};
    auto result = runStep(input);

    ASSERT_TRUE(result.getStatus().isOK());
    const auto& obj = result.getValue();

    ASSERT_TRUE(obj.hasField("issuer"));
    ASSERT_EQ(obj["issuer"].String(), "https://issuer");

    ASSERT_TRUE(obj.hasField("clientId"));
    ASSERT_EQ(obj["clientId"].String(), "clientId");

    ASSERT_FALSE(obj.hasField("requestScopes"));
}

// Test for step1 with non-empty requestScopes configuration.
TEST_F(SaslOidcServerMechanismTest, requestScopes_notEmpty) {
    registryMock().setIdp(create_config("https://issuer",
                                        "prefix",
                                        "audience",
                                        SetClientId("clientId"),
                                        SetRequestScopes({"scope1", "scope2"})));
    registryMock().setNumOfIdpsWithHumanFlowsSupport(1);

    BSONObj input{};
    auto result = runStep(input);

    ASSERT_TRUE(result.getStatus().isOK());
    const auto& obj = result.getValue();

    ASSERT_TRUE(obj.hasField("issuer"));
    ASSERT_EQ(obj["issuer"].String(), "https://issuer");

    ASSERT_TRUE(obj.hasField("clientId"));
    ASSERT_EQ(obj["clientId"].String(), "clientId");

    const auto& requestScopes = obj.getField("requestScopes");
    ASSERT_TRUE(requestScopes.ok());
    ASSERT_EQ(requestScopes.type(), BSONType::Array);
    ASSERT_EQ(requestScopes.Array().size(), 2);
    ASSERT_EQ(requestScopes.Array()[0].String(), "scope1");
    ASSERT_EQ(requestScopes.Array()[1].String(), "scope2");
}

}  // namespace mongo
