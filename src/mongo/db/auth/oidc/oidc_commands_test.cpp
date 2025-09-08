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

#include "mongo/bson/bsonmisc.h"
#include "mongo/db/audit_interface.h"
#include "mongo/db/auth/authorization_session_for_test.h"
#include "mongo/db/auth/authz_manager_external_state_mock.h"
#include "mongo/db/auth/authz_session_external_state_mock.h"
#include "mongo/db/auth/oidc/oidc_test_fixture.h"
#include "mongo/unittest/framework.h"

namespace mongo {

namespace {

class OidcCommandsTest : public OidcTestFixture {
public:
    OidcCommandsTest(const std::string& name)
        : _authzManager(std::make_unique<AuthorizationManagerImpl>(
              serviceContext()->getService(), std::make_unique<AuthzManagerExternalStateMock>())),
          _dbName(DatabaseName::createDatabaseName_forTest(boost::none, "admin")) {

        // setup authz session mock
        AuthorizationSession::set(
            client(),
            std::make_unique<AuthorizationSessionForTest>(
                std::make_unique<AuthzSessionExternalStateMock>(_authzManager.get()),
                AuthorizationSessionImpl::InstallMockForTestingOrAuthImpl{}));

        // required when logout is called
        audit::AuditInterface::set(serviceContext(), std::make_unique<audit::AuditNoOp>());

        // find the registered command to be tested by name
        _cmd = dynamic_cast<BasicCommand*>(
            getCommandRegistry(serviceContext()->getService())->findCommand(name));
        invariant(_cmd);
    }

protected:
    BasicCommand& cmd() {
        invariant(_cmd);
        return *_cmd;
    }

    BSONObj createCmdObj() {
        return BSON(cmd().getName() << 1);
    }

    // wrapepr for running the command, returns the status with optional BSON result
    StatusWith<BSONObj> runCmd() try {
        BSONObjBuilder result;
        cmd().run(operationContext(), _dbName, createCmdObj(), result);
        return result.obj();
    } catch (const DBException& e) {
        return e.toStatus();
    }

    AuthorizationSessionForTest* authzSession() {
        return static_cast<AuthorizationSessionForTest*>(AuthorizationSession::get(client()));
    }

    // Logout the session from all databalses.
    // If not executed after calling one of the assumePrivileges* methods from the authz session,
    // the invariant inside authz session's destructor will fail.
    void logout() {
        const std::string reason = "TestReason";
        authzSession()->logoutAllDatabases(client(), reason);
    }

    // Test for basic command properties.
    void basicTest() {
        ASSERT_TRUE(cmd().adminOnly());
        ASSERT_FALSE(cmd().supportsWriteConcern(createCmdObj()));
        ASSERT_EQ(cmd().secondaryAllowed(serviceContext()),
                  BasicCommand::AllowedOnSecondary::kAlways);
        ASSERT_FALSE(cmd().help().empty());
    }

    // Test for negative authorization check.
    void authorizationTestNegative() {
        const auto status =
            cmd().checkAuthForOperation(operationContext(), _dbName, createCmdObj());
        ASSERT_NOT_OK(status);
        ASSERT_EQ(status.code(), ErrorCodes::Unauthorized);
    }

    // Test for positive authorization check.
    void authorizationTestPositive() {
        authzSession()->assumePrivilegesForBuiltinRole(RoleName("root", "admin"));

        const auto status =
            cmd().checkAuthForOperation(operationContext(), _dbName, createCmdObj());
        ASSERT_OK(status);

        logout();
    }

private:
    std::unique_ptr<AuthorizationManagerImpl> _authzManager;
    DatabaseName _dbName;
    BasicCommand* _cmd;
};

class OidcListKeysTest : public OidcCommandsTest {
public:
    OidcListKeysTest() : OidcCommandsTest("oidcListKeys") {}
};

class OidcRefreshKeysTest : public OidcCommandsTest {
public:
    OidcRefreshKeysTest() : OidcCommandsTest("oidcRefreshKeys") {}
};

TEST_F(OidcListKeysTest, Basic) {
    basicTest();
}

TEST_F(OidcRefreshKeysTest, Basic) {
    basicTest();
}

TEST_F(OidcListKeysTest, AuthorizationNegative) {
    authorizationTestNegative();
}

TEST_F(OidcRefreshKeysTest, AuthorizationNegative) {
    authorizationTestNegative();
}

TEST_F(OidcListKeysTest, AuthorizationPositive) {
    authorizationTestPositive();
}

TEST_F(OidcRefreshKeysTest, AuthorizationPositive) {
    authorizationTestPositive();
}

// Test for the oidcListKeys command with no JWK managers.
TEST_F(OidcListKeysTest, Run_NoJWKManagers) {
    const auto result = runCmd();
    ASSERT_OK(result);
    const auto& keySets = result.getValue().getField("keySets");
    ASSERT_EQ(keySets.type(), BSONType::Object);
    ASSERT_TRUE(keySets.Obj().isEmpty());
}

// Test for the oidcListKeys command with multiple JWK managers and multiple JWKs.
TEST_F(OidcListKeysTest, Run) {
    // It's not possible to mock the JWKManager so the only way to test
    // this command is to use the JWKSFetcherFactoryMock.
    JWKSFetcherFactoryMock jwksFetcherFactoryMock;

    std::string issuer1 = "issuer1";
    std::string issuer2 = "issuer2";

    const auto jwk1 = create_sample_jwk("kid1");
    const auto jwk2 = create_sample_jwk("kid2");
    const auto jwk3 = create_sample_jwk("kid3");

    jwksFetcherFactoryMock.setJWKSet(issuer1, crypto::JWKSet{{jwk1}});
    jwksFetcherFactoryMock.setJWKSet(issuer2, crypto::JWKSet{{jwk2, jwk3}});

    auto jwkManager1 =
        std::make_shared<crypto::JWKManager>(jwksFetcherFactoryMock.makeJWKSFetcher(issuer1));
    auto jwkManager2 =
        std::make_shared<crypto::JWKManager>(jwksFetcherFactoryMock.makeJWKSFetcher(issuer2));

    // trigger loading of the keys
    ASSERT_OK(jwkManager1->loadKeys());
    ASSERT_OK(jwkManager2->loadKeys());

    registryMock().setJWKManager(issuer1, jwkManager1);
    registryMock().setJWKManager(issuer2, jwkManager2);

    // Run the oidcListKeys command
    const auto result = runCmd();
    ASSERT_OK(result);

    // Check the format of the result

    // Check if the keySets field exists.
    const auto& keySets = result.getValue().getField("keySets");
    ASSERT_TRUE(keySets.ok());
    ASSERT_EQ(keySets.type(), BSONType::Object);

    // Check if the key set for issuer1 exists
    const auto& keySet1 = keySets.Obj().getField(issuer1);
    ASSERT_TRUE(keySet1.ok());
    ASSERT_EQ(keySet1.type(), BSONType::Object);

    // Check if the keys array exists for issuer1
    const auto& keys1 = keySet1.Obj().getField("keys");
    ASSERT_TRUE(keys1.ok());
    ASSERT_EQ(keys1.type(), BSONType::Array);

    // Expect one JWK ...
    const auto& keysArray1 = keys1.Array();
    ASSERT_EQ(keysArray1.size(), 1);

    // .. which should be equal to the jwk1.
    const auto& key1 = keysArray1[0];
    ASSERT_TRUE(key1.ok());
    ASSERT_EQ(key1.type(), BSONType::Object);
    ASSERT_BSONOBJ_EQ(key1.Obj(), jwk1);

    // Check if the key set for issuer2 exists
    const auto& keySet2 = keySets.Obj().getField(issuer2);
    ASSERT_TRUE(keySet2.ok());
    ASSERT_EQ(keySet2.type(), BSONType::Object);

    // Check if the keys array exists for issuer2
    const auto& keys2 = keySet2.Obj().getField("keys");
    ASSERT_TRUE(keys2.ok());
    ASSERT_EQ(keys2.type(), BSONType::Array);

    // Expect two JWKs ...
    const auto& keysArray2 = keys2.Array();
    ASSERT_EQ(keysArray2.size(), 2);

    // ... the first one should be equal to the jwk2 ...
    const auto& key2 = keysArray2[0];
    ASSERT_TRUE(key2.ok());
    ASSERT_EQ(key2.type(), BSONType::Object);
    ASSERT_BSONOBJ_EQ(key2.Obj(), jwk2);

    // ... the second one should be equal to the jwk3.
    const auto& key3 = keysArray2[1];
    ASSERT_TRUE(key3.ok());
    ASSERT_EQ(key3.type(), BSONType::Object);
    ASSERT_BSONOBJ_EQ(key3.Obj(), jwk3);
}

// Test for oidcRefreshKeys command with no JWK managers.
TEST_F(OidcRefreshKeysTest, Run_NoJWKManagers) {
    ASSERT_OK(runCmd());
}

// Test for oidcRefreshKeys command  with a single JWK manager which fails.
TEST_F(OidcRefreshKeysTest, Run_OneJwkManager_Failed) {
    JWKSFetcherFactoryMock jwksFetcherFactoryMock;
    std::string issuer = "issuer";

    // JWKSFetcherFactoryMock is not set up with a JWKSet for the issuer so refreshing should fail.
    registryMock().setJWKManager(
        issuer,
        std::make_shared<crypto::JWKManager>(jwksFetcherFactoryMock.makeJWKSFetcher(issuer)));

    const StatusWith<BSONObj> result{runCmd()};
    // the command finishes successfully but returns an error
    ASSERT_OK(result);

    const BSONElement okField{result.getValue().getField("ok")};
    ASSERT_EQ(okField.type(), BSONType::NumberInt);
    ASSERT_EQ(okField.numberInt(), 0);

    const BSONElement errmsgField{result.getValue().getField("errmsg")};
    ASSERT_EQ(errmsgField.type(), BSONType::String);
    ASSERT_EQ(errmsgField.str(), "Failed to load a JWKS from one or more IdPs");

    const BSONElement failuresField{result.getValue().getField("failures")};
    ASSERT_EQ(failuresField.type(), BSONType::Array);
    std::vector<BSONElement> failures{failuresField.Array()};
    ASSERT_EQ(failures.size(), 1);
    ASSERT_EQ(failures[0].type(), BSONType::Object);

    const BSONObj expectedFailure{
        BSON("issuer" << issuer << "error"
                      << BSON("code" << 211 << "codeName" << "KeyNotFound" << "errmsg"
                                     << std::string("No JWK for issuer ") + issuer))};
    const BSONObj::ComparisonRulesSet rules{BSONObj::ComparatorInterface::kConsiderFieldName |
                                            BSONObj::ComparatorInterface::kIgnoreFieldOrder};
    ASSERT_EQ(failures[0].Obj().woCompare(expectedFailure, {}, rules), 0);
}

// Test for oidcRefreshKeys command with multiple JWK managers:
// first two failing and the last one succeeding.
// NOTE: this test relies on the alphabetical order when visiting the JWK managers stored
// in the OidcIdentityProvidersRegistryMock.
TEST_F(OidcRefreshKeysTest, Run_MultipleJwkManagers_Failed) {
    JWKSFetcherFactoryMock jwksFetcherFactoryMock;

    std::string issuer1 = "issuer1";  // this one will fail
    std::string issuer2 = "issuer2";  // this one will fail
    std::string issuer3 = "issuer3";  // but this one will succeed

    registryMock().setJWKManager(
        issuer1,
        std::make_shared<crypto::JWKManager>(jwksFetcherFactoryMock.makeJWKSFetcher(issuer1)));

    registryMock().setJWKManager(
        issuer2,
        std::make_shared<crypto::JWKManager>(jwksFetcherFactoryMock.makeJWKSFetcher(issuer2)));

    registryMock().setJWKManager(
        issuer3,
        std::make_shared<crypto::JWKManager>(jwksFetcherFactoryMock.makeJWKSFetcher(issuer3)));

    // set the JWKSet for the last issuer
    jwksFetcherFactoryMock.setJWKSet(issuer3, crypto::JWKSet{{create_sample_jwk("kid")}});

    const StatusWith<BSONObj> result{runCmd()};
    // the command finishes successfully but returns an error
    ASSERT_OK(result);

    const BSONElement okField{result.getValue().getField("ok")};
    ASSERT_EQ(okField.type(), BSONType::NumberInt);
    ASSERT_EQ(okField.numberInt(), 0);

    const BSONElement errmsgField{result.getValue().getField("errmsg")};
    ASSERT_EQ(errmsgField.type(), BSONType::String);
    ASSERT_EQ(errmsgField.str(), "Failed to load a JWKS from one or more IdPs");

    // the first two JWK fetchers failed
    const BSONElement failuresField{result.getValue().getField("failures")};
    ASSERT_EQ(failuresField.type(), BSONType::Array);
    std::vector<BSONElement> failures{failuresField.Array()};
    ASSERT_EQ(failures.size(), 2);
    ASSERT_EQ(failures[0].type(), BSONType::Object);
    ASSERT_EQ(failures[1].type(), BSONType::Object);

    auto expectedFailure = [](const std::string issuer) {
        return BSON("issuer" << issuer << "error"
                             << BSON("code" << 211 << "codeName" << "KeyNotFound" << "errmsg"
                                            << std::string("No JWK for issuer ") + issuer));
    };
    auto failureEq = [](const BSONObj& lhs, const BSONObj& rhs) {
        const BSONObj::ComparisonRulesSet rules{BSONObj::ComparatorInterface::kConsiderFieldName |
                                                BSONObj::ComparatorInterface::kIgnoreFieldOrder};
        return lhs.woCompare(rhs, {}, rules) == 0;
    };
    ASSERT_TRUE((failureEq(failures[0].Obj(), expectedFailure(issuer1)) &&
                 failureEq(failures[1].Obj(), expectedFailure(issuer2))) ||
                (failureEq(failures[0].Obj(), expectedFailure(issuer2)) &&
                 failureEq(failures[1].Obj(), expectedFailure(issuer1))));

    // the third JWK fetcher succeded once
    ASSERT_EQ(jwksFetcherFactoryMock.getFetchCount(issuer3), 1);
}

// Success test case for oidcRefreshKeys command with multiple JWK managers.
TEST_F(OidcRefreshKeysTest, Run_MultipleJwkManagers_Success) {
    JWKSFetcherFactoryMock jwksFetcherFactoryMock;
    std::string issuer1 = "issuer1";
    std::string issuer2 = "issuer2";
    std::string issuer3 = "issuer3";

    registryMock().setJWKManager(
        issuer1,
        std::make_shared<crypto::JWKManager>(jwksFetcherFactoryMock.makeJWKSFetcher(issuer1)));

    registryMock().setJWKManager(
        issuer2,
        std::make_shared<crypto::JWKManager>(jwksFetcherFactoryMock.makeJWKSFetcher(issuer2)));

    registryMock().setJWKManager(
        issuer3,
        std::make_shared<crypto::JWKManager>(jwksFetcherFactoryMock.makeJWKSFetcher(issuer3)));

    jwksFetcherFactoryMock.setJWKSet(issuer1, crypto::JWKSet{{create_sample_jwk("kid1")}});
    jwksFetcherFactoryMock.setJWKSet(issuer2, crypto::JWKSet{{create_sample_jwk("kid2")}});
    jwksFetcherFactoryMock.setJWKSet(issuer3, crypto::JWKSet{{create_sample_jwk("kid3")}});

    for (int i = 1; i <= 3; ++i) {
        ASSERT_OK(runCmd());

        // expect all JWK managers requested the keys, anytime the command is executed
        ASSERT_EQ(jwksFetcherFactoryMock.getFetchCount(issuer1), i);
        ASSERT_EQ(jwksFetcherFactoryMock.getFetchCount(issuer2), i);
        ASSERT_EQ(jwksFetcherFactoryMock.getFetchCount(issuer3), i);
    }
}

}  // namespace
}  // namespace mongo
