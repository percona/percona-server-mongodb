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

#include "mongo/db/auth/oidc/user_request_oidc.h"

#include "mongo/unittest/assert.h"
#include "mongo/unittest/framework.h"

namespace mongo {
namespace {

const auto kTestUserName = UserName{"testUser", "testDB"};

const std::set<RoleName> kTestRolesFromToken{
    RoleName{"testRoleFromToken1", "someDB1"},
    RoleName{"testRoleFromToken2", "someDB2"},
};

const std::set<RoleName> kTestRoles = {
    RoleName{"testRoleFromToken1", "someDB1"},
    RoleName{"testRoleFromToken2", "someDB2"},
    RoleName{"testRole1", "testDB1"},
    RoleName{"testRole2", "testDB2"},
};

// Test for getType method of UserRequestOIDC class which should return UserRequestType::OIDC.
TEST(UserRequestOIDCTest, Type) {
    UserRequestOIDC request(kTestUserName, boost::none, boost::none);

    ASSERT_EQ(request.getType(), UserRequest::UserRequestType::OIDC);
}

// Test for clone method of UserRequestOIDC class.
// It should return a new UserRequestOIDC object with the same user name and roles.
TEST(UserRequestOIDCTest, Clone) {
    UserRequestOIDC request(kTestUserName, kTestRoles, kTestRolesFromToken);

    auto clonedRequest = request.clone();
    ASSERT_NE(clonedRequest, nullptr);
    ASSERT_TRUE(clonedRequest->getUserName() == kTestUserName);
    ASSERT_TRUE(clonedRequest->getRoles().has_value());
    ASSERT_EQ(clonedRequest->getRoles(), kTestRoles);

    auto anotherClonedRequest = clonedRequest->clone();
    ASSERT_NE(anotherClonedRequest, nullptr);
    ASSERT_TRUE(anotherClonedRequest->getUserName() == kTestUserName);
    ASSERT_TRUE(anotherClonedRequest->getRoles().has_value());
    ASSERT_EQ(anotherClonedRequest->getRoles(), kTestRoles);
}

// Test for cloneForReacquire method of UserRequestOIDC class.
// It should return a new UserRequestOIDC object with the same user name and roles from token.
TEST(UserRequestOIDCTest, CloneForReacquire) {

    UserRequestOIDC request(kTestUserName, kTestRoles, kTestRolesFromToken);

    auto clonedRequest = request.cloneForReacquire();
    ASSERT_OK(clonedRequest.getStatus());
    ASSERT_TRUE(clonedRequest.getValue()->getUserName() == kTestUserName);
    ASSERT_TRUE(clonedRequest.getValue()->getRoles().has_value());
    ASSERT_EQ(clonedRequest.getValue()->getRoles(), kTestRolesFromToken);
}

// Test for cloneForReacquire method after clone.
// The request cloned for reacquire after normal clone should have the same user name
// and roles from token as the original request.
TEST(UserRequestOIDCTest, CloneForReacquireAfterClone) {

    UserRequestOIDC request(kTestUserName, kTestRoles, kTestRolesFromToken);

    auto clonedRequest = request.clone();
    ASSERT_NE(clonedRequest, nullptr);
    ASSERT_TRUE(clonedRequest->getUserName() == kTestUserName);
    ASSERT_TRUE(clonedRequest->getRoles().has_value());
    ASSERT_EQ(clonedRequest->getRoles(), kTestRoles);

    auto clonedForReacquire = clonedRequest->cloneForReacquire();
    ASSERT_OK(clonedForReacquire.getStatus());
    ASSERT_TRUE(clonedForReacquire.getValue()->getUserName() == kTestUserName);
    ASSERT_TRUE(clonedForReacquire.getValue()->getRoles().has_value());
    ASSERT_EQ(clonedForReacquire.getValue()->getRoles(), kTestRolesFromToken);
}

}  // namespace
}  // namespace mongo
