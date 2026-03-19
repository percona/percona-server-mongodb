/**
 * Tests that LDAP connection pool is invalidated when bind credentials
 * are changed at runtime via setParameter.
 */
import {createAdminUser} from "jstests/ldapauthz/_setup.js";

(function() {
"use strict";

load("jstests/ldapauthz/_check.js");

const username = "cn=exttestro,dc=percona,dc=com";
const userpwd = "exttestro9a5S";

// ------------------------------------------------------------------
// Test: Changing ldapQueryPassword invalidates the connection pool.
//
// Pool connections are bound once at creation time. When credentials
// change, existing connections must be destroyed so new ones are
// created with the updated credentials.
// ------------------------------------------------------------------
jsTestLog("Test: Pool invalidation on ldapQueryPassword change");

var conn = MongoRunner.runMongod({
    auth: "",
    ldapServers: TestData.ldapServers,
    ldapTransportSecurity: "none",
    ldapBindMethod: "simple",
    ldapQueryUser: TestData.ldapQueryUser,
    ldapQueryPassword: TestData.ldapQueryPassword,
    ldapAuthzQueryTemplate: TestData.ldapAuthzQueryTemplate,
    setParameter: {
        authenticationMechanisms: "PLAIN,SCRAM-SHA-256,SCRAM-SHA-1",
        ldapUserCacheInvalidationInterval: 1,
        ldapShouldRefreshUserCacheEntries: false,
    },
});
assert(conn, "Cannot start mongod instance");

// Create admin user via localhost exception for setParameter access
createAdminUser(conn);

var db = conn.getDB("$external");

// Auth should succeed with correct credentials
assert(
    db.auth({user: username, pwd: userpwd, mechanism: "PLAIN"}),
    "Auth should succeed with valid LDAP credentials",
);

// Verify roles are correct
checkConnectionStatus(username, db.runCommand({connectionStatus: 1}));
db.logout();

// Change ldapQueryPassword to an invalid value — pool should be invalidated
var adminDb = conn.getDB("admin");
assert(adminDb.auth({user: "admin", pwd: "password"}));
assert.commandWorked(adminDb.adminCommand({setParameter: 1, ldapQueryPassword: "wrong_password"}));
adminDb.logout();

// Wait for user cache to be invalidated
sleep(2000);

// Auth should fail because pool connections were invalidated and
// new connections will bind with the wrong query password,
// causing the authz query to fail
assert(
    !db.auth({user: username, pwd: userpwd, mechanism: "PLAIN"}),
    "Auth should fail after ldapQueryPassword changed to invalid value",
);

// Restore correct ldapQueryPassword — pool invalidated again
assert(adminDb.auth({user: "admin", pwd: "password"}));
assert.commandWorked(
    adminDb.adminCommand({setParameter: 1, ldapQueryPassword: TestData.ldapQueryPassword}));
adminDb.logout();

// Auth should succeed again with restored credentials
assert(
    db.auth({user: username, pwd: userpwd, mechanism: "PLAIN"}),
    "Auth should succeed after restoring correct ldapQueryPassword",
);
db.logout();

MongoRunner.stopMongod(conn);
})();
