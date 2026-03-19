/**
 * Tests that LDAP timeout options (LDAP_OPT_NETWORK_TIMEOUT, LDAP_OPT_TIMEOUT)
 * are applied to LDAP connections, ensuring auth fails gracefully instead of
 * hanging when the LDAP server is unreachable or unresponsive.
 */
import {createAdminUser} from "jstests/ldapauthz/_setup.js";

(function() {
"use strict";

const username = "cn=exttestro,dc=percona,dc=com";
const userpwd = "exttestro9a5S";

// ------------------------------------------------------------------
// Test 1: Auth against a non-listening LDAP port fails gracefully.
//
// When the LDAP server is completely unreachable (connection refused),
// auth must fail quickly and the server must remain responsive.
// After switching ldapServers to a valid server, auth must succeed.
// ------------------------------------------------------------------
{
    jsTestLog("Test 1: Auth against non-listening LDAP port fails gracefully");

    var conn = MongoRunner.runMongod({
        auth: "",
        ldapServers: "localhost:39999",
        ldapTransportSecurity: "none",
        ldapBindMethod: "simple",
        ldapQueryUser: "cn=admin,dc=percona,dc=com",
        ldapQueryPassword: "password",
        ldapAuthzQueryTemplate:
            "dc=percona,dc=com??sub?(&(objectClass=groupOfNames)(member={USER}))",
        ldapTimeoutMS: 5000,
        ldapValidateLDAPServerConfig: false,
        setParameter: {
            authenticationMechanisms: "PLAIN,SCRAM-SHA-256,SCRAM-SHA-1",
        },
    });
    assert(conn, "Cannot start mongod instance");

    // Create admin user via localhost exception so we can call setParameter
    createAdminUser(conn);

    var db = conn.getDB("$external");

    // PLAIN auth must fail (LDAP server is not listening)
    assert(
        !db.auth({user: username, pwd: userpwd, mechanism: "PLAIN"}),
        "Auth should fail when LDAP server is not listening",
    );

    // Server must remain responsive after LDAP auth failure.
    // Switch to a valid LDAP server and verify auth works.
    var adminDb = conn.getDB("admin");
    assert(adminDb.auth({user: "admin", pwd: "password"}), "Admin SCRAM auth should succeed");
    assert.commandWorked(
        adminDb.adminCommand({setParameter: 1, ldapServers: TestData.ldapServers}));
    adminDb.logout();

    assert(
        db.auth({user: username, pwd: userpwd, mechanism: "PLAIN"}),
        "Auth should succeed after switching to a valid LDAP server",
    );
    db.logout();

    // Switch back to the non-listening port — pool should be invalidated again
    assert(adminDb.auth({user: "admin", pwd: "password"}));
    assert.commandWorked(adminDb.adminCommand({setParameter: 1, ldapServers: "localhost:39999"}));
    adminDb.logout();

    assert(
        !db.auth({user: username, pwd: userpwd, mechanism: "PLAIN"}),
        "Auth should fail after switching back to non-listening LDAP server",
    );

    MongoRunner.stopMongod(conn);
}

// ------------------------------------------------------------------
// Test 2: Zero ldapTimeoutMS causes auth to fail.
//
// With a 0 ms timeout, LDAP operations time out immediately,
// proving that LDAP_OPT_TIMEOUT is actually applied to bind
// operations.
// ------------------------------------------------------------------
{
    jsTestLog("Test 2: Auth fails with zero ldapTimeoutMS");

    var conn = MongoRunner.runMongod({
        auth: "",
        ldapServers: TestData.ldapServers,
        ldapTransportSecurity: "none",
        ldapBindMethod: "simple",
        ldapQueryUser: TestData.ldapQueryUser,
        ldapQueryPassword: TestData.ldapQueryPassword,
        ldapAuthzQueryTemplate: TestData.ldapAuthzQueryTemplate,
        ldapTimeoutMS: 0,
        ldapValidateLDAPServerConfig: false,
        setParameter: {
            authenticationMechanisms: "PLAIN,SCRAM-SHA-256,SCRAM-SHA-1",
        },
    });
    assert(conn, "Cannot start mongod instance");

    var db = conn.getDB("$external");

    // PLAIN auth must fail — 0ms timeout expires immediately
    assert(!db.auth({user: username, pwd: userpwd, mechanism: "PLAIN"}),
           "Auth should fail with 0ms ldapTimeoutMS");

    MongoRunner.stopMongod(conn);
}
})();
