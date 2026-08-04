/**
 * PSMDB-2212: mongod must not abort when an LDAP operation timeout in
 * execQuery() is followed by a failed retry borrow that leaves the local
 * connection pointer null on scope exit.
 *
 * Bug (before the fix):
 *   execQuery() registers ON_BLOCK_EXIT that returns the borrowed connection
 *   via a by-reference capture. After a timed-out search the connection is
 *   destroyed and borrow_search_connection() may return nullptr (retry bind
 *   also times out); the guard then called return_search_connection(nullptr)
 *   → ldap_unbind_ext(nullptr) → process abort (SIGABRT).
 *
 * Reproduction uses a minimal LDAP mock that:
 *   1) Allows one successful PLAIN auth/authz (bind + successful search),
 *   2) Then hangs once on search and once on the retry bind so ldapTimeoutMS
 *      fires and the retry borrow returns nullptr,
 *   3) Closes further connections immediately so background authz retries
 *      fail fast (avoids jstest hang).
 *
 * With the fix, the second auth fails gracefully and mongod stays up.
 * Without the fix, mongod aborts during the second auth attempt.
 */
import {createAdminUser} from "jstests/ldapauthz/_setup.js";

load("jstests/libs/python.js");

(function() {
"use strict";

const kMockPath = "jstests/ldapauthz/lib/ldap_mock_timeouts.py";
const kMockReady = "LDAP mock server is running at ";

const kLdapTimeoutMS = 1000;
// Slightly above ldapTimeoutMS so the client-side timeout wins.
const kMockHangSeconds = 3;

const mockPort = allocatePort();
const mockHostPort = "127.0.0.1:" + mockPort;

jsTestLog("Starting LDAP mock on " + mockHostPort);

clearRawMongoProgramOutput();
const mockPid = _startMongoProgram({
    args: [
        getPython3Binary(),
        kMockPath,
        "--host",
        "127.0.0.1",
        "--port",
        String(mockPort),
        // Successful first auth: user bind + pool bind.
        // Second auth: user bind (3rd success), then hung search on pooled conn,
        // then hung retry bind (4th bind overall).
        "--max-successful-binds",
        "3",
        "--max-successful-searches",
        "1",
        "--hang-seconds",
        String(kMockHangSeconds),
        "--search-entry-dn",
        "cn=testreaders,dc=percona,dc=com",
    ],
});
assert(checkProgram(mockPid).alive, "LDAP mock failed to start");

assert.soon(
    () => rawMongoProgramOutput(".*").search(kMockReady + "127.0.0.1:" + mockPort) !== -1,
    "LDAP mock did not print ready banner",
);

const username = "cn=exttestro,dc=percona,dc=com";
const userpwd = "exttestro9a5S";

let conn;
try {
    jsTestLog("Starting mongod against LDAP mock (ldapTimeoutMS=" + kLdapTimeoutMS + ")");
    conn = MongoRunner.runMongod({
        auth: "",
        ldapServers: mockHostPort,
        ldapTransportSecurity: "none",
        ldapBindMethod: "simple",
        ldapQueryUser: "cn=admin,dc=percona,dc=com",
        ldapQueryPassword: "password",
        ldapAuthzQueryTemplate:
            "dc=percona,dc=com??sub?(&(objectClass=groupOfNames)(member={USER}))",
        ldapTimeoutMS: kLdapTimeoutMS,
        ldapValidateLDAPServerConfig: false,
        setParameter: {
            authenticationMechanisms: "PLAIN,SCRAM-SHA-256,SCRAM-SHA-1",
            ldapConnectionPoolSizePerHost: 2,
            // Keep invalidation interval high; we invalidate explicitly below.
            ldapUserCacheInvalidationInterval: 30,
            ldapShouldRefreshUserCacheEntries: false,
        },
    });
    assert(conn, "Cannot start mongod instance");

    createAdminUser(conn);

    const extDb = conn.getDB("$external");
    const adminDb = conn.getDB("admin");

    jsTestLog("First PLAIN auth: mock returns successful authz search");
    assert(extDb.auth({user: username, pwd: userpwd, mechanism: "PLAIN"}),
           "First auth should succeed against LDAP mock");
    const status = assert.commandWorked(extDb.runCommand({connectionStatus: 1}));
    assert.eq(status.authInfo.authenticatedUsers[0].user, username);
    assert(status.authInfo.authenticatedUserRoles.some((r) => r.role ===
                                                           "cn=testreaders,dc=percona,dc=com"),
           "expected mock-granted role, got: " + tojson(status.authInfo.authenticatedUserRoles));
    extDb.logout();

    // Drop the cached $external user so the next auth re-enters execQuery(),
    // without enabling a 1s invalidation loop that storms the mock.
    assert(adminDb.auth({user: "admin", pwd: "password"}));
    assert.commandWorked(adminDb.runCommand({invalidateUserCache: 1}));
    adminDb.logout();

    jsTestLog("Second PLAIN auth: search times out, retry borrow times out; mongod must not abort");
    // Bounded by ~2 * ldapTimeoutMS (search + retry bind), plus mock slack.
    assert(
        !extDb.auth({user: username, pwd: userpwd, mechanism: "PLAIN"}),
        "Second auth should fail when LDAP search/retry times out",
    );

    assert(adminDb.auth({user: "admin", pwd: "password"}),
           "mongod aborted or became unresponsive after LDAP operation timeout (PSMDB-2212)");
    assert.commandWorked(adminDb.runCommand({ping: 1}));
    adminDb.logout();

    jsTestLog("mongod remained responsive after successful auth + timeout null-connection path");
    MongoRunner.stopMongod(conn);
    conn = null;
} finally {
    if (conn) {
        try {
            MongoRunner.stopMongod(conn);
        } catch (e) {
            jsTestLog("stopMongod after failure: " + e);
        }
    }
    stopMongoProgramByPid(mockPid);
}
})();
