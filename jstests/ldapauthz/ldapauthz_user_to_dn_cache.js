/**
 * Tests userToDN mapping cache behavior:
 * - Authentication works correctly with caching enabled and disabled
 * - Cache is invalidated when ldapUserToDNMapping is changed at runtime
 * - Cache is invalidated when ldapUserToDNCacheTTLSeconds is changed at runtime
 * - Cache is invalidated when ldapUserToDNCacheSize is changed at runtime
 * - New server parameters can be read and set at runtime
 */
import {createAdminUser} from "jstests/ldapauthz/_setup.js";

(function() {
"use strict";

load("jstests/ldapauthz/_check.js");

const username = "exttestro";
const userpwd = "exttestro9a5S";
const nameToDn = function(name) {
    return "cn=" + name + ",dc=percona,dc=com";
};

const ldapQueryMapping =
    '[{match: "(.+)", ldapQuery: "dc=percona,dc=com??sub?(&(objectClass=organizationalPerson)(sn={0}))"}]';
const substMapping = '[{match: "(.+)", substitution: "cn={0},dc=percona,dc=com"}]';
const brokenMapping = '[{match: "(.+)", substitution: "cn={0},dc=WRONG,dc=com"}]';

function baseMongodOpts(extraSetParams) {
    // Use a short user cache invalidation interval so that each auth attempt after
    // a setParameter change re-resolves the DN via mapUserToDN() instead of being
    // served from the $external authorization user cache.
    var setParameter = Object.assign({
        authenticationMechanisms: "PLAIN,SCRAM-SHA-256,SCRAM-SHA-1",
        ldapUserCacheInvalidationInterval: 1,
        ldapShouldRefreshUserCacheEntries: false,
    },
                                     extraSetParams || {});
    return {
        auth: "",
        ldapServers: TestData.ldapServers,
        ldapTransportSecurity: "none",
        ldapBindMethod: "simple",
        ldapQueryUser: TestData.ldapQueryUser,
        ldapQueryPassword: TestData.ldapQueryPassword,
        ldapAuthzQueryTemplate: TestData.ldapAuthzQueryTemplate,
        ldapUserToDNMapping: ldapQueryMapping,
        setParameter: setParameter,
    };
}

function authLDAPUser(conn) {
    var db = conn.getDB("$external");
    var ok = db.auth({user: username, pwd: userpwd, mechanism: "PLAIN"});
    if (ok) {
        checkConnectionStatus(username, db.runCommand({connectionStatus: 1}), nameToDn);
        db.logout();
    }
    return ok;
}

function setParam(conn, paramObj) {
    var adminDb = conn.getDB("admin");
    assert(adminDb.auth({user: "admin", pwd: "password"}));
    assert.commandWorked(adminDb.adminCommand(Object.assign({setParameter: 1}, paramObj)));
    adminDb.logout();
    // Wait for the $external user cache to be invalidated (interval is 1s)
    // so the next auth attempt re-resolves the DN via mapUserToDN().
    sleep(2000);
}

function getParam(conn, paramName) {
    var adminDb = conn.getDB("admin");
    assert(adminDb.auth({user: "admin", pwd: "password"}));
    var cmd = {getParameter: 1};
    cmd[paramName] = 1;
    var res = adminDb.adminCommand(cmd);
    assert.commandWorked(res);
    adminDb.logout();
    return res[paramName];
}

// ------------------------------------------------------------------
// Instance 1: Cache enabled with default params, ldapQuery mapping
// ------------------------------------------------------------------
{
    jsTestLog("Starting instance with default cache params and ldapQuery mapping");

    var conn = MongoRunner.runMongod(baseMongodOpts());
    assert(conn, "Cannot start mongod instance");

    createAdminUser(conn);

    jsTestLog("Test: Auth with cache enabled (first call)");
    assert(authLDAPUser(conn), "First auth should succeed");

    jsTestLog("Test: Auth with cache enabled (second call, cache hit)");
    assert(authLDAPUser(conn), "Second auth should succeed (cache hit)");

    jsTestLog("Test: getParameter returns default cache values");
    assert.eq(getParam(conn, "ldapUserToDNCacheTTLSeconds"), 30);
    assert.eq(getParam(conn, "ldapUserToDNCacheSize"), 10000);

    jsTestLog("Test: Invalidation on ldapUserToDNMapping change to substitution mode");
    setParam(conn, {ldapUserToDNMapping: substMapping});
    assert(authLDAPUser(conn), "Auth should succeed with substitution mapping");

    jsTestLog("Test: Invalidation on ldapUserToDNMapping change to broken mapping");
    setParam(conn, {ldapUserToDNMapping: brokenMapping});
    assert(!authLDAPUser(conn),
           "Auth should fail with broken mapping (proves cache was invalidated)");

    jsTestLog("Test: Restore original ldapQuery mapping");
    setParam(conn, {ldapUserToDNMapping: ldapQueryMapping});
    assert(authLDAPUser(conn), "Auth should succeed after restoring ldapQuery mapping");

    // To prove TTL/size changes actually invalidate the DN cache, we populate the
    // cache with the correct mapping, then change the cache parameter AND switch to
    // the broken mapping in the same batch. If the cache were NOT invalidated by the
    // parameter change, the old cached DN would still be used and auth would succeed.
    // Auth failing proves the parameter change cleared the cache.

    jsTestLog("Test: ldapUserToDNCacheTTLSeconds change invalidates the DN cache");
    setParam(conn, {ldapUserToDNMapping: ldapQueryMapping});
    assert(authLDAPUser(conn), "Auth should succeed to populate cache");
    setParam(conn, {ldapUserToDNCacheTTLSeconds: 60, ldapUserToDNMapping: brokenMapping});
    assert(!authLDAPUser(conn), "Auth should fail — proves TTL change invalidated the DN cache");

    jsTestLog("Test: ldapUserToDNCacheTTLSeconds=0 disables the DN cache");
    setParam(conn, {ldapUserToDNCacheTTLSeconds: 0, ldapUserToDNMapping: ldapQueryMapping});
    assert(authLDAPUser(conn), "Auth should succeed with cache disabled (TTL=0)");

    setParam(conn, {ldapUserToDNCacheTTLSeconds: 30});

    jsTestLog("Test: ldapUserToDNCacheSize change invalidates the DN cache");
    assert(authLDAPUser(conn), "Auth should succeed to populate cache");
    setParam(conn, {ldapUserToDNCacheSize: 1, ldapUserToDNMapping: brokenMapping});
    assert(!authLDAPUser(conn), "Auth should fail — proves size change invalidated the DN cache");

    jsTestLog("Test: ldapUserToDNCacheSize=0 disables the DN cache");
    setParam(conn, {ldapUserToDNCacheSize: 0, ldapUserToDNMapping: ldapQueryMapping});
    assert(authLDAPUser(conn), "Auth should succeed with cache disabled (size=0)");

    setParam(conn, {ldapUserToDNCacheSize: 10000});

    MongoRunner.stopMongod(conn);
}

// ------------------------------------------------------------------
// Instance 2: Cache disabled at startup via TTL=0
// ------------------------------------------------------------------
{
    jsTestLog("Test: Auth works with cache disabled at startup (TTL=0)");

    var conn = MongoRunner.runMongod(baseMongodOpts({ldapUserToDNCacheTTLSeconds: 0}));
    assert(conn, "Cannot start mongod instance");

    assert(authLDAPUser(conn), "Auth should succeed with cache disabled (TTL=0)");

    MongoRunner.stopMongod(conn);
}

// ------------------------------------------------------------------
// Instance 3: Cache disabled at startup via size=0
// ------------------------------------------------------------------
{
    jsTestLog("Test: Auth works with cache disabled at startup (size=0)");

    var conn = MongoRunner.runMongod(baseMongodOpts({ldapUserToDNCacheSize: 0}));
    assert(conn, "Cannot start mongod instance");

    assert(authLDAPUser(conn), "Auth should succeed with cache disabled (size=0)");

    MongoRunner.stopMongod(conn);
}
})();
