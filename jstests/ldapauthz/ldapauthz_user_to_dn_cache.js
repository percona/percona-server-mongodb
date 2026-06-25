/**
 * Tests userToDN mapping cache behavior:
 * - Authentication works correctly with caching enabled and disabled
 * - Cache is invalidated when ldapUserToDNMapping is changed at runtime
 * - Cache is invalidated when ldapUserToDNCacheTTLSeconds is changed at runtime
 * - Cache is invalidated when ldapUserToDNCacheSize is changed at runtime
 * - New server parameters can be read and set at runtime
 */
import {checkConnectionStatus} from "jstests/ldapauthz/_check.js";
import {createAdminUser} from "jstests/ldapauthz/_setup.js";

(function () {
    "use strict";

    const username = "exttestro";
    const userpwd = "exttestro9a5S";
    const nameToDn = function (name) {
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
        var setParameter = Object.assign(
            {
                authenticationMechanisms: "PLAIN,SCRAM-SHA-256,SCRAM-SHA-1",
                ldapUserCacheInvalidationInterval: 1,
                ldapShouldRefreshUserCacheEntries: false,
            },
            extraSetParams || {},
        );
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

    function authLDAPUser(conn, check = true) {
        var db = conn.getDB("$external");
        var ok = db.auth({user: username, pwd: userpwd, mechanism: "PLAIN"});
        if (ok) {
            if (check) {
                checkConnectionStatus(username, db.runCommand({connectionStatus: 1}), nameToDn);
            }
            db.logout();
        }
        return ok;
    }

    // The authLDAPUserNoCheck was introduced because authLDAPUser can generate unpredictable number
    // of cache hits. We use authLDAPUserNoCheck in those places where we have asserts on the number
    // of cache hits.
    function authLDAPUserNoCheck(conn) {
        return authLDAPUser(conn, false);
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

    function getServerStatus(conn) {
        var adminDb = conn.getDB("admin");
        assert(adminDb.auth({user: "admin", pwd: "password"}));
        var res = assert.commandWorked(adminDb.adminCommand({serverStatus: 1}));
        adminDb.logout();
        return res;
    }

    function assertCacheStats(stats, expected, msg) {
        assert(stats.hasOwnProperty("ldap"), "serverStatus.ldap missing", {stats});
        assert(
            stats.ldap.hasOwnProperty("userToDNCache"),
            "serverStatus.ldap.userToDNCache missing",
            {stats},
        );
        var cache = stats.ldap.userToDNCache;
        for (var [key, val] of Object.entries(expected)) {
            if (key === "hits") {
                // The "hits" counter is a LOWER BOUND, not an exact value. A successful
                // $external auth resolves the DN via mapUserToDN() at two call sites -- the
                // SASL bind (external_sasl_authentication_session.cpp) and queryUserRoles()
                // (ldap_manager_impl.cpp) -- which is the "miss + hit" the checkpoints below
                // model. But the AuthorizationManager can also re-acquire an $external user's
                // roles opportunistically (the short ldapUserCacheInvalidationInterval, session
                // teardown around logout), and each extra acquisition runs queryUserRoles() ->
                // mapUserToDN() again, adding another cache hit. That re-acquisition races the
                // serverStatus read on the checkpoints taken right after an auth, so the exact
                // hit count is timing-dependent and flakes under load (observed on the bb-psmdb
                // farm: "expected NumberLong(2) to equal 1"). Assert hits >= expected so a
                // legitimate extra hit does not fail the test.
                //
                // "misses" is intentionally NOT relaxed (asserted exactly below): a miss means
                // an actual LDAP round-trip, so it is the metric that proves caching works and
                // it is stable here -- on the post-auth checkpoints the DN is cached (a
                // re-acquisition is a hit, not a miss), and the invalidation checkpoints settle
                // via setParam()'s sleep before the read.
                assert.gte(cache[key], val, msg + ": field " + key, {cache});
            } else {
                assert.eq(cache[key], val, msg + ": field " + key, {cache});
            }
        }
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
        assert(authLDAPUserNoCheck(conn), "First auth should succeed");

        // Each successful auth calls mapUserToDN twice: once for the LDAP bind (sasl session)
        // and once inside queryUserRoles.

        // Ensure first auth = 1 miss + 1 hit
        assertCacheStats(
            getServerStatus(conn),
            {
                enabled: true,
                maxSize: 10000,
                ttlSeconds: 30,
                currentSize: 1,
                misses: 1,
                hits: 1,
                invalidations: 0,
            },
            "after first auth (miss+hit)",
        );

        // Wait for the $external user cache to expire so the second auth re-resolves
        // the DN via mapUserToDN() and exercises the cache hit path.
        sleep(2000);

        jsTestLog("Test: Auth with cache enabled (second call, cache hit)");
        assert(authLDAPUserNoCheck(conn), "Second auth should succeed (cache hit)");

        jsTestLog(
            "Test: serverStatus.ldap.userToDNCache fields are present and correct after first auth (miss+hit) and second auth (two hits)",
        );

        // Second auth = 2 hits (no additional misses because the user is cached after the first
        // auth)
        assertCacheStats(
            getServerStatus(conn),
            {
                enabled: true,
                maxSize: 10000,
                ttlSeconds: 30,
                currentSize: 1,
                misses: 1,
                hits: 3,
                invalidations: 0,
            },
            "after first auth (miss+hit) and second auth (two hits)",
        );

        jsTestLog("Test: getParameter returns default cache values");
        assert.eq(getParam(conn, "ldapUserToDNCacheTTLSeconds"), 30);
        assert.eq(getParam(conn, "ldapUserToDNCacheSize"), 10000);

        jsTestLog("Test: Invalidation on ldapUserToDNMapping change to substitution mode");
        setParam(conn, {ldapUserToDNMapping: substMapping});

        jsTestLog(
            "Test: hit/miss counters reset to zero immediately after invalidation (before any new auth)",
        );
        assertCacheStats(
            getServerStatus(conn),
            {
                enabled: true,
                invalidations: 1,
                hits: 0,
                misses: 0,
            },
            "counters reset right after invalidation",
        );

        assert(authLDAPUser(conn), "Auth should succeed with substitution mapping");

        jsTestLog("Test: invalidations counter incremented, one miss + one hit from single auth");
        assertCacheStats(
            getServerStatus(conn),
            {
                enabled: true,
                invalidations: 1,
                hits: 1,
                misses: 1,
            },
            "after first auth post-invalidation (1 miss + 1 hit from two mapUserToDN calls)",
        );

        jsTestLog("Test: Invalidation on ldapUserToDNMapping change to broken mapping");
        setParam(conn, {ldapUserToDNMapping: brokenMapping});
        assert(
            !authLDAPUser(conn),
            "Auth should fail with broken mapping (proves cache was invalidated)",
        );
        assertCacheStats(
            getServerStatus(conn),
            {enabled: true, invalidations: 2, hits: 0, misses: 1},
            "invalidation should happen on ldapUserToDNMapping change",
        );

        jsTestLog("Test: Restore original ldapQuery mapping");
        setParam(conn, {ldapUserToDNMapping: ldapQueryMapping});
        assert(authLDAPUser(conn), "Auth should succeed");

        jsTestLog("Test: ldapUserToDNCacheTTLSeconds change invalidates the DN cache");
        setParam(conn, {ldapUserToDNCacheTTLSeconds: 60});
        assertCacheStats(
            getServerStatus(conn),
            {
                enabled: true,
                invalidations: 4,
                hits: 0,
                misses: 0,
            },
            "invalidation should happen on ldapUserToDNCacheTTLSeconds change",
        );

        jsTestLog("Test: ldapUserToDNCacheTTLSeconds=0 disables the DN cache");
        setParam(conn, {ldapUserToDNCacheTTLSeconds: 0});
        assert(authLDAPUser(conn), "Auth should succeed with cache disabled (TTL=0)");
        assertCacheStats(
            getServerStatus(conn),
            {
                enabled: false,
                invalidations: 5,
                ttlSeconds: 0,
                hits: 0,
                misses: 0,
            },
            "ldapUserToDNCacheTTLSeconds=0 disables the DN cache",
        );

        // Restore original value
        setParam(conn, {ldapUserToDNCacheTTLSeconds: 30});

        jsTestLog("Test: ldapUserToDNCacheSize change invalidates the DN cache");
        assert(authLDAPUser(conn), "Auth should succeed to populate cache");
        setParam(conn, {ldapUserToDNCacheSize: 1});
        assertCacheStats(
            getServerStatus(conn),
            {
                enabled: true,
                invalidations: 7,
                hits: 0,
                misses: 0,
            },
            "invalidation should happen on ldapUserToDNCacheTTLSeconds change",
        );

        jsTestLog("Test: ldapUserToDNCacheSize=0 disables the DN cache");
        setParam(conn, {ldapUserToDNCacheSize: 0});
        assert(authLDAPUser(conn), "Auth should succeed with cache disabled (size=0)");
        assertCacheStats(
            getServerStatus(conn),
            {
                enabled: false,
                invalidations: 8,
                maxSize: 0,
                hits: 0,
                misses: 0,
            },
            "ldapUserToDNCacheSize=0 disables the DN cache",
        );

        // Restore original value
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

        createAdminUser(conn);
        assert(authLDAPUser(conn), "Auth should succeed with cache disabled (TTL=0)");

        jsTestLog(
            "Test: serverStatus.ldap.userToDNCache reports enabled=false and zero counters when TTL=0",
        );
        assertCacheStats(
            getServerStatus(conn),
            {
                enabled: false,
                ttlSeconds: 0,
                hits: 0,
                misses: 0,
                invalidations: 0,
            },
            "cache disabled via TTL=0",
        );

        MongoRunner.stopMongod(conn);
    }

    // ------------------------------------------------------------------
    // Instance 3: Cache disabled at startup via size=0
    // ------------------------------------------------------------------
    {
        jsTestLog("Test: Auth works with cache disabled at startup (size=0)");

        var conn = MongoRunner.runMongod(baseMongodOpts({ldapUserToDNCacheSize: 0}));
        assert(conn, "Cannot start mongod instance");

        createAdminUser(conn);
        assert(authLDAPUser(conn), "Auth should succeed with cache disabled (size=0)");

        jsTestLog(
            "Test: serverStatus.ldap.userToDNCache reports enabled=false and zero counters when size=0",
        );
        assertCacheStats(
            getServerStatus(conn),
            {
                enabled: false,
                maxSize: 0,
                hits: 0,
                misses: 0,
                invalidations: 0,
            },
            "cache disabled via size=0",
        );

        MongoRunner.stopMongod(conn);
    }
})();
