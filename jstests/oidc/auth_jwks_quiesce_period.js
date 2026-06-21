import {OIDCFixture, ShardedCluster, StandaloneMongod} from "jstests/oidc/lib/oidc_fixture.js";

const issuer_url = OIDCFixture.allocate_issuer_url();

const idp_config = {
    token: {
        payload: {
            aud: "audience",
            sub: "user",
            claim: "group",
        },
    },
};

const oidcProvider = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    authorizationClaim: "claim",
};

function test_jwks_quiesce_period(clusterClass) {
    var test = new OIDCFixture({
        oidcProviders: [oidcProvider],
        idps: [{url: issuer_url, config: idp_config}],
    });
    // The negative assertion below requires that the IdP restart + the second auth attempt
    // all complete WITHIN this window (measured from mongod's first JWKS fetch). With the
    // old value of 15s the window could elapse during a slow idp.restart() (the mock
    // regenerates RSA JWKs on startup), so mongod was allowed to refetch and auth
    // unexpectedly succeeded. Size the window well above the worst-case restart time; the
    // wait for the positive case below only sleeps the *remaining* time, so the larger
    // window does not proportionally slow the test.
    const jwksMinimumQuiescePeriodSecs = 60;
    test.setup(clusterClass, false, jwksMinimumQuiescePeriodSecs);
    test.create_role("test/group", [{role: "readWrite", db: "test_db"}]);
    const expectedRoles = ["test/group", {role: "readWrite", db: "test_db"}];
    var conn = test.create_conn();
    var idp = test.get_idp(issuer_url);

    // First authentication, expect fetching jwks. Anchor the quiesce window to this fetch:
    // mongod starts its JWKSMinimumQuiescePeriodSecs timer when it loads the keys here.
    assert(test.auth(conn, "user"), "Failed to authenticate");
    idp.assert_http_request("GET", "/keys");
    const firstFetchMs = Date.now();
    test.assert_authenticated(conn, "test/user", expectedRoles);
    test.logout(conn);

    // Restart IdP to generate new keys
    idp.restart();
    idp.clear_output();

    // Still within the quiesce window (sized generously above), so mongod must NOT refetch
    // JWKS -- it can't verify the new-key token and auth must fail. This is a "must not
    // happen yet" check, so it cannot use assert.soon; its validity relies on the window
    // not having elapsed, which the generous size guarantees even on a slow machine.
    assert(
        !test.auth(conn, "user"),
        "Authentication should fail due to JWKSMinimumQuiescePeriodSecs",
    );
    idp.assert_no_http_request("GET", "/keys");

    // Wait out only the REMAINDER of the quiesce window (measured from the first fetch),
    // plus a small margin, so widening the window above doesn't add a proportional sleep.
    const marginMs = 2000;
    const remainingMs = jwksMinimumQuiescePeriodSecs * 1000 - (Date.now() - firstFetchMs);
    sleep(Math.max(remainingMs, 0) + marginMs);

    // Now authentication should work again because fetching new JWKs is possible again
    assert(test.auth(conn, "user"), "Failed to authenticate");
    idp.assert_http_request("GET", "/keys");
    test.assert_authenticated(conn, "test/user", expectedRoles);
    test.logout(conn);

    test.teardown();
}

test_jwks_quiesce_period(StandaloneMongod);
test_jwks_quiesce_period(ShardedCluster);
