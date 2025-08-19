import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

const idp_config = {
    token: {
        payload: {
            aud: "audience",
            sub: "user",
            claim: "group",
        }
    },
};

const oidcProvider = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    authorizationClaim: "claim"
};

function test_jwks_quiesce_period(clusterClass) {
    var test = new OIDCFixture(
        {oidcProviders: [oidcProvider], idps: [{url: issuer_url, config: idp_config}]});
    const jwksMinimumQuiescePeriodSecs = 15;
    test.setup(clusterClass, false, jwksMinimumQuiescePeriodSecs);
    test.create_role("test/group", [{role: "readWrite", db: "test_db"}]);
    const expectedRoles = ["test/group", {role: "readWrite", db: "test_db"}];
    var conn = test.create_conn();
    var idp = test.get_idp(issuer_url);

    // First authentication, expect fetching jwks
    assert(test.auth(conn, "user"), "Failed to authenticate");
    idp.assert_http_request("GET", "/keys");
    test.assert_authenticated(conn, "test/user", expectedRoles);
    test.logout(conn);

    // Restart IdP to generate new keys
    idp.restart();
    idp.clear_output();

    // Expect authentication failure due to JWKSMinimumQuiescePeriodSecs not yet passed
    assert(!test.auth(conn, "user"), "Authentication should fail due to JWKSMinimumQuiescePeriodSecs");
    idp.assert_no_http_request("GET", "/keys");

    // Wait for JWKSMinimumQuiescePeriodSecs to pass
    sleep(jwksMinimumQuiescePeriodSecs * 1000);

    // Now authentication should work again because fetching new JWKs is possible again
    assert(test.auth(conn, "user"), "Failed to authenticate");
    idp.assert_http_request("GET", "/keys");
    test.assert_authenticated(conn, "test/user", expectedRoles);
    test.logout(conn);

    test.teardown();
}

test_jwks_quiesce_period(StandaloneMongod);
test_jwks_quiesce_period(ShardedCluster);
