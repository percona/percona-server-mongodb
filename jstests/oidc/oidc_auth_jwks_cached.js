import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

var idp_config = {
    token: {
        payload: {
            aud: "audience",
            sub: "user",
            claim: "group",
        }
    },
};

var oidcProvider = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    authorizationClaim: "claim"
};

var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
test.setup();
test.create_role("test/group", [{ role: "readWrite", db: "test_db" }]);
const expectedRoles = ["test/group", { role: "readWrite", db: "test_db" }];
var conn = test.create_conn();
var idp = test.get_idp(issuer_url);

// First authentication, expect fetching jwks
assert(test.auth(conn, "user"), "Failed to authenticate");
idp.assert_http_request("GET", "/keys");
test.assert_authenticated(conn, "test/user", expectedRoles);
test.logout(conn);

// Next authentications use the same kid, expect no fetching jwks
for (let i = 0; i < 4; i++) {
    idp.clear_output();
    assert(test.auth(conn, "user"), "Failed to authenticate, i = " + i);
    idp.assert_no_http_request("GET", "/keys");
    test.assert_authenticated(conn, "test/user", expectedRoles);
    test.logout(conn);
}

// Authenticate, without fetching jwks...
idp.clear_output();
assert(test.auth(conn, "user"), "Failed to authenticate");
idp.assert_no_http_request("GET", "/keys");
test.assert_authenticated(conn, "test/user", expectedRoles);
idp.clear_output();

// ...refresh token, still without fetching jwks...
var access_token = test.refresh_token(conn);
idp.assert_no_http_request("GET", "/keys");
assert(access_token, "No access token returned");
test.assert_authenticated(conn, "test/user", expectedRoles);
test.logout(conn);

// ...authenticate with access token, still without fetching jwks..
idp.clear_output();
assert(conn.auth({ mechanism: 'MONGODB-OIDC', oidcAccessToken: access_token }), "Failed to authenticate with token");
test.assert_authenticated(conn, "test/user", expectedRoles);
idp.assert_no_http_request("GET", "/keys");
test.logout(conn);

// ...don't expect fetching jwks, even if new keys are generated if the same kid is still used.
// NOTE: Restarting idp will generate new jwks
idp.restart();
idp.clear_output();
assert(conn.auth({ mechanism: 'MONGODB-OIDC', oidcAccessToken: access_token }), "Failed to authenticate with token");
test.assert_authenticated(conn, "test/user", expectedRoles);
idp.assert_no_http_request("GET", "/keys");
test.logout(conn);

test.teardown();
