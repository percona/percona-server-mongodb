import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

var idp_config = {
    token: [
        { // The first token will be created with jwk generated on init
            generate_jwks: false,
            payload: {
                aud: "audience",
                sub: "user",
                claim: "group",
            }
        },
        { // The second token will be created with the same jwk
            generate_jwks: false,
            payload: {
                aud: "audience",
                sub: "user",
                claim: "group",
            }
        },
        {
            // The third token will be created with a new jwk
            generate_jwks: true,
            payload: {
                aud: "audience",
                sub: "user",
                claim: "group",
            }
        },
        {
            // The fourth token will be created with the same jwk
            generate_jwks: false,
            payload: {
                aud: "audience",
                sub: "user",
                claim: "group",
            }
        },
    ],
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

// First authentication, expect fetching jwks
var conn = test.create_conn();
var idp = test.get_idp(issuer_url);
assert(test.auth(conn, "user"), "Failed to authenticate");
idp.assert_http_request("GET", "/keys");
test.assert_authenticated(conn, "test/user", expectedRoles);
test.logout(conn);

// Second authentication with the same kid, expect no fetching jwks
idp.clear_output();
assert(test.auth(conn, "user"), "Failed to authenticate");
idp.assert_no_http_request("GET", "/keys");
test.assert_authenticated(conn, "test/user", expectedRoles);
test.logout(conn);

// Third authentication with a new kid, expect fetching jwks
idp.clear_output();
assert(test.auth(conn, "user"), "Failed to authenticate");
idp.assert_http_request("GET", "/keys");
test.assert_authenticated(conn, "test/user", expectedRoles);
test.logout(conn);

// Fourth authentication with the same kid, expect no fetching jwks
idp.clear_output();
assert(test.auth(conn, "user"), "Failed to authenticate");
idp.assert_no_http_request("GET", "/keys");
test.assert_authenticated(conn, "test/user", expectedRoles);
test.logout(conn);

test.teardown();
