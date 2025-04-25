import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

var idp_config = {
    token: {
        expires_in_seconds: 2,
        payload: {
            aud: "audience",
            sub: "user",
            claim: [
                "group",
            ],
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

var conn = test.create_conn();

assert(test.auth(conn, "user"), "Failed to authenticate");
test.assert_authenticated(conn, "test/user", [
    "test/group",
    { role: "readWrite", db: "test_db" },
]);

// Wait for the token to expire.
// The token expires in 1 second but wait for a bit longer to ensure that the token is expired
sleep(2200);

// Verify that the user is no longer authenticated
test.assert_not_authenticated(conn);

test.logout(conn);

test.teardown();
