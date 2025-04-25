import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

var idp_config = {
    token: {
        payload: {
            aud: "audience",
            sub: "user",
        }
    },
};

var oidcProvider = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    useAuthorizationClaim: false,
    JWKSPollSecs: 1,
};

var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
var idp = test.get_idp(issuer_url);

test.setup();
test.create_user("test/user", [{ role: "readWrite", db: "test_db" }]);

// Wait for periodic job to fetch the JWKs
sleep(1000);
idp.assert_http_request("GET", "/keys");

// Verify that the JWKs are cached and not fetched again when authenticating
idp.clear_output();
var conn = test.create_conn();
assert(test.auth(conn, "user"), "Failed to authenticate");
test.assert_authenticated(conn, "test/user", [{ role: "readWrite", db: "test_db" }]);
idp.assert_no_http_request("GET", "/keys");
test.logout(conn);

// Verify that the JWKs are fetched again after the polling interval
idp.clear_output();
sleep(1000);
idp.assert_http_request("GET", "/keys");

// Stop the IdP and verify that an error is logged when trying to fetch JWKs
idp.clear_output();
idp.stop();
sleep(1000);

const expectedLog = {
    msg: "Failed to load JWKs from issuer",
    attr: {
        issuer: issuer_url,
        error: {
            code: 96,
            errmsg: "Failed loading keys from " + issuer_url +
                " :: caused by :: Bad HTTP response from API server: Couldn't connect to server",
        },
    },
}
assert(test.checkLogExists(expectedLog), "Expected log message not found");

// Start the IdP and verify that the JWKs are fetched again after the polling period
idp.clear_output();
idp.start();
sleep(1000);
idp.assert_http_request("GET", "/keys");

test.teardown();
