import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

var idp_config = {
    token: {
        payload: {
            aud: "audience",
            sub: "user",
            claim: [
                "group1",
                "group2",
            ],
        },
    },
};

var oidcProvider = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    requestScopes: ["offline_access"],
    authorizationClaim: "claim"
};

var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
test.setup();
test.create_role("test/group1", [{ role: "readWrite", db: "test_db1" }]);
test.create_role("test/group2", [{ role: "read", db: "test_db2" }]);

const expectedRoles = [
    "test/group1",
    "test/group2",
    { role: "readWrite", db: "test_db1" },
    { role: "read", db: "test_db2" },
];
var conn = test.create_conn();

var idp = test.get_idp(issuer_url);

assert(test.auth(conn, "user"), "Failed to authenticate");
idp.assert_config_requested();
idp.assert_token_requested(oidcProvider.clientId, oidcProvider.requestScopes);
test.assert_authenticated(conn, "test/user", expectedRoles);
idp.clear_output();

sleep(200);

assert(test.refresh_token(conn), "No access token returned");
idp.assert_token_refresh_requested(oidcProvider.clientId);
test.assert_authenticated(conn, "test/user", expectedRoles);
test.teardown();
