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
    authorizationClaim: "claim",
};

const expectedRoles = [
    "test/group1",
    "test/group2",
    { role: "readWrite", db: "test_db1" },
    { role: "read", db: "test_db2" },
];

// Use refresh token to get the access token for next authentication
const create_access_token = (test) => {
    var conn = test.create_conn();
    assert(test.auth(conn, "user"), "Failed to authenticate");
    var access_token = test.refresh_token(conn);
    assert(access_token, "No access token returned");
    test.assert_authenticated(conn, "test/user", expectedRoles);

    return access_token;
}

var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
test.setup();
test.create_role("test/group1", [{ role: "readWrite", db: "test_db1" }]);
test.create_role("test/group2", [{ role: "read", db: "test_db2" }]);

var access_token = create_access_token(test);

var conn = test.create_conn();

assert(conn.auth({ mechanism: 'MONGODB-OIDC', oidcAccessToken: access_token }), "Failed to authenticate with token");
test.assert_authenticated(conn, "test/user", expectedRoles);

test.teardown();
