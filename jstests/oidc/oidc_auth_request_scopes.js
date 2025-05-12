import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

var idp_config = {
    token:
    {
        payload: {
            aud: "audience",
            sub: "user",
            claim: [
                "group",
            ],
            scp: [
                "other_custom_scope"
            ]
        }
    },
};

const clientId = "clientId";
const requestScopes = ["custom_scope1", "custom_scope2"];

var oidcProvider = {
    issuer: issuer_url,
    clientId: clientId,
    audience: "audience",
    authNamePrefix: "test",
    authorizationClaim: "claim",
    requestScopes: requestScopes,
};

var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
test.setup();

test.create_role("test/group", [{ role: "readWrite", db: "test_db" }]);
var idp = test.get_idp(issuer_url)

var conn = test.create_conn();

assert(test.auth(conn, "user"), "Failed to authenticate");
test.assert_authenticated(conn, "test/user", [
    "test/group",
    { role: "readWrite", db: "test_db" },
]);
idp.assert_token_requested(clientId, requestScopes)
test.logout(conn);

test.teardown();
