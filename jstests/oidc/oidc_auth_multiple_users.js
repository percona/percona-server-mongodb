import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

var idp_config = {
    token: [
        {
            payload: {
                aud: "audience",
                sub: "user1",
                claim: [
                    "group1",
                    "group2",
                ]
            }
        },
        {
            payload: {
                aud: "audience",
                sub: "user2",
                claim: [
                    "group1",
                    "group2",
                ]
            }
        }
    ]
};

var oidcProviders = [
    {
        issuer: issuer_url,
        clientId: "clientId",
        audience: "audience",
        authNamePrefix: "idp",
        authorizationClaim: "claim"
    }
];

var test = new OIDCFixture({
    oidcProviders,
    idps: [{ url: issuer_url, config: idp_config }]
});

test.setup();

var conn = test.create_conn();

assert(test.auth(conn, "user1"), "Failed to authenticate user1");
test.assert_authenticated(conn, "idp/user1", ["idp/group1", "idp/group2"]);
test.logout(conn);

assert(test.auth(conn, "user2"), "Failed to authenticate user2");
test.assert_authenticated(conn, "idp/user2", ["idp/group1", "idp/group2"]);
test.logout(conn);

test.teardown();
