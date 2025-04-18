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
                    "group3",
                    "group4",
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

var conn1 = test.create_conn();
var conn2 = test.create_conn();

test.auth(conn1, "user1");
test.assert_authenticated(conn1, "idp/user1", ["idp/group1", "idp/group2"]);

test.auth(conn2, "user2");
test.assert_authenticated(conn2, "idp/user2", ["idp/group3", "idp/group4"]);

test.logout(conn1);
test.logout(conn2);

test.teardown();
