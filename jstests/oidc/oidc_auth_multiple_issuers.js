import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer1_url = OIDCFixture.allocate_issuer_url();
const issuer2_url = OIDCFixture.allocate_issuer_url();

var idp1_config = {
    token: {
        expires_in_seconds: 2,
        payload: {
            sub: "user1",
            aud: "audience1",
            claim1: [
                "group11",
                "group12",
            ]
        }
    },
};

var idp2_config = {
    token: {
        expires_in_seconds: 2,
        payload: {
            sub: "user2",
            aud: "audience2",
            claim2: [
                "group21",
                "group22",
            ]
        }
    },
};

var oidcProviders = [
    {
        issuer: issuer1_url,
        clientId: "clientId1",
        audience: "audience1",
        authNamePrefix: "idp1",
        matchPattern: "1$",
        authorizationClaim: "claim1"
    },
    {
        issuer: issuer2_url,
        clientId: "clientId2",
        audience: "audience2",
        authNamePrefix: "idp2",
        matchPattern: "2$",
        authorizationClaim: "claim2"
    }
];

var test = new OIDCFixture({
    oidcProviders,
    idps: [
        { url: issuer1_url, config: idp1_config },
        { url: issuer2_url, config: idp2_config }
    ]
});

test.setup();

var conn = test.create_conn();

assert(test.auth(conn, "user1"), "Failed to authenticate user1");
test.get_idp(issuer1_url).assert_token_requested("clientId1");
test.assert_authenticated(conn, "idp1/user1", ["idp1/group11", "idp1/group12"]);
test.logout(conn);

assert(test.auth(conn, "user2"), "Failed to authenticate user2");
test.get_idp(issuer2_url).assert_token_requested("clientId2");
test.assert_authenticated(conn, "idp2/user2", ["idp2/group21", "idp2/group22"]);
test.logout(conn);

test.teardown();
