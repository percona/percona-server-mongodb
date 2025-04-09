import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const idp_port = allocatePort();
const issuer_url = "https://localhost:" + idp_port + "/issuer"


var idp_config = {
    number_of_jwks: 2,
    token: [
        {
            key_id: 0,
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
            key_id: 1,
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
        useAuthorizationClaim: true,
        requestScopes: ["offline_access"],
        supportsHumanFlows: true,
        authorizationClaim: "claim"
    },
];

var test = new OIDCFixture({
    oidcProviders,
    idps: [{ url: issuer_url, config: idp_config }]
});

test.setup();

test.auth("user1");
test.get_idp(issuer_url).assert_config_requested();
test.get_idp(issuer_url).assert_token_requested("clientId");
test.assert_authenticated("idp/user1", ["idp/group1", "idp/group2"]);
test.logout();

test.auth("user2");
test.get_idp(issuer_url).assert_config_requested();
test.get_idp(issuer_url).assert_token_requested("clientId");
test.assert_authenticated("idp/user2", ["idp/group1", "idp/group2"]);
test.logout();

test.teardown();
