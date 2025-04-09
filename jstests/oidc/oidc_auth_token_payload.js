import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

var idp_config_base = {
    token: {
        payload: {
        }
    },
};

var oidcProvider =
{
    issuer: "",
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    useAuthorizationClaim: true,
    requestScopes: ["offline_access"],
    supportsHumanFlows: true,
    authorizationClaim: "claim"
};

var variants = [
    {
        // Empty payload
        payload: {},
        expectedLog: {
            id: 5286307,
        }
    },
    {
        // Missing 'sub'
        payload: {
            aud: "audience",
            claim: [
                "group1",
                "group2",
            ],
        },
        expectedLog: {
            id: 5286307,
        }
    },
    {
        // Missing 'aud'
        payload: {
            sub: "user",
            claim: [
                "group1",
                "group2",
            ],
        },
        expectedLog: {
            id: 5286307,
        }
    },
    {
        // Missing 'claim'
        payload: {
            sub: "user",
            aud: "audience",
        },
        expectedLog: {
            id: 5286307,
        }
    },
    {
        // Missing 'iss'
        payload: {
            sub: "user",
            aud: "audience",
            iss: null,
            claim: [
                "group1",
                "group2",
            ],
        },
        expectedLog: {
            id: 5286307,
        }
    },
    // { // TODO: clarify if this is a valid case
    //     // Missing 'iat'
    //     payload: {
    //         sub: "user",
    //         aud: "audience",
    //         iat: null,
    //         claim: [
    //             "group1",
    //             "group2",
    //         ],
    //     },
    //     expectedLog: {
    //         id: 5286307,
    //     }
    // },
    // { // TODO: clarify if this is a valid case
    //     // Missing 'exp'
    //     payload: {
    //         sub: "user",
    //         aud: "audience",
    //         exp: null,
    //         claim: [
    //             "group1",
    //             "group2",
    //         ],
    //     },
    //     expectedLog: {
    //         id: 5286307,
    //     }
    // },
    // { // TODO: clarify if this is a valid case
    //     // Empty 'claim'
    //     payload: {
    //         sub: "user",
    //         aud: "audience",
    //         claim: [],
    //     },
    //     expectedLog: {
    //         id: 5286307,
    //     }
    // },
]

for (const variant of variants) {
    const idp_port = allocatePort();
    const issuer_url = "https://localhost:" + idp_port + "/issuer"

    oidcProvider.issuer = issuer_url;
    var idp_config = idp_config_base;
    idp_config.token.payload = variant.payload;

    var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
    test.setup();

    var idp = test.get_idp(issuer_url);
    var res = test.auth("user");
    print("OIDCFixture.assert_authenticated: ", JSON.stringify(test.authInfo()));

    idp.assert_config_requested();
    idp.assert_token_requested(oidcProvider.clientId, oidcProvider.requestScopes);

    if (variant.expectedLog) {
        assert(test.checkLogExists(variant.expectedLog), "Expected log not found for variant " + tojson(variant));
    }

    assert(!res, "Authentication should fail for variant " + tojson(variant));

    test.teardown();

    test = null;
}
