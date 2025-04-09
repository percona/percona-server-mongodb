
import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

var idp_config = {
    token: {
        expires_in_seconds: 2,
        payload: {
            aud: "audience",
            sub: "user",
            MyClaim: [
                "group1",
                "group2",
            ]
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
    authorizationClaim: "MyClaim"
};

var variants = [
    {
        faults: {
            jwt_invalid_kid: true
        },
        expectSuccess: true, // TODO: This should be false
    },
    {
        faults: {
            jwt_missing_kid: true
        },
        expectSuccess: true, // TODO: This should be false
    },
    {
        faults: {
            jwt_invalid_key: true
        },
        expectSuccess: true, // TODO: This should be false
    },
]

for (const variant of variants) {
    const idp_port = allocatePort();
    const issuer_url = "https://localhost:" + idp_port + "/issuer"

    oidcProvider.issuer = issuer_url;
    idp_config.faults = variant.faults;

    var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
    test.setup();

    var idp = test.get_idp(issuer_url);
    var res = test.auth("user");

    idp.assert_config_requested();
    idp.assert_token_requested(oidcProvider.clientId, oidcProvider.requestScopes);

    if (variant.expectedLog) {
        assert(test.checkLogExists(variant.expectedLog), "Expected log not found for variant " + tojson(variant));
    }

    if (variant.expectSuccess) {
        assert(res, "Authentication should succeed for variant " + tojson(variant));
    }
    else {
        assert(!res, "Authentication should fail for variant " + tojson(variant));
    }

    test.teardown();
}
