import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

var idp_config = {
    number_of_jwks: 2,
    token: {
        payload: {
            aud: "audience",
            sub: "user",
            claim: [
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
    authorizationClaim: "claim"
};

var variants = [
    {
        faults: {
            jwt_invalid_kid: true
        },
        expectedError: "BadValue: Invalid JWT :: caused by :: Unknown JWT keyId << 'invalid_kid'",
    },
    {
        faults: {
            jwt_missing_kid: true
        },
        expectedError: "IDLFailedToParse: Invalid JWT :: caused by :: BSON field 'JWSHeader.kid' is missing but a required field",
    },
    {
        faults: {
            jwt_invalid_key: true
        },
        expectedError: "InvalidSignature: Invalid JWT :: caused by :: OpenSSL: Signature is invalid",
    },
    {
        faults: {
            jwt_other_valid_key: true
        },
        expectedError: "InvalidSignature: Invalid JWT :: caused by :: OpenSSL: Signature is invalid",
    },
    {
        faults: {
            jwt_invalid_format: true
        },
        expectedError: "BadValue: Invalid JWT :: caused by :: parsing failed: Missing JWS delimiter"
    },
]

for (const variant of variants) {
    const issuer_url = OIDCFixture.allocate_issuer_url();

    oidcProvider.issuer = issuer_url;
    idp_config.token.faults = variant.faults;

    var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
    test.setup();
    var conn = test.create_conn();

    var idp = test.get_idp(issuer_url);
    var res = test.auth(conn, "user");

    idp.assert_config_requested();
    idp.assert_token_requested(oidcProvider.clientId);


    var expectedLog = {
        msg: "Failed to authenticate",
        attr: {
            mechanism: "MONGODB-OIDC",
            error: variant.expectedError,
        }
    };

    assert(test.checkLogExists(expectedLog), "Expected log not found for variant " + tojson(variant));

    assert(!res, "Authentication should fail for variant " + tojson(variant));

    test.teardown();
}
