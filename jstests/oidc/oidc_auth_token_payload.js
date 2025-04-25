import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

var idp_config_base = {
    token: {
        payload: {}
    }
};

var oidcProvider =
{
    issuer: "",
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    authorizationClaim: "claim"
};

const variants = [
    {
        // Empty payload
        payload: {},
        expectedError: "BadValue: Invalid JWT :: caused by :: parsing failed: BSON field 'JWT.aud' is missing but a required field",
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
        expectedError: "BadValue: Invalid JWT :: caused by :: parsing failed: BSON field 'JWT.sub' is missing but a required field",
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
        expectedError: "BadValue: Invalid JWT :: caused by :: parsing failed: BSON field 'JWT.aud' is missing but a required field",
    },
    {
        // Missing 'claim'
        payload: {
            sub: "user",
            aud: "audience",
        },
        expectedError: "BadValue: Invalid JWT :: caused by :: authorizationClaim 'claim' is missing",
    },
    {
        // Missing 'iss'
        payload: {
            sub: "user",
            aud: "audience",
            iss: "$remove",
            claim: [
                "group1",
                "group2",
            ],
        },
        expectedError: "BadValue: Invalid JWT :: caused by :: parsing failed: BSON field 'JWT.iss' is missing but a required field",
    },
    {
        // Missing 'exp'
        payload: {
            sub: "user",
            aud: "audience",
            exp: "$remove",
            claim: [
                "group1",
                "group2",
            ],
        },
        expectedError: "BadValue: Invalid JWT :: caused by :: parsing failed: BSON field 'JWT.exp' is missing but a required field",
    },
    {
        // Invalid type of claim
        payload: {
            sub: "user",
            aud: "audience",
            claim: {
                some_field: "group1",
            },
        },
        expectedError: "BadValue: Invalid JWT :: caused by :: authorizationClaim `claim` is neither a string nor an array of strings",
    },
    {
        // Invalid type of sub
        payload: {
            sub: ["user"],
            aud: "audience",
            claim: "group",
        },
        expectedError: "BadValue: Invalid JWT :: caused by :: parsing failed: BSON field 'JWT.sub' is the wrong type 'array', expected type 'string'",
    },
    {
        // Expired token
        payload: {
            sub: "user",
            aud: "audience",
            exp: Math.floor(Date.now() / 1000) - 1000,
            claim: "group",
        },
        expectedError: "BadValue: Invalid JWT :: caused by :: Token is expired",
    },
    {
        // Not yet valid token
        payload: {
            sub: "user",
            aud: "audience",
            nbf: Math.floor(Date.now() / 1000) + 1000,
            claim: "group",
        },
        expectedError: "BadValue: Invalid JWT :: caused by :: Token not yet valid",
    },
];

for (const variant of variants) {
    const issuer_url = OIDCFixture.allocate_issuer_url();

    oidcProvider.issuer = issuer_url;
    var idp_config = idp_config_base;
    idp_config.token.payload = variant.payload;

    var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
    test.setup();

    var conn = test.create_conn();

    var res = test.auth(conn, "user");

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

    test = null;
}
