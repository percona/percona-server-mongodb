import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const oidcProviderBase = {
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    authorizationClaim: "claim"
};

const variants = [
    {
        // Empty payload
        payload: {},
        expectedError: "parsing failed: BSON field 'JWT.aud' is missing but a required field",
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
        expectedError: "parsing failed: BSON field 'JWT.sub' is missing but a required field",
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
        expectedError: "parsing failed: BSON field 'JWT.aud' is missing but a required field",
    },
    {
        // Missing 'claim'
        payload: {
            sub: "user",
            aud: "audience",
        },
        expectedError: "authorizationClaim 'claim' is missing",
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
        expectedError: "parsing failed: BSON field 'JWT.iss' is missing but a required field",
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
        expectedError: "parsing failed: BSON field 'JWT.exp' is missing but a required field",
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
        expectedError: "authorizationClaim `claim` is neither a string nor an array of strings",
    },
    {
        // Invalid type of sub
        payload: {
            sub: ["user"],
            aud: "audience",
            claim: "group",
        },
        expectedError:
            "parsing failed: BSON field 'JWT.sub' is the wrong type 'array', expected type 'string'",
    },
    {
        // Expired token
        payload: {
            sub: "user",
            aud: "audience",
            exp: Math.floor(Date.now() / 1000) - 1000,
            claim: "group",
        },
        expectedError: "Token is expired",
    },
    {
        // Not yet valid token
        payload: {
            sub: "user",
            aud: "audience",
            nbf: Math.floor(Date.now() / 1000) + 1000,
            claim: "group",
        },
        expectedError: "Token not yet valid",
    },
];

function test_auth_fails(clusterClass, tokenPayload, expectedError) {
    const issuer_url = OIDCFixture.allocate_issuer_url();
    const oidcProvider = Object.assign({issuer: issuer_url}, oidcProviderBase);
    const idp_config = {token: {payload: tokenPayload}};

    var test = new OIDCFixture(
        {oidcProviders: [oidcProvider], idps: [{url: issuer_url, config: idp_config}]});
    test.setup(clusterClass);

    var conn = test.create_conn();

    var res = test.auth(conn, "user");

    var expectedLog = {
        msg: "Failed to authenticate",
        attr: {
            mechanism: "MONGODB-OIDC",
            error: "BadValue: Invalid JWT :: caused by :: " + expectedError,
        }
    };

    assert(test.checkLogExists(expectedLog), "Expected log not found: " + tojson(expectedLog));

    assert(!res, "Authentication should fail for token payload " + tojson(tokenPayload));

    test.teardown();

    test = null;
}

for (const variant of variants) {
    test_auth_fails(StandaloneMongod, variant.payload, variant.expectedError);
    test_auth_fails(ShardedCluster, variant.payload, variant.expectedError);
}
