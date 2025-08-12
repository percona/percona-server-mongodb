import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();
const oidcProvider = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    useAuthorizationClaim: true,
    authorizationClaim: "claim"
};

const variants = [
    {
        faults: {jwt_invalid_kid: true},
        expectedError: "BadValue: Invalid JWT :: caused by :: Unknown JWT keyId << 'invalid_kid'",
    },
    {
        faults: {jwt_missing_kid: true},
        expectedError: "IDLFailedToParse: Invalid JWT :: caused by :: " +
            "BSON field 'JWSHeader.kid' is missing but a required field",
    },
    {
        faults: {jwt_invalid_key: true},
        expectedError:
            "InvalidSignature: Invalid JWT :: caused by :: OpenSSL: Signature is invalid",
    },
    {
        faults: {jwt_other_valid_key: true},
        expectedError:
            "InvalidSignature: Invalid JWT :: caused by :: OpenSSL: Signature is invalid",
    },
    {
        faults: {jwt_invalid_format: true},
        expectedError:
            "BadValue: Invalid JWT :: caused by :: parsing failed: invalid base64",
    },
];

function test_auth_fails(clusterClass, faults, expectedError) {
    const idp_config = {
        number_of_jwks: 2,
        token: {
            payload: {
                aud: "audience",
                sub: "user",
                claim: [
                    "group1",
                    "group2",
                ]
            },
            faults: faults,
        },
    };

    var test = new OIDCFixture(
        {oidcProviders: [oidcProvider], idps: [{url: issuer_url, config: idp_config}]});
    test.setup(clusterClass);
    var conn = test.create_conn();

    var idp = test.get_idp(issuer_url);
    var res = test.auth(conn, "user");

    idp.assert_config_requested();
    idp.assert_token_requested(oidcProvider.clientId);

    var expectedLog = {
        msg: "Failed to authenticate",
        attr: {
            mechanism: "MONGODB-OIDC",
            error: expectedError,
        }
    };

    assert(test.checkLogExists(expectedLog), "Expected log not found: " + tojson(expectedLog));

    assert(!res, "Authentication should fail for faults " + tojson(faults));

    test.teardown();
}

for (const variant of variants) {
    test_auth_fails(StandaloneMongod, variant.faults, variant.expectedError);
    test_auth_fails(ShardedCluster, variant.faults, variant.expectedError);
}
