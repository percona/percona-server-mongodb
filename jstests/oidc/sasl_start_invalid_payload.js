import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

// Test that when the payload of the saslStart command is not valid, the server rejects
// the request with an appropriate error message. The payload is expected to be a BSON
// object with a field 'n' of type string, but here we are sending an int instead.

const oidcProvider = {
    issuer: OIDCFixture.allocate_issuer_url(),
    clientId: "clientId1",
    audience: "audience1",
    authNamePrefix: "idp1",
    matchPattern: "1$",
    authorizationClaim: "claim1"
};

function test_sasl_step_1_fails_if_invalid_payload(clusterClass) {
    var test = new OIDCFixture({oidcProviders: [oidcProvider]});
    test.setup(clusterClass);

    const res = test.admin.getSiblingDB('$external').runCommand({
        saslStart: 1,
        mechanism: "MONGODB-OIDC",
        // DAAAABBuAAEAAAAA is base64 encoded bson doc: { 'n': 1 }
        payload: new BinData(0, "DAAAABBuAAEAAAAA")
    });
    assert.commandFailedWithCode(res, ErrorCodes.AuthenticationFailed);

    const expected_log = {
        msg: "Failed to authenticate",
        attr: {
            mechanism: "MONGODB-OIDC",
            error: "TypeMismatch: BSON field 'OIDCStep1Request.n' is the wrong type 'int', " +
                "expected type 'string'",
        }
    };
    assert(test.checkLogExists(expected_log), "Expected log not found");

    test.teardown();
}

test_sasl_step_1_fails_if_invalid_payload(StandaloneMongod);
test_sasl_step_1_fails_if_invalid_payload(ShardedCluster);
