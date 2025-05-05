import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';


// Test that when the payload of the saslStart command is not valid, the server rejects
// the request with an appropriate error message. The payload is expected to be a BSON
// object with a field 'n' of type string, but here we are sending an int instead.

var oidcProvider = {
    issuer: OIDCFixture.allocate_issuer_url(),
    clientId: "clientId1",
    audience: "audience1",
    authNamePrefix: "idp1",
    matchPattern: "1$",
    authorizationClaim: "claim1"
};

// BQAAAAAA is base64 encoded [05 00 00 00 00 00] which is an empty BSON object
const EmptyBSONPayload = new BinData(0, "BQAAAAAA");

var test = new OIDCFixture({ oidcProviders: [oidcProvider] });


const invalid_step2_payload = [
    {
        payload: EmptyBSONPayload,
        expectedError: "IDLFailedToParse: BSON field 'OIDCStep2Request.jwt' is missing but a required field",
    },
    {
        // DgAAABBqd3QAAQAAAAA is base64 encoded bson doc: { 'n': 'user' }
        // which is a valid payload for saslStart, but not for saslContinue
        payload: new BinData(0, "EQAAAAJuAAUAAAB1c2VyAAA="),
        expectedError: "IDLFailedToParse: BSON field 'OIDCStep2Request.jwt' is missing but a required field",
    },
    {

        // DgAAABBqd3QAAQAAAAA is base64 encoded bson doc: { 'jwt': 1 }
        payload: new BinData(0, "DgAAABBqd3QAAQAAAAA="),
        expectedError: "TypeMismatch: BSON field 'OIDCStep2Request.jwt' is the wrong type 'int', expected type 'string'"
    },
];

const run_saslStart = function () {
    return test.admin.getSiblingDB('$external').runCommand(
        {
            saslStart: 1,
            mechanism: "MONGODB-OIDC",
            payload: EmptyBSONPayload
        }
    );
}

const run_saslContinue = function (conversationId, payload) {
    return test.admin.getSiblingDB('$external').runCommand(
        {
            saslContinue: 1,
            conversationId: NumberInt(conversationId),
            payload: payload,
        }
    );
}

test.setup();

for (const variant of invalid_step2_payload) {
    const res1 = run_saslStart();
    assert.commandWorked(res1, "Expected saslStart to succeed");
    assert(res1.conversationId, "Expected conversationId to be present in saslStart response");



    const res2 = run_saslContinue(res1.conversationId, variant.payload);
    assert.commandFailedWithCode(res2, ErrorCodes.AuthenticationFailed, "Expected saslContinue to fail for variant:" + tojson(variant));

    const expectedLog = {
        msg: "Failed to authenticate",
        attr: {
            mechanism: "MONGODB-OIDC",
            error: variant.expectedError,
        }
    };

    assert(test.checkLogExists(expectedLog), "Expected log not found for variant " + tojson(variant));
}

test.teardown();
