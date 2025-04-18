import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

// BQAAAAAA is base64 encoded [05 00 00 00 00 00] which is an empty BSON object
const EmptyBSONPayload = new BinData(0, "BQAAAAAA");

// Function to convert hex string to printable ASCII string
// Helps with performing visual inspection of the payload
function hexToPrintableString(hex) {
    let result = '';
    for (let i = 0; i < hex.length; i += 2) {
        const byte = parseInt(hex.substr(i, 2), 16);
        result += (byte >= 32 && byte < 127) ? String.fromCharCode(byte) : '.';
    }
    return result;
}

{
    // Test that when multiple identity providers are configured, the server rejects the request
    // with no principal name in saslStart command (payload is empty BSON object).
    // The error message should indicate that a principal name is required to choose an identity provider.
    var oidcProviders = [
        {
            issuer: OIDCFixture.allocate_issuer_url(),
            clientId: "clientId1",
            audience: "audience1",
            authNamePrefix: "idp1",
            matchPattern: "1$",
            authorizationClaim: "claim1"
        },
        {
            issuer: OIDCFixture.allocate_issuer_url(),
            clientId: "clientId2",
            audience: "audience2",
            authNamePrefix: "idp2",
            matchPattern: "2$",
            authorizationClaim: "claim2"
        }
    ];

    var test = new OIDCFixture({ oidcProviders: oidcProviders });
    test.setup();

    const res = test.admin.getSiblingDB('$external').runCommand(
        {
            saslStart: 1,
            mechanism: "MONGODB-OIDC",
            payload: EmptyBSONPayload,
        }
    );
    assert.commandFailedWithCode(res, ErrorCodes.AuthenticationFailed);
    OIDCFixture.assert_mongod_output_match("BadValue: Multiple identity providers are known, provide a principal name for choosing a one")
    test.teardown();
}

{
    // Test that when a single identity provider is configured, the server accepts the request
    // with no principal name in saslStart command (payload is empty BSON object).
    var oidcProvider = {
        issuer: OIDCFixture.allocate_issuer_url(),
        clientId: "clientId1",
        audience: "audience1",
        authNamePrefix: "idp1",
        matchPattern: "1$",
        authorizationClaim: "claim1"
    };

    var test = new OIDCFixture({ oidcProviders: [oidcProvider] });
    test.setup();

    const res = test.admin.getSiblingDB('$external').runCommand(
        {
            saslStart: 1,
            mechanism: "MONGODB-OIDC",
            payload: EmptyBSONPayload,
        }
    );

    assert.commandWorked(res);

    // Verify that the payload contains the exppected fields
    // with issuer and clientId.
    // NOTE: Since there is no built-in method to decode raw BSON
    // into a JavaScrip object, use a workaround to convert the binary data
    // into printable ASCII string for visual inspection.
    const payload = hexToPrintableString(res.payload.hex());
    assert(payload.includes("issuer"));
    assert(payload.includes(oidcProvider.issuer));
    assert(payload.includes("clientId"));
    assert(payload.includes(oidcProvider.clientId));

    test.teardown();
}
