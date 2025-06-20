import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

const idp_config = {
    token: {
        payload: {
            aud: "audience",
            sub: "user",
            claim: [
                "group",
            ],
            custom_claim: {
                some_array: [
                    "element1",
                    "element2",
                ],
                some_field: "value",
            },
            email: "test@test.com",
        }
    },
};

const oidcProviderBase = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    authorizationClaim: "claim"
};

const variants = [
    // expect 'iss' and 'sub' by default
    {
        logClaims: null,
        expectedLogClaims: {
            iss: issuer_url,
            sub: "user",
        }
    },
    // no claims
    {
        logClaims: [],
        expectedLogClaims: {},
    },
    // specific claims
    {
        logClaims: ["email", "custom_claim"],
        expectedLogClaims: {
            email: "test@test.com",
            custom_claim: {
                some_array: [
                    "element1",
                    "element2",
                ],
                some_field: "value",
            },
        },
    },
    // non-existing claims
    {
        logClaims: ["non_existing_claim"],
        expectedLogClaims: {},
    },
];

function test_claims_are_logged(clusterClass, configuredLogClaims, expectedLogClaims) {
    let oidcProvider = Object.assign({}, oidcProviderBase);

    if (configuredLogClaims) {
        oidcProvider.logClaims = configuredLogClaims;
    }

    var test = new OIDCFixture(
        {oidcProviders: [oidcProvider], idps: [{url: issuer_url, config: idp_config}]});
    test.setup(clusterClass, /* with_audit = */ true);

    test.create_role("test/group", [{ role: "readWrite", db: "test_db" }]);

    var conn = test.create_conn();

    assert(test.auth(conn, "user"), "Failed to authenticate");

    test.assert_authenticated(conn, "test/user", [
        "test/group",
        { role: "readWrite", db: "test_db" },
    ]);

    const expectedLog = {
        atype: "authenticate",
        param: {
            claims: expectedLogClaims,
        }
    };

    sleep(1000); // Wait for the audit log to be flushed

    const auditLog = test.checkAuditLogExists(expectedLog);
    assert(auditLog, "No audit log for successful authentication");

    const loggedClaims = Object.keys(auditLog.param.claims);
    const expectedClaims = Object.keys(expectedLogClaims);

    assert(loggedClaims.length <= expectedClaims.length, "Too many claims in the audit log");

    for (const claim of loggedClaims) {
        assert(JSON.stringify(expectedLogClaims[claim]) ===
                   JSON.stringify(auditLog.param.claims[claim]),
               `Claim ${claim} does not match`);
    }

    test.teardown();
}

for (const variant of variants) {
    test_claims_are_logged(StandaloneMongod, variant.logClaims, variant.expectedLogClaims);
    test_claims_are_logged(ShardedCluster, variant.logClaims, variant.expectedLogClaims);
}
