import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

// The configuration for one issuer with multiple audiences.
// The 'matchPattern' will multiplex the audience requirement to the correct user.
// Two confiigurations use authorization claims, one does not.
var oidcProviders = [
    {
        issuer: issuer_url,
        clientId: "client1",
        audience: "audience1",
        authNamePrefix: "idp",
        matchPattern: "1$",
        authorizationClaim: "claim1" // use authorization claim
    },
    {
        issuer: issuer_url,
        clientId: "client2",
        audience: "audience2",
        authNamePrefix: "idp",
        matchPattern: "2$",
        authorizationClaim: "claim2" // use authorization claim
    },
    {
        issuer: issuer_url,
        clientId: "client3",
        audience: "audience3",
        authNamePrefix: "idp",
        matchPattern: "3$",
        useAuthorizationClaim: false, // don't use authorization claim
    }
];


// Each token is for a different user, with a different audience.
// NOTE: the claim3 is provided in the token, but not used in the configuration.
var idp_config = {
    token: [
        // Positive cases
        {
            payload: {
                sub: "user1",
                aud: "audience1",
                claim1: ["group1"]
            }
        },
        {
            payload: {
                sub: "user2",
                aud: "audience2",
                claim2: ["group2"]
            }
        },
        {
            payload: {
                sub: "user3",
                aud: "audience3",
                claim3: ["group3"]
            }
        },
        // Negative cases
        {
            payload: {
                sub: "user2",
                aud: "audience2",
                claim1: ["group3"] // wrong claim
            }
        },
        {
            payload: {
                sub: "user1",
                aud: "audience1",
                claim3: ["group1"] // wrong claim
            }
        },
        {
            payload: {
                sub: "user1",
                aud: "audience1",
                claim2: ["group1"] // wrong claim
            }
        }
    ]
};

var test = new OIDCFixture({
    oidcProviders,
    idps: [{ url: issuer_url, config: idp_config }]
});

test.setup();
test.create_role("idp/group1", [{ role: "readWrite", db: "test_db1" }]);
test.create_role("idp/group2", [{ role: "read", db: "test_db2" }]);
test.create_user('idp/user3');

const expectedRolesUser1 = ["idp/group1", { role: "readWrite", db: "test_db1" }];
const expectedRolesUser2 = ["idp/group2", { role: "read", db: "test_db2" }];

var conn = test.create_conn();

// authenticate as user1 and check the roles from claim1
test.auth(conn, "user1");
test.assert_authenticated(conn, "idp/user1", expectedRolesUser1);
test.logout(conn);

// authenticate as user2 and check the roles from claim2
test.auth(conn, "user2");
test.assert_authenticated(conn, "idp/user2", expectedRolesUser2);
test.logout(conn);

// authenticate as user3, no roles expected as no authorization claim is used
test.auth(conn, "user3");
test.assert_authenticated(conn, "idp/user3", []);
test.logout(conn);

const expectedLog = {
    msg: "Failed to authenticate",
    attr: {
        mechanism: "MONGODB-OIDC",
        error: "BadValue: Invalid JWT: Some claims are missing"
    }
};

// authenticate as user2 with wrong claim in the token
assert(!test.auth(conn, "user2"), "Authentication should fail due to invalid claim");
assert(test.checkLogExists(expectedLog), "Expected log not found for token with invalid claim");

// authenticate as user1 with wrong claim in the token
assert(!test.auth(conn, "user1"), "Authentication should fail due to invalid claim");
assert(test.checkLogExists(expectedLog), "Expected log not found for token with invalid claim");

// authenticate as user1 with wrong claim in the token
assert(!test.auth(conn, "user1"), "Authentication should fail due to invalid claim");
assert(test.checkLogExists(expectedLog), "Expected log not found for token with invalid claim");

test.teardown();
