import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const issuer1_url = OIDCFixture.allocate_issuer_url();
const issuer2_url = OIDCFixture.allocate_issuer_url();

const idp1_config = {
    token: {
        expires_in_seconds: 2,
        payload: {
            sub: "user1",
            aud: "audience1",
            claim1: [
                "group11",
                "group12",
            ]
        }
    },
};

const idp2_config = {
    token: {
        expires_in_seconds: 2,
        payload: {
            sub: "user2",
            aud: "audience2",
            claim2: [
                "group21",
                "group22",
            ]
        }
    },
};

const oidcProviders = [
    {
        issuer: issuer1_url,
        clientId: "clientId1",
        audience: "audience1",
        authNamePrefix: "idp1",
        matchPattern: "1$",
        authorizationClaim: "claim1"
    },
    {
        issuer: issuer2_url,
        clientId: "clientId2",
        audience: "audience2",
        authNamePrefix: "idp2",
        matchPattern: "2$",
        authorizationClaim: "claim2"
    }
];

function test_multiple_issuers(clusterClass) {
    var test = new OIDCFixture({
        oidcProviders,
        idps: [{url: issuer1_url, config: idp1_config}, {url: issuer2_url, config: idp2_config}]
    });

    test.setup(clusterClass);
    test.create_role("idp1/group11", [{role: "readWrite", db: "test_db11"}]);
    test.create_role("idp1/group12", [{role: "read", db: "test_db12"}]);
    test.create_role("idp2/group21", [{role: "readWrite", db: "test_db21"}]);
    test.create_role("idp2/group22", [{role: "read", db: "test_db22"}]);

    const expectedRolesUser1 = [
        "idp1/group11",
        "idp1/group12",
        {role: "readWrite", db: "test_db11"},
        {role: "read", db: "test_db12"}
    ];

    const expectedRolesUser2 = [
        "idp2/group21",
        "idp2/group22",
        {role: "readWrite", db: "test_db21"},
        {role: "read", db: "test_db22"}
    ];

    var conn = test.create_conn();

    assert(test.auth(conn, "user1"), "Failed to authenticate user1");
    test.get_idp(issuer1_url).assert_token_requested("clientId1");
    test.assert_authenticated(conn, "idp1/user1", expectedRolesUser1);
    test.logout(conn);

    assert(test.auth(conn, "user2"), "Failed to authenticate user2");
    test.get_idp(issuer2_url).assert_token_requested("clientId2");
    test.assert_authenticated(conn, "idp2/user2", expectedRolesUser2);
    test.logout(conn);

    assert(!test.auth(conn, "user3"), "Authentication should fail");
    const expectedLog = {
        msg: "Failed to authenticate",
        attr: {
            mechanism: "MONGODB-OIDC",
            error: "BadValue: No identity provider found for principal name `user3`"
        }
    };

    assert(test.checkLogExists(expectedLog), "Expected log not found");

    test.teardown();
}

test_multiple_issuers(StandaloneMongod);
test_multiple_issuers(ShardedCluster);
