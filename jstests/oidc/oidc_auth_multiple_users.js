import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

const idp_config = {
    token: [
        {
            payload: {
                aud: "audience",
                sub: "user1",
                claim: [
                    "group1",
                    "group2",
                ]
            }
        },
        {
            payload: {
                aud: "audience",
                sub: "user2",
                claim: [
                    "group1",
                    "group2",
                ]
            }
        }
    ]
};

const oidcProviders = [{
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "idp",
    authorizationClaim: "claim"
}];

function assert_multiple_users_for_single_issuer(clusterClass) {
    var test = new OIDCFixture({oidcProviders, idps: [{url: issuer_url, config: idp_config}]});

    test.setup(clusterClass);
    test.create_role("idp/group1", [{role: "readWrite", db: "test_db1"}]);
    test.create_role("idp/group2", [{role: "read", db: "test_db2"}]);

    const expectedRoles = [
        "idp/group1",
        "idp/group2",
        {role: "readWrite", db: "test_db1"},
        {role: "read", db: "test_db2"},
    ];

    var conn = test.create_conn();

    assert(test.auth(conn, "user1"), "Failed to authenticate user1");
    test.assert_authenticated(conn, "idp/user1", expectedRoles);
    test.logout(conn);

    assert(test.auth(conn, "user2"), "Failed to authenticate user2");
    test.assert_authenticated(conn, "idp/user2", expectedRoles);
    test.logout(conn);

    test.teardown();
}

assert_multiple_users_for_single_issuer(StandaloneMongod);
assert_multiple_users_for_single_issuer(ShardedCluster);
