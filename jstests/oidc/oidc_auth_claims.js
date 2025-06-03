import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

const idp_config = {
    token: [
        {
            payload: {
                aud: "audience",
                sub: "user",
                claim: [
                    "group1",
                    "group2",
                ],
            }
        },
        {
            payload: {
                aud: "audience",
                sub: "user",
                claim: [],
            }
        },
        {
            payload: {
                aud: "audience",
                sub: "user",
                claim: ["group3"],
            }
        },
        {
            payload: {
                aud: "audience",
                sub: "user",
                claim: "group4",
            }
        }
    ]
};

const oidcProvider = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    authorizationClaim: "claim"
};

function test_granted_roles_match_claims(clusterClass) {
    var test = new OIDCFixture(
        {oidcProviders: [oidcProvider], idps: [{url: issuer_url, config: idp_config}]});
    test.setup(clusterClass);

    test.create_role("test/group1", [{role: "readWrite", db: "test_db1"}]);
    test.create_role("test/group2", [{role: "read", db: "test_db2"}]);
    test.create_role("test/group3", [{role: "dbAdmin", db: "test_db3"}]);
    test.create_role("test/group4", [{role: "dbOwner", db: "test_db4"}]);

    var conn = test.create_conn();

    assert(test.auth(conn, "user"), "Failed to authenticate");
    test.assert_authenticated(conn, "test/user", [
        "test/group1",
        "test/group2",
        {role: "readWrite", db: "test_db1"},
        {role: "read", db: "test_db2"},
    ]);
    test.logout(conn);

    test.auth(conn, "user");
    test.assert_authenticated(conn, "test/user", []);  // empty claim
    test.logout(conn);

    test.auth(conn, "user");
    test.assert_authenticated(
        conn, "test/user", ["test/group3", {role: "dbAdmin", db: "test_db3"}]);
    test.logout(conn);

    test.auth(conn, "user");
    test.assert_authenticated(
        conn, "test/user", ["test/group4", {role: "dbOwner", db: "test_db4"}]);
    test.logout(conn);

    test.teardown();
}

test_granted_roles_match_claims(StandaloneMongod);
test_granted_roles_match_claims(ShardedCluster);
