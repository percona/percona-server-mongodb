import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

const idp_config = {
    token: {
        payload: {
            aud: "audience",
            sub: "user",
            claim: [
                "/absolute/path/to/group1",
                "/group2",
            ],
        }
    },
};

const oidcProvider = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "auth_prefix",
    authorizationClaim: "claim"
};

function test_no_double_slash_in_role_name(clusterClass) {
    var test = new OIDCFixture(
        {oidcProviders: [oidcProvider], idps: [{url: issuer_url, config: idp_config}]});
    test.setup(clusterClass);

    test.create_role("auth_prefix/absolute/path/to/group1", [{role: "readWrite", db: "test_db1"}]);
    test.create_role("auth_prefix/group2", [{role: "read", db: "test_db2"}]);

    var conn = test.create_conn();

    assert(test.auth(conn, "user"), "Failed to authenticate");
    test.assert_authenticated(conn, "auth_prefix/user", [
        "auth_prefix/absolute/path/to/group1",
        "auth_prefix/group2",
        {role: "readWrite", db: "test_db1"},
        {role: "read", db: "test_db2"},
    ]);
    test.logout(conn);

    test.teardown();
}

test_no_double_slash_in_role_name(StandaloneMongod);
test_no_double_slash_in_role_name(ShardedCluster);
