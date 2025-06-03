import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

const idp_config = {
    token: {
        payload: {
            aud: "audience",
            sub: "user",
            custom_claim: "custom_username",
            claim: [
                "group1",
                "group2",
            ],
        }
    },
};

const oidcProviderBase = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    principalName: "custom_claim",
    authorizationClaim: "claim",
};

function test_auth_succeeds_with_custom_principal_name_and_auth_claim_disabled(clusterClass) {
    // don't use auth claims
    const oidcProvider = Object.assign(oidcProviderBase, {useAuthorizationClaim: false});

    var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
    test.setup(clusterClass);
    test.create_user("test/custom_username", [{ role: "readWrite", db: "test_db" }]);

    var conn = test.create_conn();

    assert(test.auth(conn, "custom_username"), "Failed to authenticate");
    // verify user is authenticated with no roles
    test.assert_authenticated(conn, "test/custom_username", [{ role: "readWrite", db: "test_db" }]);

    test.teardown();
}

function test_auth_succeeds_with_custom_principal_name_and_auth_claim_enabled(clusterClass) {
    // use auth claims
    const oidcProvider = Object.assign(oidcProviderBase, {useAuthorizationClaim: true});

    var test = new OIDCFixture(
        {oidcProviders: [oidcProvider], idps: [{url: issuer_url, config: idp_config}]});
    test.setup(clusterClass);
    test.create_role("test/group1", [{ role: "readWrite", db: "test_db1" }]);
    test.create_role("test/group2", [{ role: "read", db: "test_db2" }]);

    const expectedRoles = [
        "test/group1",
        "test/group2",
        { role: "readWrite", db: "test_db1" },
        { role: "read", db: "test_db2" },
    ];

    var conn = test.create_conn();

    assert(test.auth(conn, "custom_username"), "Failed to authenticate");
    // verify user is authenticated with correct roles
    test.assert_authenticated(conn, "test/custom_username", expectedRoles);

    test.teardown();
}

function test_auth_succeeds_with_default_principal_name_and_auth_claim_disabled(clusterClass) {
    // set default principal value
    // don't use auth claims
    const oidcProvider =
        Object.assign(oidcProviderBase, {principalName: "sub", useAuthorizationClaim: false});

    var test = new OIDCFixture(
        {oidcProviders: [oidcProvider], idps: [{url: issuer_url, config: idp_config}]});
    test.setup(clusterClass);
    test.create_user("test/user", [{ role: "readWrite", db: "test_db" }]);

    var conn = test.create_conn();

    assert(test.auth(conn, "user"), "Failed to authenticate");
    // verify user is authenticated with correct roles
    test.assert_authenticated(conn, "test/user", [{ role: "readWrite", db: "test_db" }]);

    test.teardown();
}

function test_auth_fails_with_missing_principla_name_claim(clusterClass) {
    // use auth claims
    const oidcProvider = Object.assign(
        oidcProviderBase, {principalName: "some_other_custom_claim", useAuthorizationClaim: true});

    var test = new OIDCFixture(
        {oidcProviders: [oidcProvider], idps: [{url: issuer_url, config: idp_config}]});
    test.setup(clusterClass);

    var conn = test.create_conn();

    assert(!test.auth(conn, "user"),
           "Authentication should fail due to missing claim for principalName");

    test.teardown();
}

test_auth_succeeds_with_custom_principal_name_and_auth_claim_disabled(StandaloneMongod);
test_auth_succeeds_with_custom_principal_name_and_auth_claim_disabled(ShardedCluster);

test_auth_succeeds_with_custom_principal_name_and_auth_claim_enabled(StandaloneMongod);
test_auth_succeeds_with_custom_principal_name_and_auth_claim_enabled(ShardedCluster);

test_auth_succeeds_with_default_principal_name_and_auth_claim_disabled(StandaloneMongod);
test_auth_succeeds_with_default_principal_name_and_auth_claim_disabled(ShardedCluster);

test_auth_fails_with_missing_principla_name_claim(StandaloneMongod);
test_auth_fails_with_missing_principla_name_claim(ShardedCluster);
