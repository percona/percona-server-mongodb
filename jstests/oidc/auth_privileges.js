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
        }
    },
};

const oidcProviderWithClaim = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    authorizationClaim: "claim"
};

const oidcProviderNoClaim = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    useAuthorizationClaim: false,
};

const roles = [
    { role: "readWrite", db: "test_db1" },
    { role: "read", db: "test_db2" },
]

const expectedRolesWithClaim = [
    "test/group",
    ...roles
];

const expectedRolesNoClaim = roles;

const readWriteActions = [
    "changeStream",
    "collStats",
    "compactStructuredEncryptionData",
    "convertToCapped",
    "createCollection",
    "createIndex",
    "createSearchIndexes",
    "dbHash",
    "dbStats",
    "dropCollection",
    "dropIndex",
    "dropSearchIndex",
    "find",
    "insert",
    "killCursors",
    "listCollections",
    "listIndexes",
    "listSearchIndexes",
    "updateSearchIndex",
    "planCacheRead",
    "remove",
    "renameCollectionSameDB",
    "update"
];

const readActions = [
    "changeStream",
    "collStats",
    "dbHash",
    "dbStats",
    "find",
    "killCursors",
    "listCollections",
    "listIndexes",
    "listSearchIndexes",
    "planCacheRead"
];

const expectedPrivileges = [
    {
        resource: { db: "test_db1", collection: "" },
        actions: readWriteActions,
    },
    {
        resource: { db: "test_db2", collection: "" },
        actions: readActions,
    },
];

function test_roles_and_privileges_with_auth_claim(
    clusterClass, should_create_roles, expected_roles, expected_privileges) {
    var test = new OIDCFixture({
        oidcProviders: [oidcProviderWithClaim], idps: [{ url: issuer_url, config: idp_config }]
    });
    test.setup(clusterClass);
    if (should_create_roles) {
        // Create a role that inherits from built-in roles on test_db1 and test_db2.
        // When the user authenticates, the role associated with the claim should inherit
        // these roles and appropriate privileges.
        test.create_role("test/group", roles);
    }
    var conn = test.create_conn();

    assert(test.auth(conn, "user"), "Failed to authenticate");
    test.assert_authenticated(conn, "test/user", expected_roles, expected_privileges);

    test.logout(conn);
    test.teardown();
}

function test_roles_and_privileges_without_auth_claim(clusterClass) {
    var test = new OIDCFixture({
        oidcProviders: [oidcProviderNoClaim], idps: [{ url: issuer_url, config: idp_config }]
    });

    test.setup(clusterClass);

    // Create user with roles.
    test.create_user("test/user", roles);

    var conn = test.create_conn();

    // Authenticate and expect privileges to be granted.
    assert(test.auth(conn, "user"), "Failed to authenticate");
    test.assert_authenticated(conn, "test/user", expectedRolesNoClaim, expectedPrivileges);

    test.logout(conn);

    test.teardown();
}

test_roles_and_privileges_with_auth_claim(StandaloneMongod, false, ["test/group"], []);
test_roles_and_privileges_with_auth_claim(ShardedCluster, false, ["test/group"], []);

test_roles_and_privileges_with_auth_claim(
    StandaloneMongod, true, expectedRolesWithClaim, expectedPrivileges);
test_roles_and_privileges_with_auth_claim(
    ShardedCluster, true, expectedRolesWithClaim, expectedPrivileges);

test_roles_and_privileges_without_auth_claim(StandaloneMongod);
test_roles_and_privileges_without_auth_claim(ShardedCluster);
