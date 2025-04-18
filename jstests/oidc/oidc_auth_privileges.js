import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

var idp_config = {
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
    "cleanupStructuredEncryptionData",
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

{
    var test = new OIDCFixture({
        oidcProviders: [oidcProviderWithClaim], idps: [{ url: issuer_url, config: idp_config }]
    });

    test.setup();

    var conn = test.create_conn();

    // Authenticate and expect no privileges because no roles are created.
    assert(test.auth(conn, "user"), "Failed to authenticate");
    test.assert_authenticated(conn, "test/user", ["test/group"], []);
    test.logout(conn);

    // Create a role that inherits from built-in roles on test_db1 and test_db2.
    // When the user authenticates, the role associated with the claim should inherit
    // these roles and appropriate privileges.
    test.create_role("test/group", roles);

    // Authenticate and expect privileges to be granted.
    assert(test.auth(conn, "user"), "Failed to authenticate");
    test.assert_authenticated(conn, "test/user", expectedRolesWithClaim, expectedPrivileges);

    test.logout(conn);

    test.teardown();
}

{
    var test = new OIDCFixture({
        oidcProviders: [oidcProviderNoClaim], idps: [{ url: issuer_url, config: idp_config }]
    });

    test.setup();

    // Create user with roles.
    test.create_user("test/user", roles);

    var conn = test.create_conn();

    // Authenticate and expect privileges to be granted.
    assert(test.auth(conn, "user"), "Failed to authenticate");
    test.assert_authenticated(conn, "test/user", expectedRolesNoClaim, expectedPrivileges);

    test.logout(conn);

    test.teardown();
}
