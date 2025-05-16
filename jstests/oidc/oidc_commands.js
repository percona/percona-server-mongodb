import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

var oidcProvider =
{
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    useAuthorizationClaim: false,
};

var idp_config = {
    number_of_jwks: 3,
    token: [
        {
            payload: {
                aud: "audience",
                sub: "user",
            }
        },
        {
            payload: {
                aud: "audience",
                sub: "admin",
            }
        },
        {
            payload: {
                aud: "audience",
                sub: "user",
            }
        },
        {
            payload: {
                aud: "audience",
                sub: "admin",
            }
        },
    ]
};

var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
test.setup();

test.create_user("test/user", [{ role: "readWrite", db: "test_db" }]);
test.create_user("test/admin", [{ role: "root", db: "admin" }]);

const commands = assert.commandWorked(test.admin.runCommand({ listCommands: 1 }), "listCommands should work").commands;

const verifyCommand = (name, command) => {
    // verify basic command properties
    assert(command, `${name} command should exist`);
    assert(command.help, `${name} command should have help`);
    assert(command.requiresAuth, `${name} command should require auth`);
    assert(command.adminOnly, `${name} command should be admin only command`);
    assert(command.secondaryOk, `${name} command should have secondaryOk=true`);

    var conn = test.create_conn();
    const runCommandParam = { [name]: 1 };

    // expect the command to fail without auth
    assert.commandFailedWithCode(conn.getDB("admin").runCommand(runCommandParam), ErrorCodes.Unauthorized, `${name} command should fail without auth`);

    // expect the command to fail without authorization on admin db
    assert(test.auth(conn, "user"), "Failed to authenticate");
    test.assert_authenticated(conn, "test/user", [{ role: "readWrite", db: "test_db" }]);
    assert.commandFailedWithCode(conn.getDB("admin").runCommand(runCommandParam), ErrorCodes.Unauthorized, `${name} command should fail with auth but not with authz on admin`);

    // expect the command to work when run as admin
    var adminConn = test.create_conn();
    assert(test.auth(adminConn, "admin"), "Failed to authenticate");
    test.assert_authenticated(adminConn, "test/admin", [{ role: "root", db: "admin" }]);
    assert.commandWorked(adminConn.getDB("admin").runCommand(runCommandParam), `${name} command should work`);
};

// check all the OIDC related commands
verifyCommand("oidcListKeys", commands.oidcListKeys);
verifyCommand("oidcRefreshKeys", commands.oidcRefreshKeys);

test.teardown();
