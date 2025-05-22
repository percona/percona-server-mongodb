import { OIDCIdPMock } from 'jstests/oidc/lib/oidc_idp_mock.js';

Random.setRandomSeed();

/**
 * Helper function to check if the expected log matches the actual log.
 *
 * @param {object} expectedLog - The expected log object to compare against.
 * @param {object} element - The actual log object to compare with.
 * @returns {boolean} - Returns true if the expected log matches the actual log, false otherwise.
 */
function checkExpectedLog(expectedLog, element) {
    if (typeof expectedLog !== "object" || expectedLog === null) {
        // If expectedLog is not an object, perform a direct comparison
        return expectedLog === element;
    }

    if (typeof element !== "object" || element === null) {
        // If element is not an object, it cannot match expectedLog
        return false;
    }

    // Check each key in expectedLog
    for (const key in expectedLog) {
        if (!element.hasOwnProperty(key)) {
            // Key is missing in element
            return false;
        }

        // Recursively check nested objects
        if (!checkExpectedLog(expectedLog[key], element[key])) {
            return false;
        }
    }

    return true;
}

/**
 * OIDCFixture class
 *
 * This class is used to set up and manage the OIDC fixture for testing.
 *
 * See README.md for example usage.
 */
export class OIDCFixture {
    /**
     * Constructor for the OIDCFixture class.
     *
     * @param {object} oidcProviders - The OIDC providers configuration object for mongod.
     * @param {object} idps - The IdP configuration object for the OIDC IdP mock.
     * @param {function} client_callback - The callback function to handle authentication callbacks on the client side.
     */
    constructor({ oidcProviders, idps, client_callback }) {
        this.idps = {};
        this.client_callback = client_callback;
        if (idps) {
            for (const idp_config of idps) {
                assert(idp_config, "Missing idp_config");
                assert(idp_config.url, "Missing idp_config.url");
                assert(idp_config.config, "Missing idp_config.config");

                this.create_idp(idp_config.url, idp_config.config);
            }
        }

        this.oidc_providers = oidcProviders;
        this.admin_conn = null;
        this.admin = null;
        this.last_log_date = new Date();
        this.last_audit_log_date = new Date();
        this.audit_path = null;
    }

    /**
     * Allocate a unique audit path for the audit log.
     *
     * @returns {string} - The allocated audit path.
     */
    static allocate_audit_path() {
        return MongoRunner.dataPath + "audit_log_" + Random.rand().toString() + ".json";
    }

    /**
     * Allocate a unique issuer URL.
     *
     * @param {string} issuer_name - The name of the issuer (default: "issuer").
     * @returns {string} - The allocated issuer URL.
     */
    static allocate_issuer_url(issuer_name = "issuer") {
        return "https://localhost:" + allocatePort() + "/" + issuer_name;
    }

    /**
     * Create the options object for the MongoDB server.
     *
     * @param {object} oidcProviders - The OIDC providers configuration object for mongod.
     * @param {string} auditPath - The path to the audit log file (optional).
     *                            If not provided, audit logging will be disabled.
     * @returns {object} - The options object for the MongoDB server.
     */
    static create_options(oidcProviders, auditPath = null) {
        let config = {
            auth: "",
            setParameter: {
                authenticationMechanisms: "SCRAM-SHA-256,MONGODB-OIDC",
                oidcIdentityProviders: JSON.stringify(oidcProviders),
                JWKSMinimumQuiescePeriodSecs: 0, // Disable JWKS quiesce period for testing
            }
        };

        if (auditPath) {
            config = Object.merge(config, {
                auditDestination: "file",
                auditFormat: "JSON",
                auditPath: auditPath,
            });
        }

        return config;
    }

    /**
     * Create and register a new OIDC IdP mock.
     *
     * @param {string} issuer_url The issuer URL for the IdP mock.
     * @param {object} config The configuration object for the IdP mock.
     * @returns {object} The created IdP mock.
     */
    create_idp(issuer_url, config) {
        assert(typeof issuer_url === "string", "idp_config.url must be a string");
        assert(typeof config === "object", "idp_config.config must be an object");
        print("OIDCFixture.create_idp " + issuer_url);
        var idp = new OIDCIdPMock({
            issuer_url: issuer_url,
            config: config
        });
        this.idps[issuer_url] = idp;

        return idp;
    }

    /**
     * Get the OIDC IdP mock object for the given issuer URL.
     *
     * @param {string} issuer_url The issuer URL for the IdP mock.
     * @returns {object} The OIDC IdP mock object.
     */
    get_idp(issuer_url) {
        assert(issuer_url, "Missing issuer_url");
        assert(this.idps[issuer_url], "Missing idp for issuer_url: " + issuer_url);

        return this.idps[issuer_url];
    }

    /**
     * Create a new MongoDB connection object.
     *
     * @returns {object} - The MongoDB connection object.
     */
    create_conn() {
        print("OIDCFixture.create_session")
        return new Mongo(this.admin_conn.host);
    }

    /**
     * Set up the OIDC fixture.
     *
     * This function:
     * - starts all the prior registered IdP mocks,
     * - starts the MongoDB server with the specified options,
     * - sets the authentication mechanisms to SCRAM-SHA-256 and MONGODB-OIDC,
     * - sets the OIDC identity providers for the MongoDB server,
     * - creates and admin session,
     * - creates an admin user with root privileges,
     * - sets the OIDCIdPAuthCallback to handle authentication callbacks.
     *
     * @param {boolean} with_audit - If true, enables audit logging.
     * 
     * NOTE: The SCRAM-SHA-256 mechanism is specified to allow admin authentication.
     *       The admin session is created so that it is possible to run admin commands
     *       on the server (e.g. getLog). It can also be used to create roles for the user.
     */
    setup(with_audit = false) {
        print("OIDCFixture.setup")

        if (with_audit) {
            this.audit_path = OIDCFixture.allocate_audit_path();
        }

        for (const idp_url in this.idps) {
            this.idps[idp_url].start();
        }

        const options = OIDCFixture.create_options(this.oidc_providers, this.audit_path);
        this.admin_conn = MongoRunner.runMongod(options);
        this.admin = this.admin_conn.getDB("admin");
        assert.commandWorked(this.admin.runCommand(
            { createUser: "admin", pwd: "admin", roles: [{ role: "root", db: "admin" }] }));
        assert(this.admin.auth("admin", "admin"));

        var callback = function (authInfo) {
            print("OIDCFixture.OIDCIdPAuthCallback: ", JSON.stringify(this));
            if (this.client_callback) {
                var issuer = authInfo.activationEndpoint.replace("/device/verify", "")
                this.client_callback({
                    user: authInfo.userName,
                    issuer: issuer,
                })
            }
        };

        this.admin_conn._setOIDCIdPAuthCallback(callback.toString());
    }

    /**
     * Teardown the OIDC fixture.
     *
     * This function stops the MongoDB server and all the registered IdP mocks.
     */
    teardown() {
        print("OIDCFixture.teardown stopMongod")
        MongoRunner.stopMongod(this.admin_conn);
        for (const idp_url in this.idps) {
            print("OIDCFixture.teardown stop IdP " + idp_url);
            this.idps[idp_url].stop();
        }
    }

    /**
     * Check if the expected log exists in the provided array with logs with respect to the
     * last processed date.
     *
     * This function searches the global log for a specific log entry that matches the expected log.
     * It check if all fields from the expectedLog object exist in the log entry.
     * Example:
     * var expectedLog = {
     *     msg: "Successfully authenticated",
     *     attr: {
     *         mechanism: "MONGODB-OIDC",
     *         user: "user1",
     *     }
     * }
     * This will check if there is a log entry with the message "Successfully authenticated" and
     * the attribute "mechanism" set to "MONGODB-OIDC" and "user" set to "user1".
     * @param {object[]} logs - Array of log objects to search in.
     * @param {object} expectedLog - The expected log object to check for.
     * @param {Date} lastDate - The date of the last processed log entry.
     * @param {function} getDate - Function to extract the date from the log entry.
     * @returns {object} - Returns pair including a boolean which indicates if the expected log exists,
     * and the date of found element.
     */
    static checkLogExistsWithDate(logs, expectedLog, lastDate, getDate) {
        const res = logs.find(element => {
            const logDate = getDate(element);
            if (logDate <= lastDate) {
                // Ignore logs not newer than the last log date
                return false;
            }
            const found = checkExpectedLog(expectedLog, element);
            if (found) {
                print("OIDCFixture.checkLogExists: found: ", JSON.stringify(element));
                lastDate = logDate;
            }

            return found;
        });

        return { res, lastDate };
    }

    /**
     * Check if the expected log exists in the global log.
     *
     * @param {object} expectedLog - The expected log object to check for.
     * @returns True if the expected log exists, false otherwise.
     */
    checkLogExists(expectedLog) {
        const logs =
            assert.commandWorked(this.admin.runCommand({ getLog: "global" })).log.map(element => JSON.parse(element));

        const result = OIDCFixture.checkLogExistsWithDate(logs, expectedLog, this.last_log_date, element => {
            new Date(element["t"]["$date"]);
        });

        if (result.res) {
            this.last_log_date = result.lastDate;
        }

        return result.res;
    }

    /**
     * Check if the expected log exists in the audit log.
     *
     * @param {object} expectedLog - The expected log object to check for.
     * @returns True if the expected log exists, false otherwise.
     */
    checkAuditLogExists(expectedLog) {
        if (!this.audit_path) {
            return false;
        }

        let auditLogs = [];
        cat(this.audit_path).split('\n').filter(line => line.length > 0).forEach(line => {
            const logJson = parseJsonCanonical(line);
            auditLogs.push(logJson);
        });

        const result = OIDCFixture.checkLogExistsWithDate(auditLogs, expectedLog, this.last_audit_log_date, element => {
            new Date(element["ts"]);
        });

        if (result.res) {
            this.last_audit_log_date = result.lastDate;
        }
        return result.res;
    }

    /**
     * Authenticate the user with the OIDC mechanism.
     *
     * @param {object} conn - The connection object.
     * @param {string} user - The user to authenticate.
     * @returns {boolean} - Returns true if authentication is successful, false otherwise.
     */
    auth(conn, user) {
        assert(conn, "Connection is not defined");
        assert(user, "User is not defined");

        print("OIDCFixture.auth")
        try {
            return conn.auth({ mechanism: 'MONGODB-OIDC', user });
        }
        catch (e) {
            print("OIDCFixture.auth exception: ", e);
        }

        return false;
    }

    /**
     * Refresh the access token for the current user and reauthenticate.
     * 
     * @param {object} conn - The connection object.
     * @returns {string|null} - Returns the new access token if successful, null otherwise.
     */
    refresh_token(conn) {
        print("OIDCFixture.refresh_token")
        assert(conn, "Connection is not defined");
        try {
            const accessToken = conn._refreshAccessToken();
            conn.auth({
                oidcAccessToken: accessToken,
                mechanism: 'MONGODB-OIDC'
            });

            return accessToken;
        } catch (e) {
            print("OIDCFixture.refresh_token exception: ", e);

            return null;
        }
    }

    /**
     * Logout the current user from the '$external' database.
     *
     * @param {object} conn - The connection object.
     * @returns {boolean} - Returns true if the logout was successful, false otherwise.
     */
    logout(conn) {
        assert(conn, "Connection is not defined");
        var db = conn.getDB('$external');
        return db.logout();
    }

    /**
     * Get the authentication information for the current connection.
     *
     * Executes the 'connectionStatus' command on the '$external' database
     *
     * @param {object} conn - The connection object.
     * @returns {object} - Returns the authentication information for the current connection.
     */
    authInfo(conn) {
        assert(conn, "Connection is not defined");
        var db = conn.getDB('$external');
        return db.runCommand({ connectionStatus: 1, showPrivileges: 1 }).authInfo;
    }

    /**
     * Assert that the expected privileges match the privileges in the array.
     * The privileges for the 'system.js' collection are ignored.
     *
     * @param {object[]} allPrivileges - Privileges to check.
     * @param {object[]} expectedPrivileges - Expected privileges.
     */
    assert_has_privileges(allPrivileges, expectedPrivileges) {
        // Ignore privileges for system.js collections.
        const privileges = allPrivileges.filter(privilege => privilege.resource.collection !== "system.js");

        assert.eq(privileges.length, expectedPrivileges.length, "Privileges count mismatch");

        for (const expectedPrivilege of expectedPrivileges) {
            assert(privileges.some(privilege => {
                if (privilege.resource.db !== expectedPrivilege.resource.db) {
                    return false;
                }

                if (privilege.resource.collection !== expectedPrivilege.resource.collection) {
                    return false;
                }

                assert.eq(privilege.actions.length, expectedPrivilege.actions.length, "Actions count mismatch");
                for (const action of expectedPrivilege.actions) {
                    assert(privilege.actions.includes(action),
                        `Action ${action} not found in privilege actions: ${JSON.stringify(privilege.actions)}`);
                }

                return true;
            }), `Privileges mismatch: expected: ${JSON.stringify(expectedPrivileges)} current: ${JSON.stringify(privileges)}`);
        }
    }

    /**
     * Assert that the expected roles are teh same as the roles in the array.
     *
     * @param {object[]} roles Roles to check
     * @param {object[]} expectedRoles Expected roles
     */
    assert_has_roles(roles, expectedRoles) {
        assert.eq(roles.length, expectedRoles.length, "Roles count mismatch");
        for (const expectedRole of expectedRoles) {
            assert(roles.some(role => {
                if (typeof expectedRole === "string") {
                    return role.role == expectedRole && role.db == "admin";
                }

                return role.role == expectedRole.role && role.db == expectedRole.db;
            }), "Role not found: " + JSON.stringify(expectedRole));
        }
    }


    /**
     * Assert that the user is authenticated with the provided roles. 
     *
     * @param {object} conn - The connection object.
     * @param {string} user The expected user name.
     * @param {(string|object)[]} roles The expected roles. If a string is provided,
     *                                  it is assumed to be a role name in the 'admin' database.
     */
    assert_authenticated(conn, user, roles, privileges) {
        assert(conn, "Connection is not defined");
        assert(user, "User is not defined");

        // Make sure the user is authenticated according to server's logs
        var expectedLog = {
            msg: "Successfully authenticated",
            attr: {
                mechanism: "MONGODB-OIDC",
                user: user
            }
        }
        assert(this.checkLogExists(expectedLog), user + " is not authenticated");

        // Make sure the user is authenticated according to the connectionStatus command
        var authInfo = this.authInfo(conn);
        print("OIDCFixture.assert_authenticated: ", JSON.stringify(authInfo));
        assert.eq(authInfo.authenticatedUsers.length, 1);
        assert.eq(authInfo.authenticatedUsers[0].user, user, user + " is not authenticated");
        assert.eq(authInfo.authenticatedUsers[0].db, "$external");

        // Verify roles if provided
        if (roles) {
            print("OIDCFixture.assert_authenticated: checking roles");
            this.assert_has_roles(authInfo.authenticatedUserRoles, roles);
        }

        if (privileges) {
            print("OIDCFixture.assert_authenticated: checking privileges");
            this.assert_has_privileges(authInfo.authenticatedUserPrivileges, privileges);
        }
    }

    /**
     * Assert that the user is not authenticated.
     *
     * @param {object} conn The connection object.
     */
    assert_not_authenticated(conn) {
        assert(conn, "Connection is not defined");

        const authInfo = this.authInfo(conn);
        assert.eq(authInfo.authenticatedUsers.length, 0, "User is authenticated");
        assert.eq(authInfo.authenticatedUserRoles.length, 0, "User has roles");
        assert.eq(authInfo.authenticatedUserPrivileges.length, 0, "User has privileges");
    }

    /**
     * Create a new role with the specified name, roles, and privileges.
     *
     * @param {string} role_name Name of the role to create.
     * @param {object[]} roles Roles to be included in the new role.
     * @param {object[]} privileges Privileges to be included in the new role.
     */
    create_role(role_name, roles = [], privileges = []) {
        assert(role_name, "Role name is not defined");

        print(`OIDCFixture.create_role: ${role_name}`);
        assert.commandWorked(this.admin.runCommand({
            createRole: role_name,
            privileges: privileges,
            roles: roles
        }), `Failed to create role: ${role_name}`);
    }

    /**
     * This function creates a new user in the '$external' database.
     *
     * @param {string} user The user name to create.
     * @param {object[]} roles The roles to assign to the user.
     */
    create_user(user, roles = []) {
        assert(user, "User is not defined");
        print(`OIDCFixture.create_user: ${user} with roles: ${JSON.stringify(roles)}`);
        assert.commandWorked(this.admin.getSiblingDB("$external").runCommand({
            createUser: user,
            roles: roles,
        }), `Failed to create user: ${user}`);
    }

    /**
     * Assert that the mongod process fails with the provided OIDC providers configuration.
     * The mongod output is checked against the provided regular expression.
     * 
     * @param {object} oidcProviders The OIDC providers configuration object for mongod.
     * @param {string} match The regular expression to match against the mongod output.
     */
    static assert_mongod_fails_with(oidcProviders, match) {
        clearRawMongoProgramOutput();
        var options = this.create_options(oidcProviders);
        try {
            var conn = MongoRunner.runMongod(options);
            assert(!conn, "mongod should fail with options: " + JSON.stringify(oidcProviders))
        } catch (e) {
            // ignore
        }
        this.assert_mongod_output_match(match);
    }

    /**
     * Assert that the mongod output matches the provided regular expression.
     *
     * @param {string} match The regular expression to match against the mongod output.
     */
    static assert_mongod_output_match(match) {
        assert(rawMongoProgramOutput().match(match), `mongod output does not match: '${match}':\n` + rawMongoProgramOutput());
    }
}
