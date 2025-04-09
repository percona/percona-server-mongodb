import { OIDCIdPMock } from 'jstests/oidc/lib/oidc_idp_mock.js';

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
     * @param {function} client_callback - The callback function to handle authentication callback on the client side.* 
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

        this.oidcProviders = oidcProviders;
        this.conn = null;
        this.adminSession = null;
        this.admin = null;
    }

    /**
     * Create and register new OIDC IdP mock.
     *
     * @param {str} issuer_url The issuer URL for the IdP mock.
     * @param {object} config The configuration object for the IdP mock.
     * @returns 
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
     * NOTE: The SCRAM-SHA-256 mechanism is specified to allow admin authentication.
     *       The admin session is created so that it is possible to run admin commands
     *       on the server (e.g. getLog). It can also be used to create roles for the user.
     */
    setup() {
        print("OIDCFixture.setup")
        var options = {
            auth: "",
            setParameter: {
                authenticationMechanisms: "SCRAM-SHA-256,MONGODB-OIDC",
                oidcIdentityProviders: JSON.stringify(this.oidcProviders),
            }
        };

        for (const idp_url in this.idps) {
            this.idps[idp_url].start();
        }

        this.conn = MongoRunner.runMongod(options);
        this.adminSession = new Mongo(this.conn.host);
        this.admin = this.adminSession.getDB("admin");
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

        this.conn._setOIDCIdPAuthCallback(callback.toString());
    }

    /**
     * Theardown the OIDC fixture.
     *
     * This function stops the MongoDB server and all the registered IdP mocks.
     */
    teardown() {
        print("OIDCFixture.teardown stopMongod")
        MongoRunner.stopMongod(this.conn);
        for (const idp_url in this.idps) {
            print("OIDCFixture.teardown stop IdP " + idp_url);
            this.idps[idp_url].stop();
        }
    }

    /**
     * Check if the expected log exists in the global log.
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
     * @param {object} expectedLog - The expected log object to check for.
     * @returns {boolean} - Returns true if the expected log exists, false otherwise.
     */
    checkLogExists(expectedLog) {
        const log =
            assert.commandWorked(this.admin.runCommand({ getLog: "global" })).log;

        return log.some(function (element) {
            const logJson = JSON.parse(element);
            return checkExpectedLog(expectedLog, logJson);
        })
    }

    /**
     * Authenticate the user with the OIDC mechanism.
     *
     * @param {string} user - The user to authenticate.
     * @returns {boolean} - Returns true if authentication is successful, false otherwise.
     */
    auth(user) {
        print("OIDCFixture.auth")
        try {
            return this.conn.auth({ mechanism: 'MONGODB-OIDC', user });
        }
        catch (e) {
            print("OIDCFixture.auth exception: ", e);
        }

        return false;
    }

    /**
     * Logout the current user from the '$external' database.
     *
     * @returns {boolean} - Returns true if the logout was successful, false otherwise.
     */
    logout() {
        print("OIDCFixture.logout")
        var db = this.conn.getDB('$external')
        return db.logout();
    }

    /**
     * Get the authentication information for the current connection.
     *
     * Executes the 'connectionStatus' command on the '$external' database
     *
     * @returns {object} - Returns the authentication information for the current connection.
     */
    authInfo() {
        var db = this.conn.getDB('$external')
        return db.runCommand({ connectionStatus: "1" }).authInfo;
    }

    assert_authenticated(user, roles) {
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
        var authInfo = this.authInfo();
        print("OIDCFixture.assert_authenticated: ", JSON.stringify(authInfo));
        assert.eq(authInfo.authenticatedUsers.length, 1);
        assert.eq(authInfo.authenticatedUsers[0].user, user, user + " is not authenticated");
        assert.eq(authInfo.authenticatedUsers[0].db, "$external");

        // Verify roles if provided
        if (roles) {
            assert.eq(authInfo.authenticatedUserRoles.length, roles.length);
            for (var i = 0; i < roles.length; i++) {
                assert.eq(authInfo.authenticatedUserRoles[i].role, roles[i]);
                assert.eq(authInfo.authenticatedUserRoles[i].db, "admin");
            }
        }
    }
}
