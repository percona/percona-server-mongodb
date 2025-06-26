load('jstests/libs/python.js');

const OIDC_IDP_MOCK_CERT = "jstests/oidc/lib/ca_oidc_idp.pem";
const OIDC_IDP_MOCK_PATH = "jstests/oidc/lib/oidc_idp_mock.py";
const OIDC_IDP_MOCK_START_STR = "OIDC IDP server is running at ";

export class OIDCIdPMock {
    /**
     * Constructor for the OIDC IDP mock server.
     *
     * @param {string} issuer_url The issuer URL for the OIDC IDP mock server on which it should
     *     start.
     * @param {Object} config The configuration object for the OIDC IDP mock server.
     * @param {string} cert The path the a PEM file with the private key and certificate for
     *     the IdP mock. Optional. If passed, the mock uses HTTPS rather than plain HTTP for
     *     network communication. Implies `ussuer_url` has the `https` scheme.
     */
    constructor({issuer_url, config, cert}) {
        this.python = getPython3Binary();
        this.issuer_url = issuer_url;
        this.config = config;
        this.cert = cert;
        this.pid = null;

        if (this.cert && !this.issuer_url.startsWith("https://")) {
            throw new Error("A certificate is provided but the `issuer_url` is not HTTPS");
        }
    }

    /**
     * Start the OIDC IDP mock server.
     *
     * This function starts the server with the provided configuration and issuer URL.
     * It waits for the server to start and be ready to accept requests.
     */
    start() {
        let args = [this.python, OIDC_IDP_MOCK_PATH, "--verbose"];
        if (this.cert) {
            args.push("--cert", this.cert);
        }
        args.push("--config-json", JSON.stringify(this.config), this.issuer_url);

        clearRawMongoProgramOutput();

        this.pid = _startMongoProgram({ args: args });
        assert(checkProgram(this.pid).alive);

        const start_msg = OIDC_IDP_MOCK_START_STR + this.issuer_url;
        assert.soon(function () {
            return rawMongoProgramOutput().search(start_msg) !== -1;
        });
    }

    /**
     * Clear the program output to prepare for the next assertions.
     */
    clear_output() {
        clearRawMongoProgramOutput();
    }

    /**
     * Assert that the given HTTP request was made to the OIDC IDP mock server.
     *
     * @param {string} method HTTP method (e.g., GET, POST).
     * @param {string} path Path relative to issuer_url (e.g.: /token, /keys).
     * @param {number} [timeout=1000] Timeout in milliseconds to wait for the request to be logged.
     */
    assert_http_request(method, path, timeout = 1000) {
        const request_msg = method + " " + this.issuer_url + path;
        assert.soon(function () {
            return rawMongoProgramOutput().search(request_msg) !== -1;
        }, "Request not found: " + request_msg, timeout, 100);
    }

    /**
     * Assert that the given HTTP request was NOT made to the OIDC IDP mock server.
     *
     * @param {string} method HTTP method (e.g., GET, POST).
     * @param {string} path Path relative to issuer_url (e.g.: /token, /keys).
     */
    assert_no_http_request(method, path) {
        const request_msg = method + " " + this.issuer_url + path;
        assert(rawMongoProgramOutput().search(request_msg) === -1, "Request found: " + request_msg);
    }

    /**
     * Assert that the token was requested with the given client_id and scopes.
     *
     * @param {string} client_id Client ID used to request the token.
     * @param {Array<string>} scopes Scopes requested for the token.
     */
    assert_token_requested(client_id, scopes) {
        // NOTE:
        // The '/device/authorize' is used by the device authorization flow.
        // The tests are re-using this flow to test OIDC authentication.
        // The '/token' endpoint is used by both flows.

        let auth_search = "/device/authorize"
        if (client_id) {
            auth_search += ".*client_id=" + client_id + ".*";
        }

        if (scopes) {
            let scopes_search = ".*scope=.*";
            for (const scope of scopes) {
                scopes_search += scope + ".*";
            }
            auth_search += scopes_search;
        }

        this.assert_http_request("POST", auth_search);

        let token_search = "/token";
        if (client_id) {
            token_search += ".*client_id=" + client_id + ".*";
        }

        this.assert_http_request("POST", token_search);
    }

    /**
     * Assert that the token refresh was requested with the given client_id.
     *
     * @param {string} client_id Client ID used to request the token.
     */
    assert_token_refresh_requested(client_id) {
        let token_search = "/token";
        if (client_id) {
            token_search += ".*client_id=" + client_id + ".*";
        }

        // The IdP mock server always returns 'refresh_token' as a refresh token.
        token_search += ".*refresh_token=refresh_token.*";

        this.assert_http_request("POST", token_search);
    }

    /**
     * Assert that the IDP mock server was requested for the OpenID configuration.
     */
    assert_config_requested() {
        this.assert_http_request("GET", "/.well-known/openid-configuration");
    }

    /**
     * Stop the OIDC IDP mock server if it is running.
     */
    stop() {
        if (this.pid) {
            stopMongoProgramByPid(this.pid);
            this.pid = null;
        }
    }

    /**
     * Restart the OIDC IDP mock server.
     */
    restart() {
        this.stop();
        this.start();
    }
}
