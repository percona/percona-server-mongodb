import { getPython3Binary } from "jstests/libs/python.js";

const OIDC_IDP_MOCK_CERT = "jstests/oidc/lib/ca_oidc_idp.pem";
const OIDC_IDP_MOCK_PATH = "jstests/oidc/lib/oidc_idp_mock.py";
const OIDC_IDP_MOCK_START_STR = "OIDC IDP server is running at ";

export class OIDCIdPMock {
    /**
     * Constructor for the OIDC IDP mock server.
     *
     * @param {string} issuer_url The issuer URL for the OIDC IDP mock server on which it should start.
     * @param {Object} config The configuration object for the OIDC IDP mock server.
     */
    constructor({ issuer_url, config }) {
        this.python = getPython3Binary();
        this.issuer_url = issuer_url;
        this.config = config;
        this.pid = null;
    }

    /**
     * Start the OIDC IDP mock server.
     *
     * This function starts the server with the provided configuration and issuer URL.
     * It waits for the server to start and be ready to accept requests.
     */
    start() {
        const args = [
            this.python,
            OIDC_IDP_MOCK_PATH,
            "--verbose",
            "--cert",
            OIDC_IDP_MOCK_CERT,
            "--config-json",
            JSON.stringify(this.config),
            this.issuer_url
        ];

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
    clear() {
        clearRawMongoProgramOutput();
    }

    /**
     * Assert that the given HTTP request was made to the OIDC IDP mock server.
     *
     * @param {string} method HTTP method (e.g., GET, POST).
     * @param {string} path Path relative to issuer_url (e.g.: /token, /keys).
     */
    assert_http_request(method, path) {
        const request_msg = method + " " + this.issuer_url + path;
        assert.soon(function () {
            return rawMongoProgramOutput().search(request_msg) !== -1;
        }, "Request not found: " + request_msg, 1000);
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
        this.assert_http_request("POST", "/device/authorize");
        let token_search = "/token";
        if (client_id) {
            token_search += ".*client_id=" + client_id + ".*";
        }

        if (scopes) {
            let scopes_search = ".*scope=";
            for (const scope of scopes) {
                scopes_search += scope + ".*";
            }
            // TODO: Uncomment when implemented on the server side.
            // token_search += scopes_search;
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
}
