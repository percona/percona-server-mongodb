import {getPython3Binary} from "jstests/libs/python.js";

const LDAP_MOCK_PATH = "jstests/ldapauthz/lib/ldap_mock.py";
const LDAP_MOCK_START_STR = "LDAP mock server is running on ";

/**
 * Wrapper that launches the Python mock LDAP server (jstests/ldapauthz/lib/ldap_mock.py)
 * as a child process. The server implements just enough LDAP for the ldapauthz suite
 * (simple bind + search) so the tests can run without a real slapd deployment.
 */
export class LDAPMock {
    /**
     * @param {Object} opts
     * @param {number} opts.port TCP port the mock should listen on.
     * @param {string} [opts.host="127.0.0.1"] Interface to bind to.
     * @param {boolean} [opts.verbose=false] Log binds/searches to stdout.
     */
    constructor({port, host = "127.0.0.1", verbose = false}) {
        this.python = getPython3Binary();
        this.port = port;
        this.host = host;
        this.verbose = verbose;
        this.pid = null;
    }

    /**
     * Start the mock LDAP server and wait until it is listening.
     */
    start() {
        let args = [this.python, LDAP_MOCK_PATH, "--port", String(this.port), "--host", this.host];
        if (this.verbose) {
            args.push("--verbose");
        }

        // Clear buffered output so the readiness check below can't match a stale banner
        // from an earlier program (mirrors the OIDC IdP mock).
        clearRawMongoProgramOutput();

        this.pid = _startMongoProgram({args: args});
        assert(checkProgram(this.pid).alive, "LDAP mock server failed to start");

        const start_msg = LDAP_MOCK_START_STR + this.host + ":" + this.port;
        assert.soon(() => {
            // Fail fast (instead of spinning for the full timeout) if the process died
            // during startup -- e.g. an import error, port conflict, or exception in
            // ldap_mock.py before it printed its readiness banner. assert.soon has no
            // process-death detection of its own.
            assert(
                checkProgram(this.pid).alive,
                "LDAP mock server exited during startup; see program output above",
            );
            return rawMongoProgramOutput(start_msg) !== "";
        }, "LDAP mock server did not become ready: " + start_msg);
    }

    /**
     * Stop the mock LDAP server if it is running.
     */
    stop() {
        if (this.pid) {
            stopMongoProgramByPid(this.pid);
            this.pid = null;
        }
    }
}
