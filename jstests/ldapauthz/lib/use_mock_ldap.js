/**
 * Test override that makes the ldapauthz suite run against the Python mock LDAP server
 * (jstests/ldapauthz/lib/ldap_mock.py) instead of a real slapd.
 *
 * It is imported (once per test) via the `eval` shell option of the ldapauthz_mock suite,
 * so the individual ldapauthz_*.js test files need no changes.
 *
 * Why this wraps MongoRunner rather than starting the mock directly at import time: the
 * `eval` script runs inside its own MongoProgramScope in the mongo shell (see
 * mongo_main.cpp), whose destructor kills every spawned program when the eval finishes --
 * i.e. before the test file runs. A mock started at import time would therefore be killed
 * before the first mongod starts. Starting it lazily from inside the runMongod wrapper
 * means it is spawned while the *test file* is executing, so it lives under the test
 * file's MongoProgramScope.
 *
 * The shell also fails a test (exit code != 0) if any child process is still running when
 * the test file finishes. So the stopMongod wrapper tears the mock down again: every
 * ldapauthz test stops its mongod(s) at the end, so the mock is always gone before the
 * end-of-file check. Tearing it down also resets TestData.ldapServers to the sentinel, so
 * a test that starts a second mongod (e.g. ldapauthz_ldap_timeouts.js) gets a fresh mock.
 *
 * Deliberately-invalid addresses such as "localhost:39999" are passed through untouched,
 * since only the sentinel value is rewritten.
 */
import {ADMIN_DN, ADMIN_PASSWORD} from "jstests/ldapauthz/lib/ldap_directory.js";
import {LDAPMock} from "jstests/ldapauthz/lib/ldap_mock.js";

export const LDAP_MOCK_SENTINEL = "__ldap_mock__";

// Tests read TestData.ldapServers when building their runMongod options; hand them the
// sentinel so the wrapper below can recognise and rewrite it.
TestData.ldapServers = LDAP_MOCK_SENTINEL;

// Derive the bind/query credentials from the same source of truth as the mock directory
// (ldap_directory.js) so they cannot drift from the credentials the mock accepts. The
// suite YAML therefore does not need to hardcode them.
TestData.ldapQueryUser = ADMIN_DN;
TestData.ldapQueryPassword = ADMIN_PASSWORD;

let mock = null;

function ensureMock() {
    if (mock === null) {
        const port = allocatePort();
        mock = new LDAPMock({port: port});
        mock.start();
        // Update the global so later reads (e.g. a setParameter that switches to a valid
        // server) resolve to the running mock rather than the sentinel.
        TestData.ldapServers = "127.0.0.1:" + port;
    }
}

function teardownMock() {
    if (mock !== null) {
        mock.stop();
        mock = null;
        TestData.ldapServers = LDAP_MOCK_SENTINEL;
    }
}

const originalRunMongod = MongoRunner.runMongod;
MongoRunner.runMongod = function (opts) {
    try {
        // ensureMock() is inside the try so that if mock.start() throws (e.g. the readiness
        // wait times out), the catch below still reaps the half-started mock: otherwise the
        // module-level `mock` stays non-null with a live Python process, leaking it past the
        // shell's end-of-file "child process still running" check and masking the real error.
        ensureMock();
        if (opts && opts.ldapServers === LDAP_MOCK_SENTINEL) {
            opts = Object.assign({}, opts, {ldapServers: TestData.ldapServers});
        }
        return originalRunMongod.call(this, opts);
    } catch (e) {
        teardownMock();
        throw e;
    }
};

const originalStopMongod = MongoRunner.stopMongod;
MongoRunner.stopMongod = function (...args) {
    // finally so the mock is always reaped even if stopMongod throws; otherwise a leaked
    // mock would trip the shell's end-of-file "child process still running" check.
    try {
        return originalStopMongod.apply(this, args);
    } finally {
        teardownMock();
    }
};
