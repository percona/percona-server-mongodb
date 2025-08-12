import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const pollingIntervalSecs = 3;
const sleepMargin = 0.1  // 10%
const sleepTime = pollingIntervalSecs * 1000;
const sleepTimeMargin = sleepMargin * sleepTime;


const issuer_url = OIDCFixture.allocate_issuer_url();

const idp_config = {
    token: {
        payload: {
            aud: "audience",
            sub: "user",
        }
    },
};

const oidcProvider = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    useAuthorizationClaim: false,
    JWKSPollSecs: pollingIntervalSecs,
};

function test_jwks_polling_failure_is_logged(clusterClass) {
    let test = new OIDCFixture({oidcProviders: [oidcProvider], idps: []});
    test.setup(clusterClass);
    // note: no IdP has been started

    sleep(sleepTime + sleepTimeMargin);
    const expectedLog = {
        id: 29140,
        msg: "Failed to load JWKs from issuer",
        attr: {
            issuer: issuer_url,
            error: {
                code: 96,
                codeName: "OperationFailed",
                errmsg: "Failed loading keys from " + issuer_url + " :: caused by :: " +
                    "Bad HTTP response from API server: Couldn't connect to server",
            }
        }
    };
    assert(test.checkLogExists(expectedLog), "Expected log not found");

    test.teardown();
}

function test_jwks_fetched_with_polling_interval(clusterClass) {
    var test = new OIDCFixture(
        {oidcProviders: [oidcProvider], idps: [{url: issuer_url, config: idp_config}]});
    var idp = test.get_idp(issuer_url);

    test.setup(clusterClass);
    test.create_user("test/user", [{role: "readWrite", db: "test_db"}]);

    var conn = test.create_conn();
    idp.clear_output();
    // Wait for periodic job to fetch the JWKs
    // Wait up to 'sleepTime' for the request in order to sync with the polling interval.
    idp.assert_http_request("GET", "/keys", sleepTime + sleepTimeMargin);

    // Allow some time for the JWKs to be fetched and cached
    sleep(100);

    // Verify that the JWKs are cached and not fetched again when authenticating
    idp.clear_output();
    assert(test.auth(conn, "user"), "Failed to authenticate");
    idp.assert_no_http_request("GET", "/keys");
    test.assert_authenticated(conn, "test/user", [{role: "readWrite", db: "test_db"}]);
    test.logout(conn);

    // Verify that the JWKs are fetched again after the polling interval
    idp.clear_output();
    sleep(sleepTime);
    idp.assert_http_request("GET", "/keys", sleepTimeMargin);

    // Stop the IdP and verify that an error is logged when trying to fetch JWKs
    idp.clear_output();
    idp.stop();
    sleep(sleepTime);

    const expectedLog = {
        msg: "Failed to load JWKs from issuer",
        attr: {
            issuer: issuer_url,
            error: {
                code: 96,
                errmsg: "Failed loading keys from " + issuer_url +
                    " :: caused by :: Bad HTTP response from API server: " +
                    "Couldn't connect to server",
            },
        },
    };
    assert(test.checkLogExists(expectedLog), "Expected log message not found");

    // Start the IdP and verify that the JWKs are fetched again after the polling period
    idp.clear_output();
    idp.start();
    sleep(sleepTime);
    idp.assert_http_request("GET", "/keys", sleepTimeMargin);

    test.teardown();
}

test_jwks_polling_failure_is_logged(StandaloneMongod);
test_jwks_polling_failure_is_logged(ShardedCluster);

test_jwks_fetched_with_polling_interval(StandaloneMongod);
test_jwks_fetched_with_polling_interval(ShardedCluster);
