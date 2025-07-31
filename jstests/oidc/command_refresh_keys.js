import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url1 = OIDCFixture.allocate_issuer_url();
const issuer_url2 = OIDCFixture.allocate_issuer_url();
const issuer_url3 = OIDCFixture.allocate_issuer_url();

const oidcProviders = [
    {
        issuer: issuer_url1,
        clientId: "clientId",
        audience: "audience",
        matchPattern: "1$",
        authNamePrefix: "test",
        useAuthorizationClaim: false,
        JWKSPollSecs: 0,
    },
    {
        issuer: issuer_url2,
        clientId: "clientId",
        audience: "audience",
        matchPattern: "2$",
        authNamePrefix: "test",
        useAuthorizationClaim: false,
        JWKSPollSecs: 0,
    },
    {
        issuer: issuer_url3,
        clientId: "clientId",
        audience: "audience",
        matchPattern: "3$",
        authNamePrefix: "test",
        useAuthorizationClaim: false,
        JWKSPollSecs: 0,
    },
];

const idps = [
    {
        url: issuer_url1,
        config: {
            number_of_jwks: 3,
        }
    },
    {
        url: issuer_url2,
        config: {
            number_of_jwks: 2,
        }
    },
    {
        url: issuer_url3,
        config: {
            number_of_jwks: 1,
        }
    },
];

// verifies the key sets for a given issuer_url and the expected number of keys
const verifyKeys = (keys, issuer_url, expectedNumberOfKeys) => {
    assert.eq(keys?.keySets[issuer_url]?.keys?.length, expectedNumberOfKeys, `key set for ${issuer_url} should have ${expectedNumberOfKeys} keys`);
};

// executes the command and verifies the keys for all issuer_urls
const verifyAllKeys = (test, count1, count2, count3) => {
    const keys = assert.commandWorked(test.admin.runCommand({ oidcListKeys: 1 }), "oidcListKeys should work");

    verifyKeys(keys, issuer_url1, count1);
    verifyKeys(keys, issuer_url2, count2);
    verifyKeys(keys, issuer_url3, count3);
};

function expectedFailure(issuer_url) {
    return {
        issuer: issuer_url,
        error: {
            code: 96,
            codeName: "OperationFailed",
            errmsg: "Failed loading keys from " + issuer_url + " :: caused by :: " +
                "Bad HTTP response from API server: Couldn't connect to server",
        }
    };
}

function expectedFailureLogEntry(issuer_url) {
    return {id: 29141, msg: "Failed to refresh keys for IdP", attr: expectedFailure(issuer_url)};
}

function test_refresh_keys_response_and_log_on_failure(clusterClass) {
    var test = new OIDCFixture({oidcProviders: oidcProviders, idps: []});
    test.setup(clusterClass);
    // note: no IdP has been started

    const resp = test.admin.runCommand({oidcRefreshKeys: 1});
    assert.eq(resp.ok, 0);
    assert.eq(resp.errmsg, "Failed to load a JWKS from one or more IdPs");
    assert.sameMembers(
        resp.failures || [],
        [expectedFailure(issuer_url1), expectedFailure(issuer_url2), expectedFailure(issuer_url3)]);
    // note: in the case of a sharded cluster, the `resp` object contains additional
    // sharding-related properties

    assert(test.checkLogExists(expectedFailureLogEntry(issuer_url1),
                               /* advanceLogCutOffTimePoint = */ false),
           "Expected log not found for issuer_url1");
    assert(test.checkLogExists(expectedFailureLogEntry(issuer_url2),
                               /* advanceLogCutOffTimePoint = */ false),
           "Expected log not found for issuer_url2");
    assert(test.checkLogExists(expectedFailureLogEntry(issuer_url3),
                               /* advanceLogCutOffTimePoint = */ false),
           "Expected log not found for issuer_url3");

    // no keys should be present
    verifyAllKeys(test, 0, 0, 0);

    test.teardown();
}

function test_referesh_keys_triggers_key_fetching(clusterClass) {
    var test = new OIDCFixture({oidcProviders: oidcProviders, idps: []});
    test.setup(clusterClass);

    sleep(1000);

    // no IdP is running yet, so no keys should be present
    verifyAllKeys(test, 0, 0, 0);

    // start the IdPs
    for (const idp of idps) {
        test.create_idp(idp.url, idp.config).start();
    }

    // wait for the IdPs to be ready
    sleep(500);

    // still no keys should be present
    verifyAllKeys(test, 0, 0, 0);

    // make sure the keys are not fetched without explicit request
    for (const idp of idps) {
        test.get_idp(idp.url).assert_no_http_request("GET", "/keys");
    }

    // now fetch the keys
    assert.commandWorked(test.admin.runCommand({oidcRefreshKeys: 1}),
                         "oidcRefreshKeys should work");

    // verify that the requests were made
    for (const idp of idps) {
        test.get_idp(idp.url).assert_http_request("GET", "/keys");
    }

    // verify the keys were fetched
    verifyAllKeys(test, 3, 2, 1);

    // fetch the keys again
    assert.commandWorked(test.admin.runCommand({oidcRefreshKeys: 1}),
                         "oidcRefreshKeys should work");

    // verify that the requests were made again
    for (const idp of idps) {
        test.get_idp(idp.url).assert_http_request("GET", "/keys");
    }

    // verify the keys were fetched
    verifyAllKeys(test, 3, 2, 1);

    test.teardown();
}

test_refresh_keys_response_and_log_on_failure(StandaloneMongod);
test_refresh_keys_response_and_log_on_failure(ShardedCluster);

test_referesh_keys_triggers_key_fetching(StandaloneMongod);
test_referesh_keys_triggers_key_fetching(ShardedCluster);
