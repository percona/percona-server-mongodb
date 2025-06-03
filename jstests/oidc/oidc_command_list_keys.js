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
    },
    {
        issuer: issuer_url2,
        clientId: "clientId",
        audience: "audience",
        matchPattern: "2$",
        authNamePrefix: "test",
        useAuthorizationClaim: false,
    },
    {
        issuer: issuer_url3,
        clientId: "clientId",
        audience: "audience",
        matchPattern: "3$",
        authNamePrefix: "test",
        useAuthorizationClaim: false,
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

function test_list_keys_returns_all_keys(clusterClass) {
    var test = new OIDCFixture({oidcProviders: oidcProviders, idps: idps});
    test.setup(clusterClass);

    verifyAllKeys(test, 3, 2, 1);

    test.teardown();
}

test_list_keys_returns_all_keys(StandaloneMongod);
test_list_keys_returns_all_keys(ShardedCluster);
