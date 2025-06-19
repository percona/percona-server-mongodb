import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const pollingIntervalSecs = 3;

const issuer_url = OIDCFixture.allocate_issuer_url("issuer", /* secure = */ true);

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
    serverCAFile: "jstests/oidc/lib/ca_oidc_idp.crt",
};

function test_mongodb_idp_https_converstation(clusterClass) {
    let test = new OIDCFixture({
        oidcProviders: [oidcProvider],
        idps: [{
            url: issuer_url,
            config: idp_config,
            cert: "jstests/oidc/lib/ca_oidc_idp.pem",
        }]
    });
    let idp = test.get_idp(issuer_url);

    test.setup(clusterClass);

    // Wait for periodic job to fetch the JWKs
    sleep(pollingIntervalSecs * 1000);
    idp.assert_http_request("GET", "/keys");

    test.teardown();
}

test_mongodb_idp_https_converstation(StandaloneMongod);
test_mongodb_idp_https_converstation(ShardedCluster);
