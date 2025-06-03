import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

const idp_config_with_claims = {
    token: {
        payload: {
            aud: "audience",
            sub: "user",
            claim: [
                "group1",
                "group2",
            ],
        }
    },
};

const idp_config_without_claims = {
    token: {
        payload: {
            aud: "audience",
            sub: "user",
        }
    },
};

const oidcProviderWithClaims = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    useAuthorizationClaim: false,  // don't use claims
    authorizationClaim: "claim",   // this should be ignored
};

const oidcProviderNoClaims = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    useAuthorizationClaim: false,  // don't use claims
};

// useAuthorizationClaim is false for all variants
// check all variants where:
// - oidc provider is configured with/without authorizationClaim field set - which shall be ignored
// - idp returns a token with/without the claim
const variants = [
    {idp_config: idp_config_with_claims, oidc_config: oidcProviderWithClaims},
    {idp_config: idp_config_with_claims, oidc_config: oidcProviderNoClaims},
    {idp_config: idp_config_without_claims, oidc_config: oidcProviderWithClaims},
    {idp_config: idp_config_without_claims, oidc_config: oidcProviderNoClaims},
];

function test_user_has_only_roles_it_was_created_with(clusterClass, variant) {
    var test = new OIDCFixture({ oidcProviders: [variant.oidc_config], idps: [{ url: issuer_url, config: variant.idp_config }] });
    test.setup(clusterClass);
    test.create_user("test/user", [{ role: "readWrite", db: "test_db" }]);

    var conn = test.create_conn();

    assert(test.auth(conn, "user"), "Failed to authenticate");
    test.assert_authenticated(conn, "test/user", [{ role: "readWrite", db: "test_db" }]);

    test.teardown();
}

for (const variant of variants) {
    test_user_has_only_roles_it_was_created_with(StandaloneMongod, variant);
    test_user_has_only_roles_it_was_created_with(ShardedCluster, variant);
}
