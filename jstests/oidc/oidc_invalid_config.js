// @tags: [oidc_idp_mock_cert_not_required]
import {OIDCFixture, ShardedCluster, StandaloneMongod} from 'jstests/oidc/lib/oidc_fixture.js';

const issuer = OIDCFixture.allocate_issuer_url();
const issuer1 = OIDCFixture.allocate_issuer_url();
const issuer2 = OIDCFixture.allocate_issuer_url();

// Tests for invalid OIDC configurations
const variants = [
    {
        // Missing 'issuer' field.
        expected_error: "BadValue.*issuer.*is missing.*",
        config: [{
            clientId: "client",
            audience: "audience",
            authNamePrefix: "test",
        }],
    },
    {
        // Missing 'cliendId' field, in case 'supportsHumanFlows' is true (default).
        expected_error: "BadValue.*`clientId` must present if `supportsHumanFlows` is `true`.*",
        config: [{
            issuer: issuer,
            audience: "audience",
            authNamePrefix: "test",
        }],
    },
    {
        // Missing 'audience' field.
        expected_error: "BadValue.*audience.*is missing.*",
        config: [{
            issuer: issuer,
            clientId: "clientId",
            authNamePrefix: "test",
            useAuthorizationClaim: false,
        }],
    },
    {
        // Missing 'authNamePrefix' field.
        expected_error: "BadValue.*authNamePrefix.*is missing.*",
        config: [{
            issuer: issuer,
            clientId: "client",
            audience: "audience",
            useAuthorizationClaim: false,
        }],
    },
    {
        // Invalid value for 'authNamePrefix' field.
        expected_error: "BadValue.*`authNamePrefix` contains illegal char.*",
        config: [{
            issuer: issuer,
            clientId: "client",
            audience: "audience",
            authNamePrefix: "#!@",
            useAuthorizationClaim: false,
        }],
    },
    {
        // Missing 'authorizationClaim' field, when 'useAuthorizationClaim' is true.
        expected_error:
            "BadValue.*`authorizationClaim` must present if `useAuthorizationClaim` is `true`.*",
        config: [{
            issuer: issuer,
            clientId: "client",
            audience: "audience",
            authNamePrefix: "test",
            useAuthorizationClaim: true,
        }],
    },
    {
        // Missing 'authorizationClaim' field, when 'useAuthorizationClaim' is true by default.
        expected_error:
            "BadValue.*`authorizationClaim` must present if `useAuthorizationClaim` is `true`.*",
        config: [{
            issuer: issuer,
            clientId: "client",
            audience: "audience",
            authNamePrefix: "test",
            // default: useAuthorizationClaim: true,
        }],
    },
    {
        // Missing 'matchPattern' fields, when multiple issuers are provided.
        expected_error: "BadValue.*there is no `matchPattern`.*",
        config: [
            {
                issuer: OIDCFixture.allocate_issuer_url(),
                audience: "audience1",
                clientId: "client1",
                authNamePrefix: "test1",
                useAuthorizationClaim: false,
            },
            {
                issuer: OIDCFixture.allocate_issuer_url(),
                audience: "audience2",
                clientId: "client2",
                authNamePrefix: "test2",
                useAuthorizationClaim: false,
            }
        ],
    },
    {
        // Issuer without 'matchPattern' not the last one.
        expected_error: "BadValue.*configurations without the `matchPattern` field must be " +
            "listed after those with the `matchPattern` field",
        config: [
            {
                issuer: OIDCFixture.allocate_issuer_url(),
                audience: "audience1",
                clientId: "client1",
                authNamePrefix: "test1",
                useAuthorizationClaim: false,
            },
            {
                issuer: OIDCFixture.allocate_issuer_url(),
                audience: "audience2",
                clientId: "client2",
                authNamePrefix: "test2",
                matchPattern: "2$",
                useAuthorizationClaim: false,
            }
        ],
    },
    {
        // Multiple configurations with the same 'issuer' and 'audience'.
        expected_error: "BadValue.*`issuer` values are equal.*and `audience` values are also " +
            "eqaul.*`audience` should be unique for each configuration that shares an `issuer`",
        config: [
            {
                issuer: issuer,
                audience: "audience",
                clientId: "client1",
                authNamePrefix: "test1",
                matchPattern: "1$",
                useAuthorizationClaim: false,
            },
            {
                issuer: issuer,
                audience: "audience",
                clientId: "client2",
                authNamePrefix: "test2",
                matchPattern: "2$",
                useAuthorizationClaim: false,
            }
        ],
    },
    {
        // Invalid 'matchPattern' field.
        expected_error:
            "BadValue: Bad value for parameter.*oidcIdentityProviders.*Invalid.*matchPattern.*",
        config: [{
            issuer: issuer,
            audience: "audience",
            clientId: "client1",
            authNamePrefix: "test1",
            matchPattern: "(1$",
            useAuthorizationClaim: false,
        }],
    },
    {
        expected_error: "BadValue: Bad value for parameter.*oidcIdentityProviders.*: In " +
            "`oidcIdentityProviders.1.`, `oidcIdentityProviders.3.`, `oidcIdentityProviders.4.`: " +
            "`jwksPollSecs` values are different for the same `issuer` .*`jwksPollSecs` should " +
            "be the same for each configuration that shares an `issuer`",
        config: [
            {
                issuer: issuer1,
                audience: "audience1",
                clientId: "client1",
                authNamePrefix: "test1",
                matchPattern: "1$",
                useAuthorizationClaim: false,
                JWKSPollSecs: 1,
            },
            {
                issuer: issuer2,
                audience: "audience1",
                clientId: "client1",
                authNamePrefix: "test1",
                matchPattern: "1$",
                useAuthorizationClaim: false,
                JWKSPollSecs: 1,
            },
            {
                issuer: issuer1,
                audience: "audience2",
                clientId: "client2",
                authNamePrefix: "test2",
                matchPattern: "2$",
                useAuthorizationClaim: false,
                JWKSPollSecs: 1,  // same value: ok
            },
            {
                issuer: issuer2,
                audience: "audience2",
                clientId: "client2",
                authNamePrefix: "test2",
                matchPattern: "2$",
                useAuthorizationClaim: false,
                JWKSPollSecs: 1,  // same value: ok
            },
            {
                issuer: issuer2,
                audience: "audience3",
                clientId: "client1",
                authNamePrefix: "test1",
                matchPattern: "1$",
                useAuthorizationClaim: false,
                JWKSPollSecs: 2,  // different value: not ok
            },
        ],
    },
    {
        // string is an invalid 'requestScopes' field
        expected_error: "BadValue: Bad value for parameter.*: BSON field '.*.requestScopes' is " +
            "the wrong type 'string', expected type 'array'",
        config: [{
            issuer: issuer,
            audience: "audience",
            clientId: "client",
            authNamePrefix: "test",
            useAuthorizationClaim: false,
            requestScopes: "foo",
        }],
    },
    {
        // number is an invalid 'requestScopes' field
        expected_error: "BadValue: Bad value for parameter.*: BSON field '.*.requestScopes' is " +
            "the wrong type 'int', expected type 'array'",
        config: [{
            issuer: issuer,
            audience: "audience",
            clientId: "client",
            authNamePrefix: "test",
            useAuthorizationClaim: false,
            requestScopes: 2,
        }],
    },
    {
        // number is an invalid 'requestScopes' element
        expected_error: "BadValue: Bad value for parameter.*: BSON field '.*.requestScopes.1' is " +
            "the wrong type 'int', expected type 'string'",
        config: [{
            issuer: issuer,
            audience: "audience",
            clientId: "client",
            authNamePrefix: "test",
            useAuthorizationClaim: false,
            requestScopes: ["foo", 2],
        }],
    },
];

for (const variant of variants) {
    OIDCFixture.assertClusterInitializationFailsWith(
        StandaloneMongod, variant.config, variant.expected_error);
    OIDCFixture.assertClusterInitializationFailsWith(
        ShardedCluster, variant.config, variant.expected_error);
}
