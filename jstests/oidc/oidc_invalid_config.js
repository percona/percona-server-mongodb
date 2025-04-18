// @tags: [oidc_idp_mock_cert_not_required]
import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer = OIDCFixture.allocate_issuer_url();

// Tests for invalid OIDC configurations
var variants = [
    { // Missing 'issuer' field.
        expected_error: "BadValue.*issuer.*is missing.*",
        config: [
            {
                clientId: "client",
                audience: "audience",
                authNamePrefix: "test",
            }
        ],
    },
    { // Missing 'cliendId' field, in case 'supportsHumanFlows' is true (default).
        expected_error: "BadValue.*`clientId` must present if `supportsHumanFlows` is `true`.*",
        config: [
            {
                issuer: issuer,
                audience: "audience",
                authNamePrefix: "test",
            }
        ],
    },
    { // Missing 'audience' field.
        expected_error: "BadValue.*audience.*is missing.*",
        config: [
            {
                issuer: issuer,
                clientId: "clientId",
                authNamePrefix: "test",
                useAuthorizationClaim: false,
            }
        ],
    },
    { // Missing 'authNamePrefix' field.
        expected_error: "BadValue.*authNamePrefix.*is missing.*",
        config: [
            {
                issuer: issuer,
                clientId: "client",
                audience: "audience",
                useAuthorizationClaim: false,
            }
        ],
    },
    { // Invalid value for 'authNamePrefix' field.
        expected_error: "BadValue.*`authNamePrefix` contains illegal char.*",
        config: [
            {
                issuer: issuer,
                clientId: "client",
                audience: "audience",
                authNamePrefix: "#!@",
                useAuthorizationClaim: false,
            }
        ],
    },
    { // Missing 'authorizationClaim' field, when 'useAuthorizationClaim' is true.
        expected_error: "BadValue.*`authorizationClaim` must present if `useAuthorizationClaim` is `true`.*",
        config: [
            {
                issuer: issuer,
                clientId: "client",
                audience: "audience",
                authNamePrefix: "test",
                useAuthorizationClaim: true,
            }
        ],
    },
    { // Missing 'authorizationClaim' field, when 'useAuthorizationClaim' is true by default.
        expected_error: "BadValue.*`authorizationClaim` must present if `useAuthorizationClaim` is `true`.*",
        config: [
            {
                issuer: issuer,
                clientId: "client",
                audience: "audience",
                authNamePrefix: "test",
                // default: useAuthorizationClaim: true,
            }
        ],
    },
    { // Missing 'matchPattern' fields, when multiple issuers are provided.
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
    { // Issuer without 'matchPattern' not the last one.
        expected_error: "BadValue.*configurations without the `matchPattern` field must be listed after those with the `matchPattern` field",
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
    { // Multiple configurations with the same 'issuer' and 'audience'.
        expected_error: "BadValue.*`issuer` values are equal.*and `audience` values are also eqaul.*`audience`" +
            " should be unique for each configuration that shares an `issuer`",
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
    { // Invalid 'matchPattern' field.
        expected_error: "BadValue: Bad value for parameter.*oidcIdentityProviders.*Invalid.*matchPattern.*",
        config: [
            {
                issuer: issuer,
                audience: "audience",
                clientId: "client1",
                authNamePrefix: "test1",
                matchPattern: "(1$",
                useAuthorizationClaim: false,
            },
        ],
    },
];

for (const variant of variants) {
    OIDCFixture.assert_mongod_fails_with(variant.config, variant.expected_error);
}
