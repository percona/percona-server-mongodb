import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

var oidcProvider = {
	issuer: issuer_url,
	clientId: "clientId",
	audience: "audience",
	authNamePrefix: "test",
	useAuthorizationClaim: false,
};

var test = new OIDCFixture({ oidcProviders: [oidcProvider] });
test.setup();
test.create_user("test/user", [{ role: "readWrite", db: "test_db" }]);

// Test that when the server is configured with an OIDC, the saslSupportedMechs command
// returns the supported mechanisms including MONGODB-OIDC.
const res = test.admin.runCommand({ hello: 1, saslSupportedMechs: "$external.test/user" });
assert.commandWorked(res, "Failed to get saslSupportedMechs");
assert(res.saslSupportedMechs.includes('MONGODB-OIDC'), "Expected MONGODB-OIDC in saslSupportedMechs");

test.teardown();
