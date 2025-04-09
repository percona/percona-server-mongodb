import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

var idp_config = {
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

var oidcProvider = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    authorizationClaim: "claim"
};

var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
test.setup();

var conn = test.create_conn();

test.auth(conn, "user");
test.assert_authenticated(conn, "test/user", ["test/group1", "test/group2"]);

test.teardown();
