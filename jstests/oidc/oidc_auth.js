import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const idp_port = allocatePort();
const issuer_url = "https://localhost:" + idp_port + "/issuer"

var idp_config = {
    token: {
        expires_in_seconds: 3600,
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

var oidcProvider =
{
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    useAuthorizationClaim: true,
    requestScopes: ["offline_access"],
    supportsHumanFlows: true,
    authorizationClaim: "claim"
};

var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
test.setup();

var idp = test.get_idp(issuer_url);

test.auth("user");
idp.assert_config_requested();
idp.assert_token_requested(oidcProvider.clientId, oidcProvider.requestScopes);
test.assert_authenticated("test/user", ["test/group1", "test/group2"]);

test.teardown();
