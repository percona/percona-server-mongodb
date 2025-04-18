import { OIDCFixture } from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

var idp_config = {
    token: {
        payload: {
            aud: "audience",
            sub: "user",
            custom_claim: "custom_username",
            claim: [
                "group1",
                "group2",
            ],
        }
    },
};

var oidcProviderBase = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "test",
    principalName: "custom_claim",
    authorizationClaim: "claim",
};

{
    var oidcProvider = oidcProviderBase;
    // don't use claims
    oidcProvider.useAuthorizationClaim = false;

    var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
    test.setup();
    test.create_user("test/custom_username");

    var conn = test.create_conn();

    test.auth(conn, "user");
    // verify user is authenticated with no roles
    test.assert_authenticated(conn, "test/custom_username", []);

    test.teardown();
}

{
    var oidcProvider = oidcProviderBase;
    // use claims
    oidcProvider.useAuthorizationClaim = true;

    var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
    test.setup();

    var conn = test.create_conn();

    test.auth(conn, "user");
    // verify user is authenticated with correct roles
    test.assert_authenticated(conn, "test/custom_username", ["test/group1", "test/group2"]);

    test.teardown();
}

{
    var oidcProvider = oidcProviderBase;
    // no claims
    oidcProvider.useAuthorizationClaim = false;
    // set default value
    oidcProvider.principalName = "sub";

    var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
    test.setup();
    test.create_user("test/user");

    var conn = test.create_conn();

    test.auth(conn, "user");
    // verify user is authenticated with correct roles
    test.assert_authenticated(conn, "test/user", []);

    test.teardown();
}

{
    var oidcProvider = oidcProviderBase;
    // use claims
    oidcProvider.useAuthorizationClaim = false;
    oidcProvider.principalName = "some_other_custom_claim";

    var test = new OIDCFixture({ oidcProviders: [oidcProvider], idps: [{ url: issuer_url, config: idp_config }] });
    test.setup();

    var conn = test.create_conn();

    assert(!test.auth(conn, "user"), "Authentication should fail due to missing claim for principalName");

    test.teardown();
}
