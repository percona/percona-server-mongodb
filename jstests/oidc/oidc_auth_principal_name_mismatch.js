import {OIDCFixture} from 'jstests/oidc/lib/oidc_fixture.js';

const issuer_url = OIDCFixture.allocate_issuer_url();

const oidcProvider = {
    issuer: issuer_url,
    clientId: "clientId",
    audience: "audience",
    authNamePrefix: "alpha",
    useAuthorizationClaim: false,
};

{
    const idp_config = {
        token: {
            payload: {
                sub: "bravo",
                aud: "audience",
            }
        },
    };

    let test = new OIDCFixture(
        {oidcProviders: [oidcProvider], idps: [{url: issuer_url, config: idp_config}]});
    test.setup();
    test.create_user("alpha/bravo", [{role: "readWrite", db: "test_db"}]);

    let conn = test.create_conn();
    assert(test.auth(conn, "bravo"), "Failed to authenticate");
    test.assert_authenticated(conn, "alpha/bravo", [{role: "readWrite", db: "test_db"}]);

    test.teardown();
}
{
    const idp_config = {
        token: {
            payload: {
                sub: "charlie",
                aud: "audience",
            }
        },
    };

    let test = new OIDCFixture(
        {oidcProviders: [oidcProvider], idps: [{url: issuer_url, config: idp_config}]});
    test.setup();
    test.create_user("alpha/bravo", [{role: "readWrite", db: "test_db"}]);

    let conn = test.create_conn();
    // The `mongo` client initiates a SASL conversation (step 1) with `mongod` providing principal
    // name "bravo", which is remembered by `mongod`, and gets identity provider URL in response.
    // Upon calling the URL, the `mongo` client gets an access token with principal name "charlie"
    // (please see `idp_config.token.payload.sub` value) from the identity provider. When `mongo`
    // continues the SASL conversation (step 2), `mongod` detects that the principal name in the
    // token is not equal to that at step 1.
    assert(!test.auth(conn, "bravo"), "Authentication succeeded when it must not");

    const expectedLog = {
        msg: "Failed to authenticate",
        attr: {
            mechanism: "MONGODB-OIDC",
            error: "BadValue: Invalid JWT :: caused by :: " +
                "principal names at SASL step 1 (`bravo`) and " +
                "step 2 (`charlie`) are not equal",
        }
    };
    assert(test.checkLogExists(expectedLog), "Expected log not found");

    test.teardown();
}
