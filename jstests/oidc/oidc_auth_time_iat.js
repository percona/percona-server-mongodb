import {OIDCFixture} from 'jstests/oidc/lib/oidc_fixture.js';

function seconds_since_epoch(date) {
    return Math.floor(date.getTime() / 1000);
}

function add_one_hour(date) {
    date.setHours(date.getHours() + 1);
    return date;
}

function _check_auth_success(test) {
    let conn = test.create_conn();
    assert(test.auth(conn, "bravo"), "Failed to authenticate");
    test.assert_authenticated(conn, "alpha/bravo", [{role: "readWrite", db: "test_db"}]);
}

function _check_auth_failure(expected_error, test) {
    const expected_log = {
        msg: "Failed to authenticate",
        attr: {
            mechanism: "MONGODB-OIDC",
            error: "BadValue: Invalid JWT :: caused by :: " + expected_error,
        }
    };
    let conn = test.create_conn();
    assert(!test.auth(conn, "bravo"), "Authentication succeeded when it must not");
    assert(test.checkLogExists(expected_log), "Expected log not found");
}

function _run(token_payload_extra, check) {
    const issuer_url = OIDCFixture.allocate_issuer_url();
    const oidcProvider = {
        issuer: issuer_url,
        clientId: "clientId",
        audience: "audience",
        authNamePrefix: "alpha",
        useAuthorizationClaim: false,
    };
    const idp_config = {
        token: {
            payload: Object.assign({sub: "bravo", aud: "audience"}, token_payload_extra),
        },
    };

    let test = new OIDCFixture(
        {oidcProviders: [oidcProvider], idps: [{url: issuer_url, config: idp_config}]});
    test.setup();
    test.create_user("alpha/bravo", [{role: "readWrite", db: "test_db"}]);

    check(test);

    test.teardown();
}

function assert_auth_success(token_payload_extra) {
    _run(token_payload_extra, _check_auth_success);
}

function assert_auth_failure(token_payload_extra, expected_error) {
    _run(token_payload_extra, _check_auth_failure.bind(null, expected_error));
}

assert_auth_success({auth_time: seconds_since_epoch(new Date())});
assert_auth_failure({auth_time: seconds_since_epoch(add_one_hour(new Date()))},
                    "`auth_time` is in the future");

assert_auth_success({iat: seconds_since_epoch(new Date())});
assert_auth_failure({iat: seconds_since_epoch(add_one_hour(new Date()))}, "`iat` is in the future");

assert_auth_success({
    auth_time: seconds_since_epoch(new Date()) - 2,
    iat: seconds_since_epoch(new Date()),
});
let d = new Date();
assert_auth_failure(
    {
        auth_time: seconds_since_epoch(d) + 2,
        iat: seconds_since_epoch(d),
    },
    "`auth_time` is more recent than `iat`");
