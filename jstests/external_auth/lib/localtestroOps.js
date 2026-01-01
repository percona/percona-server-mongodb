// name: Local user with read (only) access to 'test'
// mode: auth

function localtestroOpsRun() {
    "use strict";
    var db = conn.getDB("test");

    assert(
        db.auth({
            user: "localtestro",
            pwd: "localtestro9a5S",
        }),
    );

    // check who we are authenticated as

    var res = db.runCommand({connectionStatus: 1});
    assert(res.authInfo.authenticatedUsers[0].user == "localtestro");

    // test access

    load("jstests/external_auth/lib/_functions.js");

    authuser_assertro(db.getSiblingDB("test"));
    authuser_assertnone(db.getSiblingDB("other"));
    authuser_assertnone(db.getSiblingDB("yetanother"));
}

localtestroOpsRun();
