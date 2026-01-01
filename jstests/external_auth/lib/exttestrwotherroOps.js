// note: run setup.js first with mongod --auth disabled
// then run this with mongod --auth enabled

// name: External user with readWrite on 'test' and read (only) on 'other'
// mode: auth

function exttestrwotherroOpsRun() {
    "use strict";
    var testUser = "exttestrwotherro";

    var db = conn.getDB("$external");

    assert(
        db.auth({
            user: testUser,
            pwd: testUser + "9a5S",
            mechanism: "PLAIN",
            digestPassword: false,
        }),
    );

    // check who we are authenticated as

    var res = db.runCommand({connectionStatus: 1});

    assert(res.authInfo.authenticatedUsers[0].user == testUser);

    // test access

    load("jstests/external_auth/lib/_functions.js");

    authuser_assertrw(db.getSiblingDB("test"));
    authuser_assertro(db.getSiblingDB("other"));
    authuser_assertnone(db.getSiblingDB("yetanother"));
}

exttestrwotherroOpsRun();
