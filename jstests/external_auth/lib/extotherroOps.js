// note: run setup.js first with mongod --auth disabled
// then run this with mongod --auth enabled

// name: External user with read (only) access to 'other'
// mode: auth

function extotherroOpsRun() {
    'use strict';
    var db = conn.getDB('$external');

    assert(db.auth(
        {user: 'extotherro', pwd: 'extotherro9a5S', mechanism: 'PLAIN', digestPassword: false}));

    // check who we are authenticated as

    var res = db.runCommand({connectionStatus: 1});

    assert(res.authInfo.authenticatedUsers[0].user == "extotherro");

    // test access

    load('jstests/external_auth/lib/_functions.js');

    authuser_assertnone(db.getSiblingDB('test'));
    authuser_assertro(db.getSiblingDB('other'));
    authuser_assertnone(db.getSiblingDB('yetanother'));
}

extotherroOpsRun();
