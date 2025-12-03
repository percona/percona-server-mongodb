/*
 * This file runs all external_auth tests for PSMDB
 */

function runTestScript(testFile) {
    jsTestLog("---- START: ".concat(testFile, " ----"));
    conn = MongoRunner.runMongod({
        restart: conn,
        noCleanData: true,
        setParameter: "authenticationMechanisms=PLAIN,SCRAM-SHA-1",
        auth: ""
    });
    load(testFile);
    MongoRunner.stopMongod(conn);
    jsTestLog("---- END: ".concat(testFile, " ----"));
}

// setup a test database
var conn = MongoRunner.runMongod();
load('jstests/external_auth/lib/setup.js');
MongoRunner.stopMongod(conn);

// run tests
runTestScript('jstests/external_auth/lib/addLocalUsers.js');
runTestScript('jstests/external_auth/lib/addExtUsers.js');
runTestScript('jstests/external_auth/lib/showAllUsers.js');
runTestScript('jstests/external_auth/lib/showExtUsers.js');
runTestScript('jstests/external_auth/lib/localtestroLogin.js');
runTestScript('jstests/external_auth/lib/exttestroLogin.js');
runTestScript('jstests/external_auth/lib/invalidCredentials.js');
runTestScript('jstests/external_auth/lib/localtestroOps.js');
runTestScript('jstests/external_auth/lib/localtestrwOps.js');
runTestScript('jstests/external_auth/lib/localotherroOps.js');
runTestScript('jstests/external_auth/lib/localotherrwOps.js');
runTestScript('jstests/external_auth/lib/exttestroOps.js');
runTestScript('jstests/external_auth/lib/exttestrwOps.js');
runTestScript('jstests/external_auth/lib/extotherroOps.js');
runTestScript('jstests/external_auth/lib/extotherrwOps.js');
runTestScript('jstests/external_auth/lib/extbothroOps.js');
runTestScript('jstests/external_auth/lib/extbothrwOps.js');
runTestScript('jstests/external_auth/lib/exttestrootherrwOps.js');
runTestScript('jstests/external_auth/lib/exttestrwotherroOps.js');

print("SUCCESS external_auth.js");
