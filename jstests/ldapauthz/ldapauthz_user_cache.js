(function() {
    'use strict';

    // prepare for the auth mode
    load('jstests/ldapauthz/_setup.js');

    // test command line parameters related to LDAP authorization
    var conn = MongoRunner.runMongod({
        verbose: 1, // for debug output
        auth: '',
        ldapServers: TestData.ldapServers,
        ldapTransportSecurity: 'none',
        ldapBindMethod: 'simple',
        ldapQueryUser: TestData.ldapQueryUser,
        ldapQueryPassword: TestData.ldapQueryPassword,
        ldapAuthzQueryTemplate: TestData.ldapAuthzQueryTemplate,
        setParameter: {
            authenticationMechanisms: 'PLAIN,SCRAM-SHA-256,SCRAM-SHA-1',
            ldapUserCacheInvalidationInterval: 1, // 1 second
        }
    });

    assert(conn, "Cannot start mongod instance");

    // load check roles routine
    load('jstests/ldapauthz/_check.js');

    var db = conn.getDB('$external');

    const username = 'cn=' + "exttestro" + ',dc=percona,dc=com';
    const userpwd = 'exttestro9a5S';

    assert(db.auth({
        user: username,
        pwd: userpwd,
        mechanism: 'PLAIN'
    }));

    var coll = db.getSiblingDB('test').getCollection('test');

    // make sure that the invalidation thread runs at least once
    sleep(2000);
    
    clearRawMongoProgramOutput();
    // execute any command
    coll.insert({x: 1});

    // Check the log for getting user record.
    // It should be there because the cache invalidation thread
    // should have invalidated the cache and the user record
    // should be fetched again.
    const match = "Getting user record";
    const output = rawMongoProgramOutput(match);
    assert(output, "Cannot find '" + match + "' in the log");
    
    db.logout();

    MongoRunner.stopMongod(conn);
})();

