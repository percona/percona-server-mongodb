(function() {
    'use strict';

    // prepare for the auth mode
    load('jstests/ldapauthz/_setup.js');

    // test command line parameters related to LDAP authorization
    var conn = MongoRunner.runMongod({
        auth: '',
        ldapServers: TestData.ldapServers,
        ldapTransportSecurity: 'none',
        ldapBindMethod: 'simple',
        ldapQueryUser: TestData.ldapQueryUser,
        ldapQueryPassword: TestData.ldapQueryPassword,
        ldapAuthzQueryTemplate: TestData.ldapAuthzQueryTemplate,
        setParameter: {authenticationMechanisms: 'PLAIN,SCRAM-SHA-256,SCRAM-SHA-1'}
    });

    assert(conn, "Cannot start mongod instance");

    // load check roles routine
    load('jstests/ldapauthz/_check.js');

    var db = conn.getDB('$external');

    shortusernames.forEach(function(entry){
        const username = 'cn=' + entry + ',dc=percona,dc=com';
        const userpwd = entry + '9a5S';

        print('authenticating ' + username);
        assert(db.auth({
            user: username,
            pwd: userpwd,
            mechanism: 'PLAIN'
        }));

        // ensure user have got correct set of privileges
        checkConnectionStatus(username, db.runCommand({connectionStatus: 1}));
    });

    MongoRunner.stopMongod(conn);
})();

