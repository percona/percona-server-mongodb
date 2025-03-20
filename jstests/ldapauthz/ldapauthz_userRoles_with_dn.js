(function() {
    'use strict';

    // prepare for the auth mode
    load('jstests/ldapauthz/_setup.js');

    // test command line parameters related to LDAP authorization
    var conn = MongoRunner.runMongod({
        auth: '',
        ldapServers: 'localhost:389',
        ldapTransportSecurity: 'none',
        ldapBindMethod: 'simple',
        ldapQueryUser: 'cn=admin,dc=percona,dc=com',
        ldapQueryPassword: 'password',
        ldapAuthzQueryTemplate: 'dc=percona,dc=com?dn?sub?(&(objectClass=groupOfNames)(member={USER}))',
        setParameter: {authenticationMechanisms: 'PLAIN,SCRAM-SHA-256,SCRAM-SHA-1'}
    });

    assert(conn, "Cannot start mongod instance");

    // load check roles routine
    load('jstests/ldapauthz/_check.js');

    var db = conn.getDB('$external');

    const username = 'cn=' + "exttestro" + ',dc=percona,dc=com';
    const userpwd = 'exttestro9a5S';

    print('authenticating ' + username);

    assert(db.auth({
        user: username,
        pwd: userpwd,
        mechanism: 'PLAIN'
    }));

    var authenticatedUserRoles = JSON.stringify(db.runCommand({connectionStatus: 1}).authInfo.authenticatedUserRoles[0])
    assert(authenticatedUserRoles == '{"role":"cn=testreaders,dc=percona,dc=com","db":"admin"}')

    db.logout();

    MongoRunner.stopMongod(conn);
})();
