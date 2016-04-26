// test that authzCommand gets called.

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

var testDBName = 'audit_authz_command';

auditTest(
    'authzCommand',
    function(m) {
        createAdminUserForAudit(m);
        var testDB = m.getDB(testDBName);
        var user = createNoPermissionUserForAudit(m, testDB);

        // Admin user logs in
        var adminDB = m.getDB('admin');
        adminDB.auth('admin','admin');

        // Admin tries to run a command with auditAuthorized=false and then
        // with auditAuthorized=true. Only one event should be logged
        assert.writeOK(testDB.foo.insert({'_id': 1}));
        testDB.runCommand( {count : 'foo'} );
        adminDB.runCommand({ setParameter: 1, 'auditAuthorized': true });
        testDB.runCommand( {count : 'foo'} );
        adminDB.runCommand({ setParameter: 1, 'auditAuthorized': false });
        adminDB.logout();

        // User (tom) with no permissions logs in.
        var r = testDB.auth('tom', 'tom');
        assert(r);

        // Tom tries to perform a command.
        testDB.runCommand( {count : 'foo'} );

        // Tom logs out.
        testDB.logout();

        // Verify that audit event was inserted.
        beforeLoad = Date.now();
        auditColl = getAuditEventsCollection(m, undefined, true);

        // Audit event for user tom.
        assert.eq(1, auditColl.count({
            atype: "authCheck",
            ts: withinFewSecondsBefore(beforeLoad),
            users: { $elemMatch: { user:'tom', db:testDBName} },
            'params.ns': testDBName + '.' + 'foo',
            'params.command': 'count',
            result: 13, // <-- Unauthorized error, see error_codes.err...
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        // Audit event for user admin
        assert.eq(1, auditColl.count({
            atype: "authCheck",
            ts: withinTheLastFewSeconds(),
            users: { $elemMatch: { user:'admin', db:'admin'} },
            'params.ns': testDBName + '.' + 'foo',
            'params.command': 'count',
            result: 0, // <-- Authorization successful
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));
    },
    { auth:"" }
);
