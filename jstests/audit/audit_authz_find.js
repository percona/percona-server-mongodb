// test that authzQuery gets called.

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

var testDBName = 'audit_authz_query';

auditTest(
    'authzQuery',
    function(m) {
        createAdminUserForAudit(m);
        var testDB = m.getDB(testDBName);
        var user = createNoPermissionUserForAudit(m, testDB);

        // Admin should be allowed to perform the operation.
        // NOTE: We expect NOT to see an audit event
        // when an 'admin' user performs this operation.
        var adminDB = m.getDB('admin');
        adminDB.auth('admin','admin');
        assert.writeOK(testDB.foo.insert({'_id':1}));

        // Admin tries to run a query with auditAuthorized=false and then
        // with auditAuthorized=true. Only one event should be logged
        var cursor = testDB.foo.find( {_id:1} );
        assert.eq(null, testDB.getLastError());
        cursor.next();
        adminDB.runCommand({ setParameter: 1, 'auditAuthorized': true });
        cursor = testDB.foo.find( {_id:1} );
        assert.eq(null, testDB.getLastError());
        cursor.next();
        adminDB.runCommand({ setParameter: 1, 'auditAuthorized': false });
        adminDB.logout();

        // User (tom) with no permissions logs in.
        var r = testDB.auth('tom', 'tom');
        assert(r);

        // Tom tries to perform a query, but will only
        // fail when he accesses the document in the
        // returned cursor.  This will throw, so we 
        // have to ignore that exception in this test.
        cursor = testDB.foo.find( {_id:1} );
        assert.eq(null, testDB.getLastError());
        assert.throws( function(){ cursor.next(); } );

        // Tom logs out.
        testDB.logout();

        // Verify that audit event was inserted.
        beforeLoad = Date.now();
        auditColl = getAuditEventsCollection(m, undefined, true);

        // Audit event for user tom
        assert.eq(1, auditColl.count({
            atype: "authCheck",
            ts: withinFewSecondsBefore(beforeLoad),
            users: { $elemMatch: { user:'tom', db:testDBName} },
            'params.ns': testDBName + '.' + 'foo',
            'params.command': 'find',
            result: 13, // <-- Unauthorized error, see error_codes.err...
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        // Audit event for user admin
        assert.eq(1, auditColl.count({
            atype: "authCheck",
            ts: withinTheLastFewSeconds(),
            users: { $elemMatch: { user:'admin', db:'admin'} },
            'params.ns': testDBName + '.' + 'foo',
            'params.command': 'find',
            result: 0, // <-- Authorization successful
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

    },
    { auth:"" }
);
