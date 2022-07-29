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

        const beforeCmd = Date.now();

        // Admin should be allowed to perform the operation.
        // NOTE: We expect NOT to see an audit event
        // when an 'admin' user performs this operation.
        var adminDB = m.getDB('admin');
        adminDB.auth('admin','admin');
        assert.writeOK(testDB.foo.insert({'_id':1}));

        // Admin tries to run a query with auditAuthorizationSuccess=false and then
        // with auditAuthorizationSuccess=true. Only one event should be logged
        var cursor = testDB.foo.find( {_id:1} );
        assert(cursor.hasNext());
        cursor.next();
        adminDB.runCommand({ setParameter: 1, 'auditAuthorizationSuccess': true });
        cursor = testDB.foo.find( {_id:1} );
        assert(cursor.hasNext());
        cursor.next();
        adminDB.runCommand({ setParameter: 1, 'auditAuthorizationSuccess': false });
        adminDB.logout();

        // User (tom) with no permissions logs in.
        var r = testDB.auth('tom', 'tom');
        assert(r);

        // Tom tries to perform a query, but will only
        // fail when he accesses the document in the
        // returned cursor.  This will throw, so we 
        // have to ignore that exception in this test.
        cursor = testDB.foo.find( {_id:1} );
        assert.neq(null, cursor);
        assert.throws( function(){ cursor.next(); } );

        // Tom logs out.
        testDB.logout();

        // Verify that audit event was inserted.
        const beforeLoad = Date.now();
        auditColl = getAuditEventsCollection(m, testDBName, undefined, true);

        // Audit event for user tom
        assert.eq(1, auditColl.count({
            atype: "authCheck",
            ts: withinInterval(beforeCmd, beforeLoad),
            users: { $elemMatch: { user:'tom', db:testDBName} },
            'param.ns': testDBName + '.' + 'foo',
            'param.command': 'find',
            result: 13, // <-- Unauthorized error, see error_codes.err...
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        // Audit event for user admin
        assert.eq(1, auditColl.count({
            atype: "authCheck",
            ts: withinInterval(beforeCmd, beforeLoad),
            users: { $elemMatch: { user:'admin', db:'admin'} },
            'param.ns': testDBName + '.' + 'foo',
            'param.command': 'find',
            result: 0, // <-- Authorization successful
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));
    },
    { auth:"" }
);
