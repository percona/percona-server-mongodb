// test that authzKillOp gets called.

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

var testDBName = 'audit_authz_kill_op';

auditTest(
    'authzKillOp',
    function(m) {
        createAdminUserForAudit(m);
        var testDB = m.getDB(testDBName);
        var user = createNoPermissionUserForAudit(m, testDB);

        // Admin should be allowed to perform the operation.
        // NOTE: We expect NOT to see an audit event
        // when an 'admin' user performs this operation.
        var adminDB = m.getDB('admin');
        adminDB.auth('admin','admin');

        // Admin tries to kill an operation with auditAuthorized=false
        var operation = testDB.currentOp(false);
        assert.eq(null, testDB.getLastError());
        var first = operation.inprog[0];
        var id = first.opid;
        testDB.killOp(id);

        // Admin tries to kill an operation with auditAuthorized=true, only
        // one operation should be killed
        operation = testDB.currentOp(false);
        assert.eq(null, testDB.getLastError());
        first = operation.inprog[0];
        id = first.opid;
        adminDB.runCommand({ setParameter: 1, 'auditAuthorized': true });
        testDB.killOp(id);
        adminDB.runCommand({ setParameter: 1, 'auditAuthorized': false });

        // Get next operation id to kill as tom
        operation = testDB.currentOp(false);
        assert.eq(null, testDB.getLastError());
        first = operation.inprog[0];
        id = first.opid;
        adminDB.logout();

        // User (tom) with no permissions logs in.
        var r = testDB.auth('tom', 'tom');
        assert(r);

        // Tom tries to kill this process.
        testDB.killOp(id);

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
            'params.command': 'killOp',
            result: 13, // <-- Unauthorized error, see error_codes.err...
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        // Audit event for user admin
        assert.eq(1, auditColl.count({
            atype: "authCheck",
            ts: withinTheLastFewSeconds(),
            users: { $elemMatch: { user:'admin', db:'admin'} },
            'params.command': 'killOp',
            result: 0, // <-- Authorization successful
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));
    },
    { auth:"" }
);
