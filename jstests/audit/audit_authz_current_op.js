// test that authzInProg gets called.

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

var testDBName = 'audit_authz_in_prog';

auditTest(
    'authzInProg',
    function(m) {
        createAdminUserForAudit(m);
        var testDB = m.getDB(testDBName);
        var user = createNoPermissionUserForAudit(m, testDB);

        // Admin user logs in
        var adminDB = m.getDB('admin');
        adminDB.auth('admin','admin');

        // Admin tries to get current operations first with
        // auditAuthorized=false and then with auditAuthorized=true. Only
        // one event should be logged
        var operation = testDB.currentOp(true);
        adminDB.runCommand({ setParameter: 1, 'auditAuthorized': true });
        operation = testDB.currentOp(true);
        adminDB.runCommand({ setParameter: 1, 'auditAuthorized': false });

        // admin logout
        adminDB.logout();

        // User (tom) with no permissions logs in.
        var r = testDB.auth('tom', 'tom');
        assert(r);

        // Tom tries to get the current operations..
        operation = testDB.currentOp(true);
        // NOTE: This doesn't seem to set the error message on the current db!?!

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
            'params.command': 'currentOp',
            result: 13, // <-- Unauthorized error, see error_codes.err...
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        // Audit event for user admin
        assert.eq(1, auditColl.count({
            atype: "authCheck",
            ts: withinTheLastFewSeconds(),
            users: { $elemMatch: { user:'admin', db:'admin'} },
            'params.command': 'currentOp',
            result: 0, // <-- Authorization successful
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));
    },
    { auth:"" }
);
