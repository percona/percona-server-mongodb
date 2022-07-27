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

        const beforeCmd = Date.now();

        // Admin user logs in
        var adminDB = m.getDB('admin');
        adminDB.auth('admin','admin');

        // Admin tries to get current operations first with
        // auditAuthorizationSuccess=false and then with auditAuthorizationSuccess=true. Only
        // one event should be logged
        var operation = testDB.currentOp(true);
        adminDB.runCommand({ setParameter: 1, 'auditAuthorizationSuccess': true });
        operation = testDB.currentOp(true);
        adminDB.runCommand({ setParameter: 1, 'auditAuthorizationSuccess': false });

        // admin logout
        adminDB.logout();

        // User (tom) with no permissions logs in.
        var r = testDB.auth('tom', 'tom');
        assert(r);

        // Tom tries to get the current operations..
        var operation = testDB.currentOp(true);
        // NOTE: This doesn't seem to set the error message on the current db!?!

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
            'param.command': 'aggregate',
            result: 13, // <-- Unauthorized error, see error_codes.err...
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        // Audit event for user admin
        assert.eq(1, auditColl.count({
            atype: "authCheck",
            ts: withinInterval(beforeCmd, beforeLoad),
            users: { $elemMatch: { user:'admin', db:'admin'} },
            'param.command': 'aggregate',
            result: 0, // <-- Authorization successful
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));
    },
    { auth:"" }
);
