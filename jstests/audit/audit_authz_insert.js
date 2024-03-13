// test that authzInsert gets called.

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

var testDBName = 'audit_authz_insert';

auditTest(
    'authzInsert',
    function(m) {
        createAdminUserForAudit(m);
        var testDB = m.getDB(testDBName);
        var user = createNoPermissionUserForAudit(m, testDB);

        const beforeCmd = Date.now();

        // Admin should be allowed to perform the operation.
        // NOTE: We expect NOT to see an audit event when 'admin' user
        // performs this operation with auditAuthorizationSuccess=false
        var adminDB = m.getDB('admin');
        adminDB.auth('admin','admin');
        assert.writeOK(testDB.foo.insert({'_id': 1}));

        // Admin tries to run another insert with auditAuthorizationSuccess=true
        // Only one event should be logged
        adminDB.runCommand({ setParameter: 1, 'auditAuthorizationSuccess': true });
        assert.writeOK(testDB.foo.insert({'_id': 2}));
        adminDB.runCommand({ setParameter: 1, 'auditAuthorizationSuccess': false });
        adminDB.logout();

        // User with no permissions logs in.
        testDB.auth('tom', 'tom');

        // Tom inserts data.
        assert.writeError(testDB.foo.insert({'_id': 2}));

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
            'param.command': 'insert',
            result: 13, // <-- Unauthorized error, see error_codes.err...
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        // Audit event for user admin
        assert.eq(1, auditColl.count({
            atype: "authCheck",
            ts: withinInterval(beforeCmd, beforeLoad),
            users: { $elemMatch: { user:'admin', db:'admin'} },
            'param.ns': testDBName + '.' + 'foo',
            'param.command': 'insert',
            result: 0, // <-- Authorization successful
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        // Audit event for simple insert
        assert.eq(0, auditColl.count({
            atype: "insertOperation",
            ts: withinInterval(beforeCmd, beforeLoad),
            users: { $elemMatch: { user:'admin', db:'admin'} },
            'param.ns': testDBName + '.' + 'foo',
            'param.doc._id': 1,
            result: 0, // <-- We do not expect this insert operations to be logged
        }), "FAILED, insert operation has been found in the audit log: " + tojson(auditColl.find().toArray()));
    },
    { auth:"" }
);
