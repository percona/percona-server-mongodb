// test that authzCommand gets called.

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

var testDBName = 'audit_authz_command';

auditTest('authzCommand', function(m) {
    createAdminUserForAudit(m);
    var testDB = m.getDB(testDBName);
    var user = createNoPermissionUserForAudit(m, testDB);

    const beforeCmd = Date.now();

    // Admin user logs in
    var adminDB = m.getDB('admin');
    adminDB.auth('admin', 'admin');

    // Admin tries to run a command with auditAuthorizationSuccess=false and then
    // with auditAuthorizationSuccess=true. Only one event should be logged
    assert.writeOK(testDB.foo.insert({'_id': 1}));
    testDB.runCommand({count: 'foo'});
    adminDB.runCommand({setParameter: 1, 'auditAuthorizationSuccess': true});
    testDB.runCommand({count: 'foo'});
    adminDB.runCommand({setParameter: 1, 'auditAuthorizationSuccess': false});
    adminDB.logout();

    // User (tom) with no permissions logs in.
    var r = testDB.auth('tom', 'tom');
    assert(r);

    // Tom tries to perform a command.
    testDB.runCommand({count: 'foo'});

    // Tom logs out.
    testDB.logout();

    // Verify that audit event was inserted.
    const beforeLoad = Date.now();
    auditColl = getAuditEventsCollection(m, testDBName, undefined, true);

    // Audit event for user tom.
    assert.eq(1,
              auditColl.count({
                  atype: "authCheck",
                  ts: withinInterval(beforeCmd, beforeLoad),
                  users: {$elemMatch: {user: 'tom', db: testDBName}},
                  'param.ns': testDBName + '.' +
                      'foo',
                  'param.command': 'count',
                  result: 13,  // <-- Unauthorized error, see error_codes.err...
              }),
              "FAILED, audit log: " + tojson(auditColl.find().toArray()));

    // Audit event for user admin
    assert.eq(1,
              auditColl.count({
                  atype: "authCheck",
                  ts: withinInterval(beforeCmd, beforeLoad),
                  users: {$elemMatch: {user: 'admin', db: 'admin'}},
                  'param.ns': testDBName + '.' +
                      'foo',
                  'param.command': 'count',
                  result: 0,  // <-- Authorization successful
              }),
              "FAILED, audit log: " + tojson(auditColl.find().toArray()));
}, {auth: ""});
