// test that authenticate gets audited

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

// Creates a User with userAdmin permissions and name john
var createUserFromObj = function(m, db, obj) {
    var adminDB = m.getDB('admin');
    adminDB.auth('admin', 'admin');
    db.createUser(obj);
    adminDB.logout();
};

var testDBName = 'audit_authenticate';
auditTest(
    'authenticate',
    function(m) {
        createAdminUserForAudit(m);
        var testDB = m.getDB(testDBName);
        var userObj = {user: 'john', pwd: 'john', roles: [{role: 'userAdmin', db: testDBName}]};
        createUserFromObj(m, testDB, userObj);

        let beforeCmd = Date.now();
        assert(testDB.auth('john', 'john'), "could not auth as john (pwd john)");
        testDB.logout();

        let beforeLoad = Date.now();
        var auditColl = getAuditEventsCollection(m, testDBName, undefined, true);
        assert.eq(1,
                  auditColl.count({
                      atype: 'authenticate',
                      ts: withinInterval(beforeCmd, beforeLoad),
                      'param.user': 'john',
                      'param.mechanism': 'SCRAM-SHA-256',
                      'param.db': testDBName,
                      result: 0,
                  }),
                  "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        beforeCmd = Date.now();
        assert(!testDB.auth('john', 'nope'), "incorrectly able to auth as john (pwd nope)");

        // ErrorCodes::AuthenticationFailed in src/mongo/base/error_codes.err
        var authenticationFailureCode = 18;

        beforeLoad = Date.now();
        var auditColl = getAuditEventsCollection(m, testDBName, undefined, true);
        assert.eq(1,
                  auditColl.count({
                      atype: 'authenticate',
                      ts: withinInterval(beforeCmd, beforeLoad),
                      'param.user': 'john',
                      'param.mechanism': 'SCRAM-SHA-256',
                      'param.db': testDBName,
                      result: authenticationFailureCode,
                  }),
                  "FAILED, audit log: " + tojson(auditColl.find().toArray()));
    },
    // Enable auth for this test
    {auth: ""});
