// test that system.users writes get audited

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

var testDBName = 'audit_system_users_authz';

auditTest(
    '{create/drop/update}User',
    function(m) {
        testDB = m.getDB(testDBName);

        var adminDB = m.getDB('admin');
        adminDB.auth('admin','admin');

        // enable 'auditAuthorizationSuccess' to check successful authorization events
        adminDB.runCommand({ setParameter: 1, 'auditAuthorizationSuccess': true });

        const beforeAuthChecks = Date.now();
        const beforeCreateUser = Date.now();
        var userObj = { user: 'john', pwd: 'john', roles: [ { role:'userAdmin', db:testDBName} ] };
        testDB.createUser(userObj);

        const beforeUpdateUser = Date.now();
        var updateObj = { roles: [ { role:'userAdmin', db:testDBName}, { role:'dbAdmin', db:testDBName} ] }
        testDB.updateUser(userObj.user, updateObj);

        const beforeDropUser = Date.now();
        testDB.dropUser(userObj.user);

        // disble 'auditAuthorizationSuccess' to prevent side effects of auditing getAuditEventsCollection()
        adminDB.runCommand({ setParameter: 1, 'auditAuthorizationSuccess': false });

        const beforeLoad = Date.now();
        var auditColl = getAuditEventsCollection(m, testDBName);

        assert.eq(1, auditColl.count({
            atype: "createUser",
            ts: withinInterval(beforeCreateUser, beforeLoad),
            'param.db': testDBName,
            'param.user': userObj.user,
            //'param.roles': userObj.roles,
            'param.roles': { $elemMatch: userObj.roles[0] },
            result: 0,
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        assert.eq(1, auditColl.count({
            atype: "updateUser",
            ts: withinInterval(beforeUpdateUser, beforeLoad),
            'param.db': testDBName,
            'param.user': userObj.user,
            //'param.roles': updateObj.roles,
            'param.roles': { $elemMatch: updateObj.roles[0] },
            'param.roles': { $elemMatch: updateObj.roles[1] },
            result: 0,
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        assert.eq(1, auditColl.count({
            atype: "dropUser",
            ts: withinInterval(beforeDropUser, beforeLoad),
            'param.db': testDBName,
            'param.user': userObj.user,
            result: 0,
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        // Successful authorization events
        // We expect events from 3 operations: insert, update, delete
        assert.eq(3, auditColl.count({
            atype: "authCheck",
            ts: withinInterval(beforeAuthChecks, beforeLoad),
            'param.ns': 'admin.system.users',
            result: 0, // <-- Authorization successful
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));
    },
    { /* no special mongod options */ }
);
