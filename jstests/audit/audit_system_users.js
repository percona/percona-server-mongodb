// test that system.users writes get audited

import {auditTest, getAuditEventsCollection, withinInterval} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_create_drop_update_user";

auditTest(
    "{create/drop/update}User",
    function (m) {
        let testDB = m.getDB(testDBName);

        let adminDB = m.getDB("admin");
        adminDB.auth("admin", "admin");

        const beforeAuthChecks = Date.now();
        const beforeCreateUser = Date.now();
        let userObj = {user: "john", pwd: "john", roles: [{role: "userAdmin", db: testDBName}]};
        testDB.createUser(userObj);

        const beforeUpdateUser = Date.now();
        let updateObj = {
            roles: [
                {role: "userAdmin", db: testDBName},
                {role: "dbAdmin", db: testDBName},
            ],
        };
        testDB.updateUser(userObj.user, updateObj);

        const beforeDropUser = Date.now();
        testDB.dropUser(userObj.user);

        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName);

        assert.eq(
            1,
            auditColl.count({
                atype: "createUser",
                ts: withinInterval(beforeCreateUser, beforeLoad),
                "param.db": testDBName,
                "param.user": userObj.user,
                //'param.roles': userObj.roles,
                "param.roles": {$elemMatch: userObj.roles[0]},
                result: 0,
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );

        assert.eq(
            1,
            auditColl.count({
                atype: "updateUser",
                ts: withinInterval(beforeUpdateUser, beforeLoad),
                "param.db": testDBName,
                "param.user": userObj.user,
                //'param.roles': updateObj.roles,
                "param.roles": {$elemMatch: updateObj.roles[0]},
                "param.roles": {$elemMatch: updateObj.roles[1]},
                result: 0,
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );

        assert.eq(
            1,
            auditColl.count({
                atype: "dropUser",
                ts: withinInterval(beforeDropUser, beforeLoad),
                "param.db": testDBName,
                "param.user": userObj.user,
                result: 0,
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );

        // We don't expect any successful authorization events because by default
        // 'auditAuthorizationSuccess' is false
        assert.eq(
            0,
            auditColl.count({
                atype: "authCheck",
                ts: withinInterval(beforeAuthChecks, beforeLoad),
                "param.ns": "admin.system.users",
                result: 0, // <-- Authorization successful
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );
    },
    {
        /* no special mongod options */
    },
);
