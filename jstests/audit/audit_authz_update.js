// test that authzUpdate gets called.

import {
    auditTest,
    createAdminUserForAudit,
    createNoPermissionUserForAudit,
    getAuditEventsCollection,
    withinInterval,
} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_authz_update";

auditTest(
    "authzUpdate",
    function (m) {
        createAdminUserForAudit(m);
        let testDB = m.getDB(testDBName);
        let user = createNoPermissionUserForAudit(m, testDB);

        const beforeCmd = Date.now();

        // Admin should be allowed to perform the operation.
        // NOTE: We expect NOT to see an audit event
        // when an 'admin' user performs this operation.
        let adminDB = m.getDB("admin");
        adminDB.auth("admin", "admin");
        assert.writeOK(testDB.foo.insert({"_id": 1, "bar": 1}));

        // Admin tries to run an update with auditAuthorizationSuccess=false and then
        // with auditAuthorizationSuccess=true only one event should be logged
        assert.writeOK(testDB.foo.update({"_id": 1}, {"bar": 3}));
        adminDB.runCommand({setParameter: 1, "auditAuthorizationSuccess": true});
        assert.writeOK(testDB.foo.update({"_id": 1}, {"bar": 4}));
        adminDB.runCommand({setParameter: 1, "auditAuthorizationSuccess": false});
        adminDB.logout();

        // User with no permissions logs in.
        testDB.auth("tom", "tom");

        // Tom updates data.
        assert.writeError(testDB.foo.update({"_id": 1}, {"bar": 2}));

        // Tom logs out.
        testDB.logout();

        // Verify that audit event was inserted.
        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName, undefined, true);

        // Audit event for user tom.
        assert.eq(
            1,
            auditColl.count({
                atype: "authCheck",
                ts: withinInterval(beforeCmd, beforeLoad),
                users: {$elemMatch: {user: "tom", db: testDBName}},
                "param.ns": testDBName + "." + "foo",
                "param.command": "update",
                result: 13, // <-- Unauthorized error, see error_codes.err...
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );

        // Audit event for user admin.
        assert.eq(
            1,
            auditColl.count({
                atype: "authCheck",
                ts: withinInterval(beforeCmd, beforeLoad),
                users: {$elemMatch: {user: "admin", db: "admin"}},
                "param.ns": testDBName + "." + "foo",
                "param.command": "update",
                result: 0, // <-- Authorization successful
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );

        // Audit event for update operation
        assert.eq(
            0,
            auditColl.count({
                atype: "updateOperation",
                ts: withinInterval(beforeCmd, beforeLoad),
                users: {$elemMatch: {user: "admin", db: "admin"}},
                "param.ns": testDBName + "." + "foo",
                "param.doc.bar": 3,
                result: 0, // <-- We do not expect this update operations to be logged
            }),
            "FAILED, update operation has been found in the audit log: " + tojson(auditColl.find().toArray()),
        );
    },
    {auth: ""},
);
