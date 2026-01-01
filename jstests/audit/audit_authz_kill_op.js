// test that authzKillOp gets called.

import {
    auditTest,
    createAdminUserForAudit,
    createNoPermissionUserForAudit,
    getAuditEventsCollection,
    withinInterval,
} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_authz_kill_op";

auditTest(
    "authzKillOp",
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

        // Admin tries to kill an operation with auditAuthorizationSuccess=false
        let operation = testDB.currentOp(false);
        let first = operation.inprog[0];
        let id = first.opid;
        testDB.killOp(id);

        // Admin tries to kill an operation with auditAuthorizationSuccess=true, only
        // one operation should be killed
        operation = testDB.currentOp(false);
        first = operation.inprog[0];
        id = first.opid;
        adminDB.runCommand({setParameter: 1, "auditAuthorizationSuccess": true});
        testDB.killOp(id);
        adminDB.runCommand({setParameter: 1, "auditAuthorizationSuccess": false});

        // Get next operation id to kill as tom
        operation = testDB.currentOp(false);
        first = operation.inprog[0];
        id = first.opid;
        adminDB.logout();

        // User (tom) with no permissions logs in.
        let r = testDB.auth("tom", "tom");
        assert(r);

        // Tom tries to kill this process.
        testDB.killOp(id);

        // Tom logs out.
        testDB.logout();

        // Verify that audit event was inserted.
        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName, undefined, true);

        // Audit event for user tom
        assert.eq(
            1,
            auditColl.count({
                atype: "authCheck",
                ts: withinInterval(beforeCmd, beforeLoad),
                users: {$elemMatch: {user: "tom", db: testDBName}},
                "param.command": "killOp",
                result: 13, // <-- Unauthorized error, see error_codes.err...
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );

        // Audit event for user admin
        assert.eq(
            1,
            auditColl.count({
                atype: "authCheck",
                ts: withinInterval(beforeCmd, beforeLoad),
                users: {$elemMatch: {user: "admin", db: "admin"}},
                "param.command": "killOp",
                result: 0, // <-- Authorization successful
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );
    },
    {auth: ""},
);
