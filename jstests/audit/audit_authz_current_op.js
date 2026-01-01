// test that authzInProg gets called.

import {
    auditTest,
    createAdminUserForAudit,
    createNoPermissionUserForAudit,
    getAuditEventsCollection,
    withinInterval,
} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_authz_in_prog";

auditTest(
    "authzInProg",
    function (m) {
        createAdminUserForAudit(m);
        let testDB = m.getDB(testDBName);
        let user = createNoPermissionUserForAudit(m, testDB);

        const beforeCmd = Date.now();

        // Admin user logs in
        let adminDB = m.getDB("admin");
        adminDB.auth("admin", "admin");

        // Admin tries to get current operations first with
        // auditAuthorizationSuccess=false and then with auditAuthorizationSuccess=true. Only
        // one event should be logged
        let operation = testDB.currentOp(true);
        adminDB.runCommand({setParameter: 1, "auditAuthorizationSuccess": true});
        operation = testDB.currentOp(true);
        adminDB.runCommand({setParameter: 1, "auditAuthorizationSuccess": false});

        // admin logout
        adminDB.logout();

        // User (tom) with no permissions logs in.
        let r = testDB.auth("tom", "tom");
        assert(r);

        // Tom tries to get the current operations..
        operation = testDB.currentOp(true);
        // NOTE: This doesn't seem to set the error message on the current db!?!

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
                "param.command": "aggregate",
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
                "param.command": "aggregate",
                result: 0, // <-- Authorization successful
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );
    },
    {auth: ""},
);
