// test that authzCommand gets called.

import {
    auditTest,
    createAdminUserForAudit,
    createNoPermissionUserForAudit,
    getAuditEventsCollection,
    withinInterval,
} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_authz_command";

auditTest(
    "authzCommand",
    function (m) {
        createAdminUserForAudit(m);
        let testDB = m.getDB(testDBName);
        let user = createNoPermissionUserForAudit(m, testDB);

        const beforeCmd = Date.now();

        // Admin user logs in
        let adminDB = m.getDB("admin");
        adminDB.auth("admin", "admin");

        // Admin tries to run a command with auditAuthorizationSuccess=false and then
        // with auditAuthorizationSuccess=true. Only one event should be logged
        assert.writeOK(testDB.foo.insert({"_id": 1}));
        testDB.runCommand({count: "foo"});
        adminDB.runCommand({setParameter: 1, "auditAuthorizationSuccess": true});
        testDB.runCommand({count: "foo"});
        adminDB.runCommand({setParameter: 1, "auditAuthorizationSuccess": false});
        adminDB.logout();

        // User (tom) with no permissions logs in.
        let r = testDB.auth("tom", "tom");
        assert(r);

        // Tom tries to perform a command.
        testDB.runCommand({count: "foo"});

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
                "param.command": "count",
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
                "param.ns": testDBName + "." + "foo",
                "param.command": "count",
                result: 0, // <-- Authorization successful
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );
    },
    {auth: ""},
);
