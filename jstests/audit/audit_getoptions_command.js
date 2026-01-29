// test that auditGetOptions command works as expected

import {auditTest, createAdminUserForAudit, createNoPermissionUserForAudit} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_getoptions_command";

auditTest(
    "auditGetOptions",
    function (m) {
        let adminDB = m.getDB("admin");
        let testDB = m.getDB(testDBName);
        createAdminUserForAudit(m);
        createNoPermissionUserForAudit(m, adminDB);

        // Admin user logs in
        adminDB.auth("admin", "admin");
        // Should fail if not executed on 'admin' database
        assert.commandFailedWithCode(testDB.runCommand({"auditGetOptions": 1}), ErrorCodes.Unauthorized);
        assert.commandWorked(adminDB.runCommand({"auditGetOptions": 1}));
        adminDB.logout();

        // User (tom) with no permissions logs in.
        assert(adminDB.auth("tom", "tom"));
        // Should fail if current user has no 'getParameter' privilege
        assert.commandFailedWithCode(testDB.runCommand({"auditGetOptions": 1}), ErrorCodes.Unauthorized);
        assert.commandFailedWithCode(adminDB.runCommand({"auditGetOptions": 1}), ErrorCodes.Unauthorized);
        adminDB.logout();
    },
    {auth: ""},
);
