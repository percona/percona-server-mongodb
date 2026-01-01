// test that 'logApplicationMessage' command can be authorized
// by one of the built-in roles with 'applicationMessage' privilege

import {
    auditTest,
    createAdminUserForAudit,
    getAuditEventsCollection,
    withinInterval,
} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_authz_application_message";

auditTest(
    "auth_logApplicationMessage",
    function (m) {
        createAdminUserForAudit(m);

        // Admin has 'clusterAdmin' role which includes 'applicationMessage' privilege
        // necessary to run 'logApplicationMessage' command.
        let adminDB = m.getDB("admin");
        adminDB.auth("admin", "admin");

        let msg = "it's a trap!";
        const beforeCmd = Date.now();
        assert.commandWorked(adminDB.runCommand({logApplicationMessage: msg}));

        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName, undefined, true);
        assert.eq(
            1,
            auditColl.count({
                atype: "applicationMessage",
                ts: withinInterval(beforeCmd, beforeLoad),
                "param.msg": msg,
                result: 0,
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );
    },
    {auth: ""},
);
