// test that createDatabase gets audited

import {auditTest, getAuditEventsCollection, withinInterval} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_log_application_message";

auditTest(
    "logApplicationMessage",
    function (m) {
        let msg = "it's a trap!";
        const beforeCmd = Date.now();
        assert.commandWorked(m.getDB("admin").runCommand({logApplicationMessage: msg}));

        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName);
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
    {},
);
