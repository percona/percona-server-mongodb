// test that shutdownServer gets audited

import {auditTest, getAuditEventsCollection, withinInterval} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_shutdown";

auditTest(
    "shutdown",
    function (m, restartServer) {
        const beforeCmd = Date.now();
        m.getDB("admin").shutdownServer();
        m = restartServer();

        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName, undefined, undefined, /*loadRotated =*/ true);
        assert.eq(
            1,
            auditColl.count({
                atype: "shutdown",
                ts: withinInterval(beforeCmd, beforeLoad),
                result: 0,
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );
    },
    {
        /* no special mongod options */
    },
);
