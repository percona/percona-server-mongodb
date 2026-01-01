// test that createDatabase gets audited

import {auditTest, getAuditEventsCollection, withinInterval} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_create_database";

auditTest(
    "createDatabase",
    function (m) {
        let testDB = m.getDB(testDBName);
        assert.commandWorked(testDB.dropDatabase());
        const beforeCmd = Date.now();
        assert.commandWorked(testDB.createCollection("foo"));

        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName);
        assert.eq(
            1,
            auditColl.count({
                atype: "createDatabase",
                ts: withinInterval(beforeCmd, beforeLoad),
                "param.ns": testDBName,
                result: 0,
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );
    },
    {
        /* no special mongod options */
    },
);
