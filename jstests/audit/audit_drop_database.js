// test that dropDatabase gets audited

import {auditTest, getAuditEventsCollection, withinInterval} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_drop_database";

auditTest(
    "dropDatabase",
    function (m) {
        let testDB = m.getDB(testDBName);
        assert.writeOK(testDB.getCollection("foo").insert({a: 1}));
        const beforeCmd = Date.now();
        assert.commandWorked(testDB.dropDatabase());

        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName);
        assert.eq(
            1,
            auditColl.count({
                atype: "dropDatabase",
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
