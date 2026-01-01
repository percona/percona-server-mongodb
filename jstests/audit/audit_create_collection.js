// test that createColleciton gets audited

import {auditTest, getAuditEventsCollection, withinInterval} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_create_collection";

auditTest(
    "createCollection",
    function (m) {
        let testDB = m.getDB(testDBName);
        const beforeCmd = Date.now();
        assert.commandWorked(testDB.createCollection("foo"));

        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName);
        assert.eq(
            1,
            auditColl.count({
                atype: "createCollection",
                ts: withinInterval(beforeCmd, beforeLoad),
                "param.ns": testDBName + "." + "foo",
                result: 0,
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );
    },
    {
        /* no special mongod options */
    },
);
