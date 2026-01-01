// test that shardCollection gets audited

import {
    auditTestShard,
    getDBPath,
    loadAuditEventsIntoCollection,
    withinInterval,
} from "jstests/audit/_audit_helpers.js";

auditTestShard(
    "shardCollection",
    function (st) {
        let testDB = st.s0.getDB(jsTestName());
        assert.commandWorked(testDB.dropDatabase());
        const beforeCmd = Date.now();
        assert.commandWorked(st.s0.adminCommand({enableSharding: jsTestName()}));
        assert.commandWorked(st.s0.adminCommand({shardCollection: jsTestName() + ".foo", key: {a: 1, b: 1}}));

        const beforeLoad = Date.now();
        let auditColl = loadAuditEventsIntoCollection(
            st.s0,
            getDBPath() + "/auditLog-c0.json",
            testDB.getName(),
            "auditEvents",
        );
        assert.eq(
            1,
            auditColl.count({
                atype: "enableSharding",
                ts: withinInterval(beforeCmd, beforeLoad),
                "param.ns": jsTestName(),
                result: 0,
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );
    },
    {
        /* no special mongod options */
    },
);
