// test that createDatabase isn't audited after restart

import {auditTest, getAuditEventsCollection, getDBPath, withinInterval} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_no_createdb_restart";

auditTest(
    "noCreateDatabaseRestart",
    function (m, restartServer) {
        let testDB = m.getDB(testDBName);
        assert.commandWorked(testDB.dropDatabase());
        assert.commandWorked(testDB.createCollection("foo"));

        m.getDB("admin").shutdownServer();
        let auditPath = getDBPath() + "/auditLog.json";
        removeFile(auditPath);
        const beforeCmd = Date.now();
        m = restartServer();

        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName);
        assert.eq(
            0,
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
