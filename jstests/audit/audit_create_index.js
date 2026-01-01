// test that createIndex gets audited

import {auditTest, getAuditEventsCollection, withinInterval} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_create_index";

auditTest(
    "createIndex",
    function (m) {
        let testDB = m.getDB(testDBName);
        assert.commandWorked(testDB.dropDatabase());

        // insert some data to index
        let n = 100;
        for (let i = 0; i < n; ++i) {
            assert.writeOK(testDB.coll.insert({a: i, b: n - i, t: "lotsofdummydata"}));
        }

        const beforeCmd = Date.now();

        assert.commandWorked(testDB.coll.createIndex({a: 1}, {name: "idx_a"}));

        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName);

        // two records are logged with param.indexBuildState:
        // - IndexBuildStarted
        // - IndexBuildSucceeded
        assert.eq(
            2,
            auditColl.count({
                atype: "createIndex",
                ts: withinInterval(beforeCmd, beforeLoad),
                "param.ns": testDBName + ".coll",
                "param.indexSpec.key": {a: 1},
                "param.indexName": "idx_a",
                result: 0,
            }),
            "FAILED idx_a, audit log: " + tojson(auditColl.find().toArray()),
        );
    },
    {
        /* no special mongod options */
    },
);
