// test that dropIndex gets audited

import {auditTest, getAuditEventsCollection, withinInterval} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_drop_index";

auditTest(
    "dropIndex",
    function (m) {
        let testDB = m.getDB(testDBName);
        let collName = "foo";
        let idxName = "fooIdx";
        let coll = testDB.getCollection(collName);
        assert.commandWorked(coll.createIndex({a: 1}, {name: idxName}));
        const beforeCmd = Date.now();
        assert.commandWorked(coll.dropIndex({a: 1}));

        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName);
        assert.eq(
            1,
            auditColl.count({
                atype: "dropIndex",
                ts: withinInterval(beforeCmd, beforeLoad),
                "param.ns": testDBName + "." + collName,
                "param.indexName": idxName,
                result: 0,
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );
    },
    {
        /* no special mongod options */
    },
);
