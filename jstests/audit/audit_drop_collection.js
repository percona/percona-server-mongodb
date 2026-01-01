// test that dropCollection gets audited

import {auditTest, getAuditEventsCollection, withinInterval} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_drop_collection";

auditTest(
    "dropCollection",
    function (m) {
        let testDB = m.getDB(testDBName);
        const collName = "foo";
        let coll = testDB.getCollection(collName);
        assert.writeOK(coll.insert({a: 17}));
        const beforeCmd = Date.now();
        assert(coll.drop());

        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName);
        assert.eq(
            1,
            auditColl.count({
                atype: "dropCollection",
                ts: withinInterval(beforeCmd, beforeLoad),
                "param.ns": testDBName + "." + collName,
                result: 0,
            }),
            "FAILED, audit log: " + tojson(auditColl.find().toArray()),
        );
    },
    {
        /* no special mongod options */
    },
);
