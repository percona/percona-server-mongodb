// test that renameCollection gets audited

import {auditTest, getAuditEventsCollection, withinInterval} from "jstests/audit/_audit_helpers.js";

const testDBName = "audit_rename_collection";

auditTest(
    "renameCollection",
    function (m) {
        let testDB = m.getDB(testDBName);
        assert.commandWorked(testDB.dropDatabase());

        let oldName = "john";
        let newName = "christian";

        assert.commandWorked(testDB.createCollection(oldName));
        const beforeCmd = Date.now();
        assert.commandWorked(testDB.getCollection(oldName).renameCollection(newName));

        const beforeLoad = Date.now();
        let auditColl = getAuditEventsCollection(m, testDBName);
        let checkAuditLogForSingleRename = function () {
            assert.eq(
                1,
                auditColl.count({
                    atype: "renameCollection",
                    ts: withinInterval(beforeCmd, beforeLoad),
                    "param.old": testDBName + "." + oldName,
                    "param.new": testDBName + "." + newName,
                    result: 0,
                }),
                "FAILED, audit log: " + tojson(auditColl.find().toArray()),
            );
        };
        checkAuditLogForSingleRename();

        assert.commandFailed(testDB.getCollection(oldName).renameCollection(newName));

        // Second rename won't be audited because it did not succeed.
        checkAuditLogForSingleRename();
    },
    {
        /* no special mongod options */
    },
);
