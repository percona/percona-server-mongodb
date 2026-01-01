// test that replSetReconfig gets audited

import {auditTestRepl, getAuditEventsCollection, withinInterval} from "jstests/audit/_audit_helpers.js";
import {reconfig} from "jstests/replsets/rslib.js";

const testDBName = "audit_replset_reconfig";

auditTestRepl(
    "replSetReconfig",
    function (replTest) {
        let oldConfig = replTest.getReplSetConfig();
        let newConfig = JSON.parse(JSON.stringify(oldConfig));
        newConfig.version = 200; // tired of playing games with the version

        // var master = replTest.getPrimary();
        // try {
        //     assert.commandWorked(master.adminCommand({ replSetReconfig: newConfig }));
        // } catch (e) {
        //     print('caught exception ' + e + ' while running reconfig, checking audit logs anyway..');
        // }

        const beforeCmd = Date.now();
        reconfig(replTest, newConfig);
        // MAGIC MAGIC MAGIC MAGIC!
        sleep(5000);

        // Ensure that the reconfig audit event got logged on every member.
        const withinRightInterval = withinInterval(beforeCmd, Date.now());
        replTest.nodes.forEach(function (m) {
            print("audit check looking for old, new: " + tojson(oldConfig) + ", " + tojson(newConfig));
            // We need to import the audit events collection into the master node.
            let auditColl = getAuditEventsCollection(m, testDBName, replTest.getPrimary());
            assert.eq(
                1,
                auditColl.count({
                    atype: "replSetReconfig",
                    // Allow timestamps up to 20 seconds old, since replSetReconfig may be slow
                    ts: withinRightInterval,
                    // old version is not set, so we do not query for it here
                    "param.old._id": oldConfig._id,
                    "param.old.version": 1,
                    "param.new._id": newConfig._id,
                    "param.new.version": 200,
                    result: 0,
                }),
                "FAILED, audit log: " + tojson(auditColl.find().toArray()),
            );
        });
    },
    {
        /* no special mongod options */
    },
);
