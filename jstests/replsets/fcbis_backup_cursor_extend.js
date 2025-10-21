/**
 * Tests that $backupCursorExtend works correctly with FCBIS.
 *
 * Plan:
 * - Start a replica set
 * - Create a new member
 *   - configure it to use FCBIS
 *   - configure short allowed delay (fileBasedInitialSyncMaxLagSec)
 *   - and enable failpoint (initialSyncHangAfterCloningFiles)
 * - Add the new member to the replica set
 * - Wait for the failpoint to be hit
 *   - Insert some data slowly (sleep 1s between inserts)
 * - Release the Failpoint
 * - Ensure that $backupCursorExtend was called and worked correctly
 * - Check that the new node is in the correct state
 *
 * @tags: [requires_wiredtiger]
 */
(function() {
'use strict';

load("jstests/replsets/rslib.js");  // For reconfig and isConfigCommitted.

// Add node, intiate reconfig but don't wait for anything to be able to wait for the failpoint
let addNodeConfig = function(rst, nodeId, conn) {
    var config = rst.getReplSetConfigFromNode();
    config.version += 1;
    config.members.push({_id: nodeId, host: conn.host});
    reconfig(rst, config, false /* force */, true /* doNotWaitForMembers */);
    return config;
};

const basenodes = 1;


var rsname = 'fcbis_replset_bce';
var rs = new ReplSetTest({
    name: rsname,
    nodes: basenodes,
    nodeOptions: {verbose: 2},
});


rs.startSet({ });
rs.initiate();

// Add a new member that will undergo initial sync
let newNode = rs.add({
    rsConfig: {priority: 10},
    setParameter: {
        'initialSyncMethod': 'fileCopyBased',
        'fileBasedInitialSyncMaxLagSec': 3,
        //'initialSyncSourceReadPreference': 'primary',
    },
    verbose: 2,
});

const failPointAfterCloningFiles = configureFailPoint(newNode, 'initialSyncHangAfterCloningFiles');

jsTest.log("--XXXX-- Reconfiguring replica set");

// Add new node to the replica set
addNodeConfig(rs, basenodes + 1, newNode);

jsTest.log("--XXXX-- Waiting for the failpoint");

// Wait for the failpoint to be hit
failPointAfterCloningFiles.wait();

jsTest.log("--XXXX-- Failpoint hit, inserting data");

// Insert some data slowly (sleep 1s between inserts)
let coll = rs.getPrimary().getDB('test').getCollection('foo');
for (let i = 0; i < 5; i++) {
    sleep(1000);
    assert.commandWorked(coll.insert({x: i}));
}

jsTest.log("--XXXX-- Inserted data, releasing failpoint");

// Release the Failpoint
clearRawMongoProgramOutput();
failPointAfterCloningFiles.off();

// Wait for the message in the log
try {
    checkLog.containsJson(newNode, 128455, undefined, 5000);
} catch (e) {
    // Falling back to rawMongoProgramOutput
    let output = rawMongoProgramOutput();
    if (!output.includes("The lag is too big, extending backup cursor")) {
        throw e;
    }
}
jsTest.log("--XXXX-- Found backup cursor extend message in the log");

// Wait for the new node to finish initial sync
rs.waitForState(newNode, ReplSetTest.State.SECONDARY);
rs.waitForAllNewlyAddedRemovals();

jsTest.log("--XXXX-- Added new member");

// Output serverStatus for reference
jsTest.log("--XXXX-- newNode serverStatus: " + tojson(newNode.adminCommand({'serverStatus': 1, repl: 1})));


rs.stopSet();
})();

