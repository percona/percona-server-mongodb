/**
 * Tests that new node added via FCBIS works correctly as primary.
 *
 * @tags: [requires_wiredtiger]
 */
import {reconfig, isConfigCommitted} from "jstests/replsets/rslib.js";

(function() {
'use strict';

let addNodeConfig = function(rst, nodeId, conn) {
    var config = rst.getReplSetConfigFromNode();
    config.version += 1;
    config.members.push({_id: nodeId, host: conn.host});
    reconfig(rst, config);
    assert.soon(() => isConfigCommitted(rst.getPrimary()));
    rst.waitForConfigReplication(rst.getPrimary());
    rst.awaitReplication();
    return config;
};

const basenodes = 1; // <= Test will not hang if nodes > 1


var rsname = 'fcbis_replset';
var rs = new ReplSetTest({
    name: rsname,
    nodes: basenodes,
    nodeOptions: {verbose: 2},
});

rs.startSet({ });
rs.initiate();

// do fsync before FCBIS
assert.commandWorked(rs.getPrimary().adminCommand({fsync: 1}));
// assert.commandWorked(rs.getSecondary().adminCommand({fsync: 1}));

// Add a new member that will undergo initial sync
let newNode = rs.add({
    rsConfig: {priority: 10},
    setParameter: {
        'initialSyncMethod': 'fileCopyBased',
        //'initialSyncSourceReadPreference': 'primary',
    },
    verbose: 2,
});

// wait for user input to be able to attach gdb before initial sync
//jsTest.log("--XXXX-- newNode: " + newNode.pid);
//print("Press Enter to continue");
//let psw = passwordPrompt();

addNodeConfig(rs, basenodes + 1, newNode);
rs.waitForState(newNode, ReplSetTest.State.SECONDARY);
rs.waitForAllNewlyAddedRemovals();

jsTest.log("--XXXX-- Added new member");

// Output serverStatus for reference
jsTest.log("--XXXX-- newNode serverStatus: " + tojson(newNode.adminCommand({'serverStatus': 1, repl: 1})));

// Make the new member become primary
assert.commandWorked(newNode.adminCommand({replSetStepUp: 1}));
jsTest.log("--XXXX-- After replSetStepUp");

rs.awaitNodesAgreeOnPrimary(undefined, undefined, newNode);
jsTest.log("--XXXX-- All nodes agree on newNode being primary");

// BUG: This insert would not return and test would hang because of PSMDB-1589. This only happens when using FCBIS.
assert.commandWorked(rs.getPrimary().getDB('test').getCollection('foo').insert({x: 1})); // <= This will fail!
jsTest.log("--XXXX-- After insert on new member");

rs.stopSet();
})();

