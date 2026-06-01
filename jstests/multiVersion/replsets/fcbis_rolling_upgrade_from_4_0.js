/**
 * PSMDB-2071: After a rolling upgrade from 4.0 through 8.0, the oldest oplog entries
 * (written on 4.0) still use the legacy schema (including the 'h' hash field). FCBIS opens a
 * backup cursor and reads the first oplog entry to determine oplogStart. Strict
 * OplogEntry::parse on that legacy entry fatals (error 50918) before cd71d5b8cfc; with
 * OplogEntryParserNonStrict only opTime is required and FCBIS completes.
 *
 * Plan:
 * - Start a single-node replica set on 4.0 and write data so legacy oplog entries exist.
 * - Rolling-upgrade the node through 4.2, 4.4, 5.0, 6.0, 7.0, and latest (8.0), setting FCV
 *   at each step.
 * - Verify the first oplog entry still has the legacy 'h' field.
 * - Verify $backupCursor can read the first oplog entry on the upgraded primary.
 * - Add a second member configured for FCBIS and wait for initial sync to finish.
 *
 * @tags: [requires_wiredtiger, requires_v4_0]
 */

import "jstests/multiVersion/libs/multi_rs.js";
import "jstests/multiVersion/libs/verify_versions.js";

import {getBackupCursorMetadata, openBackupCursor} from "jstests/libs/backup_utils.js";
import {getFirstOplogEntry, reconfig} from "jstests/replsets/rslib.js";

(function() {
'use strict';

const rsName = 'fcbis_rolling_upgrade_from_4_0';
const dbpath = MongoRunner.dataPath + rsName;
resetDbpath(dbpath);

const versions = [
    {binVersion: '4.0', featureCompatibilityVersion: '4.0'},
    {binVersion: '4.2', featureCompatibilityVersion: '4.2'},
    {binVersion: '4.4', featureCompatibilityVersion: '4.4'},
    {binVersion: '5.0', featureCompatibilityVersion: '5.0'},
    {binVersion: '6.0', featureCompatibilityVersion: '6.0'},
    {binVersion: '7.0', featureCompatibilityVersion: '7.0'},
    {binVersion: 'latest', featureCompatibilityVersion: latestFCV},
];

const defaultNodeOptions = {
    dbpath: dbpath,
    noCleanData: true,
};

function setFCVOnPrimary(rst, fcv) {
    const primary = rst.getPrimary();
    const adminDB = primary.getDB('admin');
    const res = adminDB.runCommand({setFeatureCompatibilityVersion: fcv});
    if (!res.ok && res.code === 7369100) {
        assert.commandWorked(
            adminDB.runCommand({setFeatureCompatibilityVersion: fcv, confirm: true}));
    } else {
        assert.commandWorked(res);
    }
    rst.awaitReplication();
    rst.awaitLastOpCommitted();
    for (const node of rst.nodes) {
        checkFCV(node.getDB('admin'), fcv);
    }
}

function addNodeToReplSet(rst, nodeId, conn) {
    const config = rst.getReplSetConfigFromNode();
    config.version += 1;
    config.members.push({_id: nodeId, host: conn.host});
    reconfig(rst, config);
}

function getTestCollection(conn) {
    return conn.getDB('test').getCollection('fcbis_rolling_upgrade');
}

// "latest" in the test is the binary from resmoke --installDir, which may differ from
// shellVersion() used by assert.binVersion(..., "latest").
function assertUpgradedToBinVersion(mongo, binVersion) {
    if (binVersion !== 'latest') {
        assert.binVersion(mongo, binVersion);
        return;
    }
    const actualVersion = mongo.getBinVersion();
    jsTestLog('Upgraded to installDir latest binary: ' + actualVersion);
    assert.gte(MongoRunner.compareBinVersions(actualVersion, '8.0'),
               0,
               'expected final mongod to be at least 8.0, got ' + actualVersion);
}

const rst = new ReplSetTest({
    name: rsName,
    nodes: 1,
    nodeOptions: defaultNodeOptions,
});

rst.startSet({binVersion: versions[0].binVersion});
rst.initiate();

let primary = rst.getPrimary();
assert.binVersion(primary, versions[0].binVersion);

// Write on 4.0 before upgrading so the oplog retains legacy-format entries at the front.
let coll = getTestCollection(primary);
assert.commandWorked(coll.insert({startedOn: versions[0].binVersion, i: 0}));
rst.awaitReplication();

for (let i = 1; i < versions.length; i++) {
    const version = versions[i];
    jsTestLog(`Upgrading replica set to ${version.binVersion}, target FCV ${
        version.featureCompatibilityVersion}`);

    rst.upgradeSet({binVersion: version.binVersion});
    primary = rst.getPrimary();
    assert.neq(null, primary, `replica set failed to restart on ${version.binVersion}`);
    assertUpgradedToBinVersion(primary, version.binVersion);

    setFCVOnPrimary(rst, version.featureCompatibilityVersion);

    // Reconnect after upgrade/setFCV; the previous shell connection may have been closed.
    primary = rst.getPrimary();
    coll = getTestCollection(primary);
    assert.commandWorked(coll.insert({upgradedTo: version.binVersion, i: i}));
    rst.awaitReplication();
}

// The oldest oplog entry was written on 4.0 and should retain the legacy 'h' hash field.
const firstOplogEntry = getFirstOplogEntry(primary);
assert.neq(null, firstOplogEntry, 'expected at least one oplog entry');
assert(firstOplogEntry.hasOwnProperty('h'),
       'expected legacy oplog entry with h field at the start of the oplog, but got: ' +
           tojson(firstOplogEntry));

jsTestLog('First oplog entry: ' + tojson(firstOplogEntry));

// Exercises openBackupCursor's non-strict parse of the first oplog entry (PSMDB-2071).
const backupCursor = openBackupCursor(primary.getDB('admin'));
const metadata = getBackupCursorMetadata(backupCursor);
assert(metadata.hasOwnProperty('oplogStart'),
       'backup cursor metadata should include oplogStart: ' + tojson(metadata));
backupCursor.close();

assert.commandWorked(primary.adminCommand({fsync: 1}));

const newNodeId = 1;
const newNode = rst.add({
    rsConfig: {priority: 0, votes: 0},
    setParameter: {
        initialSyncMethod: 'fileCopyBased',
    },
});

addNodeToReplSet(rst, newNodeId, newNode);

// Before PSMDB-2071/cd71d5b8cfc the donor fatals opening the backup cursor and this times out.
rst.waitForState(newNode, ReplSetTest.State.SECONDARY);
rst.waitForAllNewlyAddedRemovals();

assert.eq(getTestCollection(primary).find({}).itcount(), versions.length);

jsTestLog('FCBIS initial sync completed on node ' + newNode.host);
rst.stopSet();
})();
