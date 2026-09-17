/**
 * Regression test for PSMDB-2253: File Copy Based Initial Sync (FCBIS) must fetch the sync
 * source's storage engine metadata file ('storage.bson') via $_backupFile and stage it under
 * '.initialsync' before switching storage to the downloaded data. 'storage.bson' is the only
 * record of which KMIP/Vault master key identifier decrypts 'key.db'; $backupCursor's file
 * enumeration does not include it (it isn't WiredTiger-managed), so without this explicit
 * fetch, a node that started with an empty dbpath and no --kmipKeyIdentifier would have no way
 * to learn which key identifier decrypts a key.db cloned from a differently-keyed sync source.
 *
 * This uses the 'initialSyncHangAfterFetchingStorageMetadataFile' failpoint to pause FCBIS right
 * after the fetch and directly asserts the staged file's presence on disk, so it does not need
 * KMIP/Vault infrastructure to verify the fetch itself happened.
 *
 * @tags: [requires_wiredtiger, requires_persistence, multiversion_incompatible]
 */
import {configureFailPoint} from "jstests/libs/fail_point_util.js";
import {reconfig} from "jstests/replsets/rslib.js";

(function() {
'use strict';

let addNodeConfig = function(rst, nodeId, conn) {
    var config = rst.getReplSetConfigFromNode();
    config.version += 1;
    config.members.push({_id: nodeId, host: conn.host});
    reconfig(rst, config, false /* force */, true /* doNotWaitForMembers */);
    return config;
};

const basenodes = 1;

var rsname = 'fcbis_storage_metadata_fetch';
var rs = new ReplSetTest({
    name: rsname,
    nodes: basenodes,
});

rs.startSet();
rs.initiate();

assert.commandWorked(rs.getPrimary().getDB('test').getCollection('foo').insert({x: 1}));

// Add a new member that will undergo FCBIS, pausing right after it fetches storage.bson.
let newNode = rs.add({
    rsConfig: {priority: 0, votes: 0},
    setParameter: {
        'initialSyncMethod': 'fileCopyBased',
    },
});

const failPointAfterFetch =
    configureFailPoint(newNode, 'initialSyncHangAfterFetchingStorageMetadataFile');

addNodeConfig(rs, basenodes + 1, newNode);

failPointAfterFetch.wait();

const primaryStorageMetadataPath = rs.getPrimary().dbpath + '/storage.bson';
const stagedStorageMetadataPath = newNode.dbpath + '/.initialsync/storage.bson';
assert(fileExists(primaryStorageMetadataPath),
       'primary is missing storage.bson: ' + primaryStorageMetadataPath);
assert(fileExists(stagedStorageMetadataPath),
       'FCBIS did not stage storage.bson under .initialsync before switching storage: ' +
           stagedStorageMetadataPath);
assert.eq(md5sumFile(primaryStorageMetadataPath),
          md5sumFile(stagedStorageMetadataPath),
          'staged storage.bson does not match the sync source');

failPointAfterFetch.off();

rs.waitForState(newNode, ReplSetTest.State.SECONDARY);
rs.waitForAllNewlyAddedRemovals();

rs.stopSet();
})();
