/**
 * Regression test for PSMDB-2253: the $backupCursor aggregation stage must include the
 * top-level storage engine metadata file ('storage.bson') alongside the WiredTiger-managed
 * files (and, when encryption is enabled, the encrypted keystore 'key.db') it already returns.
 * 'storage.bson' is the only record of which KMIP/Vault master key identifier decrypts
 * 'key.db'; without it, a consumer that clones a node's files onto an empty destination (e.g.
 * File Copy Based Initial Sync) has no way to learn which key identifier to use, and can end up
 * crashing instead of syncing.
 *
 * This does not require KMIP/Vault infrastructure: the fix is unconditional, so plain
 * $backupCursor output is asserted directly against a single-node replica set. Because this
 * test lives under jstests/replsets/, it also automatically runs under the keyfile-encrypted
 * 'replica_sets_tde_cbc'/'replica_sets_tde_gcm' passthrough suites.
 *
 * @tags: [requires_wiredtiger, requires_persistence]
 */
(function() {
'use strict';

const rst = new ReplSetTest({nodes: 1});
rst.startSet();
rst.initiate();

const primary = rst.getPrimary();
const backupCursor = primary.getDB('admin').aggregate([{$backupCursor: {}}]);

// The first document returned by $backupCursor is always cursor metadata, not a file entry.
assert(backupCursor.hasNext(), 'expected a metadata document from $backupCursor');
backupCursor.next();

let sawStorageBson = false;
while (backupCursor.hasNext()) {
    const doc = backupCursor.next();
    assert(doc.hasOwnProperty('filename'), () => 'unexpected non-file document: ' + tojson(doc));
    if (doc.filename.endsWith('storage.bson')) {
        sawStorageBson = true;
        assert.gt(doc.fileSize,
                  0,
                  () => 'storage.bson entry should report a non-zero size: ' + tojson(doc));
    }
}
backupCursor.close();

assert(sawStorageBson,
       '$backupCursor did not include the storage engine metadata file (storage.bson)');

rst.stopSet();
})();
