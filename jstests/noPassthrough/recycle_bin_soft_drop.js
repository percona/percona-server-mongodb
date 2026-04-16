// Verifies collection recycle bin: soft drop renames to __recycle_bin.*, undelete restores.
(function() {
"use strict";

const rst = new ReplSetTest({
    name: "recycle_bin_soft_drop",
    nodes: 1,
    nodeOptions: {
        setParameter: "collectionRecycleBin=true&collectionRecycleBinRetentionSeconds=86400"
    }
});
rst.startSet();
rst.initiate();

const primary = rst.getPrimary();
const testDb = primary.getDB("test");
assert.commandWorked(testDb.coll.drop());
assert.commandWorked(testDb.coll.insert({_id: 1}));

assert.commandWorked(testDb.runCommand({drop: "coll"}));
assert.eq(null, testDb["coll"].exists());
const names = testDb.getCollectionNames();
const rb = names.find((n) => n.startsWith("__recycle_bin."));
assert(rb, "expected a __recycle_bin.* collection after soft drop, got: " + tojson(names));

const rbNss = "test." + rb;
assert.commandWorked(primary.getDB("admin").runCommand({
    undeleteCollection: 1,
    recycleNamespace: rbNss,
    to: "coll",
}));
assert.eq(1, testDb.coll.countDocuments({_id: 1}));

rst.stopSet();
}());
