/**
 * Tests for the collection recycle bin feature.
 *
 * Verifies that dropped collections are intercepted and moved to the recycle bin,
 * can be listed and restored, and that the background purger removes expired entries.
 */

const conn = MongoRunner.runMongod({});
const adminDB = conn.getDB("admin");
const testDB = conn.getDB(jsTestName());

function enableRecycleBin(retentionSeconds) {
    assert.commandWorked(adminDB.runCommand({setParameter: 1, recycleBinEnabled: true}));
    if (retentionSeconds !== undefined) {
        assert.commandWorked(adminDB.runCommand({setParameter: 1, recycleBinRetentionSeconds: retentionSeconds}));
    }
}

function disableRecycleBin() {
    assert.commandWorked(adminDB.runCommand({setParameter: 1, recycleBinEnabled: false}));
}

function listRecycleBin(dbName) {
    const res = assert.commandWorked(adminDB.runCommand({listRecycleBin: dbName || ""}));
    return res.collections;
}

function cleanup() {
    disableRecycleBin();
    testDB.dropDatabase();
}

// Start each test with a clean slate.
function setup() {
    cleanup();
    enableRecycleBin(86400);
}

// --------------------------------------------------------------------------
// Test: drop intercept when enabled
// --------------------------------------------------------------------------
jsTest.log("Test: drop is intercepted when recycle bin is enabled");
{
    setup();
    const coll = testDB.getCollection("intercepted");
    assert.commandWorked(coll.insertMany([{x: 1}, {x: 2}, {x: 3}]));
    assert.eq(3, coll.countDocuments({}));

    assert(coll.drop());

    // Original collection should be gone.
    assert.eq(null, coll.exists());

    // Recycle bin should have an entry.
    const entries = listRecycleBin(testDB.getName());
    assert.eq(1, entries.length, "Expected 1 recycle bin entry: " + tojson(entries));
    assert.eq("intercepted", entries[0].originalCollection);
    assert.gt(entries[0].dropTime, 0);

    // Data should be accessible through the recycle bin namespace.
    const rbNs = entries[0].ns;
    const rbCollName = rbNs.substring(rbNs.indexOf(".") + 1);
    assert.eq(3, testDB.getCollection(rbCollName).countDocuments({}));
}

// --------------------------------------------------------------------------
// Test: drop is NOT intercepted when disabled
// --------------------------------------------------------------------------
jsTest.log("Test: drop is NOT intercepted when recycle bin is disabled");
{
    setup();
    disableRecycleBin();

    const coll = testDB.getCollection("not_intercepted");
    assert.commandWorked(coll.insert({x: 1}));
    assert(coll.drop());

    const entries = listRecycleBin(testDB.getName());
    const found = entries.filter((e) => e.originalCollection === "not_intercepted");
    assert.eq(0, found.length, "Should not have recycle bin entry when disabled");
}

// --------------------------------------------------------------------------
// Test: restore collection (undeleteCollection)
// --------------------------------------------------------------------------
jsTest.log("Test: restore collection from recycle bin");
{
    setup();
    const coll = testDB.getCollection("to_restore");
    assert.commandWorked(coll.insertMany([{name: "a"}, {name: "b"}]));
    assert(coll.drop());

    const entries = listRecycleBin(testDB.getName());
    const entry = entries.find((e) => e.originalCollection === "to_restore");
    assert(entry, "Expected recycle bin entry for 'to_restore'");

    assert.commandWorked(adminDB.runCommand({undeleteCollection: entry.ns}));

    // Collection should be back with all data.
    assert.eq(2, coll.countDocuments({}));
    assert.eq(1, coll.countDocuments({name: "a"}));
    assert.eq(1, coll.countDocuments({name: "b"}));

    // Recycle bin should be empty for this collection.
    const remaining = listRecycleBin(testDB.getName()).filter((e) => e.originalCollection === "to_restore");
    assert.eq(0, remaining.length);
}

// --------------------------------------------------------------------------
// Test: restore with restoreAs
// --------------------------------------------------------------------------
jsTest.log("Test: restore with restoreAs to a different namespace");
{
    setup();
    const coll = testDB.getCollection("original_name");
    assert.commandWorked(coll.insert({val: 42}));
    assert(coll.drop());

    const entries = listRecycleBin(testDB.getName());
    const entry = entries.find((e) => e.originalCollection === "original_name");
    assert(entry, "Expected recycle bin entry");

    const restoreTarget = testDB.getName() + ".renamed_coll";
    assert.commandWorked(adminDB.runCommand({undeleteCollection: entry.ns, restoreAs: restoreTarget}));

    // Original name should still not exist.
    assert.eq(null, testDB.getCollection("original_name").exists());

    // Data should be in the new name.
    assert.eq(1, testDB.getCollection("renamed_coll").countDocuments({}));
    assert.eq(42, testDB.getCollection("renamed_coll").findOne().val);
}

// --------------------------------------------------------------------------
// Test: restore fails when target namespace already exists
// --------------------------------------------------------------------------
jsTest.log("Test: restore fails when target namespace already exists");
{
    setup();
    const coll = testDB.getCollection("conflict");
    assert.commandWorked(coll.insert({x: 1}));
    assert(coll.drop());

    // Re-create the collection with the same name.
    assert.commandWorked(coll.insert({x: 2}));

    const entries = listRecycleBin(testDB.getName());
    const entry = entries.find((e) => e.originalCollection === "conflict");
    assert(entry, "Expected recycle bin entry");

    assert.commandFailedWithCode(adminDB.runCommand({undeleteCollection: entry.ns}), ErrorCodes.NamespaceExists);
}

// --------------------------------------------------------------------------
// Test: restore fails with invalid namespace
// --------------------------------------------------------------------------
jsTest.log("Test: restore fails with invalid recycle bin namespace");
{
    setup();
    assert.commandFailed(adminDB.runCommand({undeleteCollection: "mydb.not_a_recycle_bin_ns"}));
}

// --------------------------------------------------------------------------
// Test: multiple drops of same collection (collision handling)
// --------------------------------------------------------------------------
jsTest.log("Test: multiple drops of the same collection name");
{
    setup();

    // Drop the same collection name twice within 1 second.
    const coll = testDB.getCollection("multi_drop");
    assert.commandWorked(coll.insert({round: 1}));
    assert(coll.drop());

    assert.commandWorked(coll.insert({round: 2}));
    assert(coll.drop());

    const entries = listRecycleBin(testDB.getName()).filter((e) => e.originalCollection === "multi_drop");
    assert.eq(2, entries.length, "Expected 2 recycle bin entries: " + tojson(entries));

    // Both entries should have distinct namespaces.
    assert.neq(entries[0].ns, entries[1].ns);
}

// --------------------------------------------------------------------------
// Test: listRecycleBin with empty string lists all databases
// --------------------------------------------------------------------------
jsTest.log("Test: listRecycleBin with empty string lists all databases");
{
    setup();
    const db2 = conn.getDB("recycle_bin_other_db");
    db2.dropDatabase();

    // Drop a collection in each database.
    assert.commandWorked(testDB.getCollection("coll_a").insert({x: 1}));
    testDB.getCollection("coll_a").drop();

    assert.commandWorked(db2.getCollection("coll_b").insert({x: 1}));
    db2.getCollection("coll_b").drop();

    const allEntries = listRecycleBin("");
    const dbs = [...new Set(allEntries.map((e) => e.db))];
    assert.gte(dbs.length, 2, "Expected entries from at least 2 databases: " + tojson(dbs));

    // Clean up the extra database.
    disableRecycleBin();
    db2.dropDatabase();
    enableRecycleBin(86400);
}

// --------------------------------------------------------------------------
// Test: listRecycleBin filters by database
// --------------------------------------------------------------------------
jsTest.log("Test: listRecycleBin filters by database name");
{
    setup();
    const db2 = conn.getDB("recycle_bin_filtered_db");
    db2.dropDatabase();

    assert.commandWorked(testDB.getCollection("in_test_db").insert({x: 1}));
    testDB.getCollection("in_test_db").drop();

    assert.commandWorked(db2.getCollection("in_other_db").insert({x: 1}));
    db2.getCollection("in_other_db").drop();

    // Filter by testDB — should only see entries from testDB.
    const filtered = listRecycleBin(testDB.getName());
    for (const entry of filtered) {
        assert.eq(entry.db, testDB.getName(), "Unexpected db in filtered result: " + tojson(entry));
    }

    // Clean up.
    disableRecycleBin();
    db2.dropDatabase();
    enableRecycleBin(86400);
}

// --------------------------------------------------------------------------
// Test: indexes are preserved through drop/restore
// --------------------------------------------------------------------------
jsTest.log("Test: indexes are preserved through drop and restore");
{
    setup();
    const coll = testDB.getCollection("with_indexes");
    assert.commandWorked(coll.insert({a: 1, b: 2}));
    assert.commandWorked(coll.createIndex({a: 1}));
    assert.commandWorked(coll.createIndex({b: 1}, {unique: true}));

    const indexesBefore = coll.getIndexes().sort((a, b) => JSON.stringify(a.key).localeCompare(JSON.stringify(b.key)));

    assert(coll.drop());

    const entry = listRecycleBin(testDB.getName()).find((e) => e.originalCollection === "with_indexes");
    assert(entry);

    assert.commandWorked(adminDB.runCommand({undeleteCollection: entry.ns}));

    const indexesAfter = coll.getIndexes().sort((a, b) => JSON.stringify(a.key).localeCompare(JSON.stringify(b.key)));
    assert.eq(indexesBefore.length, indexesAfter.length, "Index count mismatch: " + tojson(indexesAfter));

    // Verify the custom indexes exist.
    const indexKeys = indexesAfter.map((idx) => JSON.stringify(idx.key));
    assert(indexKeys.includes(JSON.stringify({a: 1})), "Missing index {a:1}");
    assert(indexKeys.includes(JSON.stringify({b: 1})), "Missing index {b:1}");
}

// --------------------------------------------------------------------------
// Test: retention expiry and purge
// --------------------------------------------------------------------------
jsTest.log("Test: expired entries are purged by the background purger");
{
    setup();

    const coll = testDB.getCollection("to_expire");
    assert.commandWorked(coll.insert({x: 1}));
    assert(coll.drop());

    // Verify it's in the recycle bin.
    let entries = listRecycleBin(testDB.getName()).filter((e) => e.originalCollection === "to_expire");
    assert.eq(1, entries.length);

    // Set retention to 1 second so the entry expires immediately.
    assert.commandWorked(adminDB.runCommand({setParameter: 1, recycleBinRetentionSeconds: 1}));

    // The purger runs every 60 seconds. Wait up to 90s.
    assert.soon(
        function () {
            const remaining = listRecycleBin(testDB.getName()).filter((e) => e.originalCollection === "to_expire");
            return remaining.length === 0;
        },
        "Expired recycle bin entry was not purged within timeout",
        90000, // timeout ms
        5000, // interval ms
    );
}

// --------------------------------------------------------------------------
// Cleanup
// --------------------------------------------------------------------------
cleanup();
MongoRunner.stopMongod(conn);
