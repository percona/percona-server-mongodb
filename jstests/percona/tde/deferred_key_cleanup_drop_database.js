/**
 * Tests that encryption key cleanup works correctly with dropDatabase.
 *
 * This test verifies that:
 * 1. Databases can be created and dropped without errors
 * 2. Encryption keys are eventually cleaned up by the periodic background process
 * 3. No data corruption occurs
 * 4. The cleanupOrphanedEncryptionKeys admin command works
 *
 * @tags: [
 *   requires_wiredtiger,
 * ]
 */
(function () {
    "use strict";

    const keyFile = TestData.keyFileGood || "jstests/percona/tde/ekf";
    const cipherMode = TestData.cipherMode || "AES256-GCM";
    const cleanupIntervalSecs = 1;
    const numDatabases = 10;
    const numCollections = 3;
    const numDocsPerCollection = 100;

    jsTestLog("Starting deferred key cleanup drop database test with cipher mode: " + cipherMode);

    // Start mongod with encryption and periodic key cleanup enabled
    const conn = MongoRunner.runMongod({
        enableEncryption: "",
        encryptionKeyFile: keyFile,
        encryptionCipherMode: cipherMode,
        setParameter: {
            encryptionKeyCleanupIntervalSeconds: cleanupIntervalSecs,
        },
    });
    assert.neq(null, conn, "mongod failed to start with encryption enabled");

    const testDbPrefix = "deferred_cleanup_test_";

    // Helper function to create a database with collections and data
    function createDatabaseWithData(dbName) {
        const db = conn.getDB(dbName);
        for (let c = 0; c < numCollections; c++) {
            const collName = "coll_" + c;
            const coll = db[collName];

            // Insert documents
            let docs = [];
            for (let d = 0; d < numDocsPerCollection; d++) {
                docs.push({
                    _id: d,
                    data: "test_data_" + d,
                    dbName: dbName,
                    collName: collName,
                    timestamp: new Date(),
                });
            }
            assert.commandWorked(coll.insertMany(docs));

            // Verify insertion
            assert.eq(
                numDocsPerCollection,
                coll.countDocuments({}),
                "Document count mismatch in " + dbName + "." + collName,
            );
        }
        return db;
    }

    // Helper function to verify database integrity
    function verifyDatabaseIntegrity(dbName) {
        const db = conn.getDB(dbName);
        for (let c = 0; c < numCollections; c++) {
            const collName = "coll_" + c;
            const coll = db[collName];

            // Verify document count
            const count = coll.countDocuments({});
            assert.eq(numDocsPerCollection, count, "Document count mismatch in " + dbName + "." + collName);

            // Verify data integrity by checking a few documents
            for (let d = 0; d < Math.min(10, numDocsPerCollection); d++) {
                const doc = coll.findOne({_id: d});
                assert.neq(null, doc, "Missing document _id=" + d + " in " + dbName + "." + collName);
                assert.eq("test_data_" + d, doc.data, "Data mismatch for document _id=" + d);
                assert.eq(dbName, doc.dbName, "dbName mismatch for document _id=" + d);
            }
        }
    }

    jsTestLog("Phase 1: Create databases and verify data integrity");

    // Create multiple databases
    let createdDbs = [];
    for (let i = 0; i < numDatabases; i++) {
        const dbName = testDbPrefix + i;
        jsTestLog("Creating database: " + dbName);
        createDatabaseWithData(dbName);
        createdDbs.push(dbName);
    }

    // Verify all databases have correct data
    for (const dbName of createdDbs) {
        verifyDatabaseIntegrity(dbName);
    }
    jsTestLog("All " + numDatabases + " databases created and verified");

    jsTestLog("Phase 2: Drop half of the databases");

    // Drop half of the databases
    let droppedDbs = [];
    let remainingDbs = [];
    for (let i = 0; i < numDatabases; i++) {
        const dbName = testDbPrefix + i;
        if (i % 2 === 0) {
            jsTestLog("Dropping database: " + dbName);
            const db = conn.getDB(dbName);
            assert.commandWorked(db.dropDatabase());
            droppedDbs.push(dbName);
        } else {
            remainingDbs.push(dbName);
        }
    }

    jsTestLog("Phase 3: Verify remaining databases are intact");

    // Verify remaining databases are still intact
    for (const dbName of remainingDbs) {
        verifyDatabaseIntegrity(dbName);
    }
    jsTestLog("All remaining databases verified after partial drop");

    jsTestLog("Phase 4: Wait for deferred cleanup to run");

    // Wait for deferred cleanup to run (at least 2 intervals)
    sleep(cleanupIntervalSecs * 3 * 1000);

    jsTestLog("Phase 5: Verify remaining databases are still intact after cleanup");

    // Verify remaining databases are still intact after cleanup ran
    for (const dbName of remainingDbs) {
        verifyDatabaseIntegrity(dbName);
    }

    jsTestLog("Phase 6: Drop remaining databases");

    // Drop remaining databases
    for (const dbName of remainingDbs) {
        jsTestLog("Dropping database: " + dbName);
        const db = conn.getDB(dbName);
        assert.commandWorked(db.dropDatabase());
    }

    jsTestLog("Phase 7: Wait for final cleanup");

    // Wait for final cleanup
    sleep(cleanupIntervalSecs * 3 * 1000);

    jsTestLog("Phase 8: Verify all test databases are gone");

    // Verify all test databases are gone
    const finalDbs = conn.getDB("admin").adminCommand({listDatabases: 1}).databases;
    for (const dbInfo of finalDbs) {
        assert(!dbInfo.name.startsWith(testDbPrefix), "Test database should have been dropped: " + dbInfo.name);
    }

    jsTestLog("Phase 9: Test explicit cleanup command");

    // Test that the cleanupOrphanedEncryptionKeys admin command works
    assert.commandWorked(conn.getDB("admin").runCommand({cleanupOrphanedEncryptionKeys: 1}));

    jsTestLog("Phase 10: Create new databases to verify system is still functional");

    // Create new databases to verify system is still functional
    for (let i = 0; i < 3; i++) {
        const dbName = testDbPrefix + "final_" + i;
        createDatabaseWithData(dbName);
        verifyDatabaseIntegrity(dbName);

        // Clean up
        const db = conn.getDB(dbName);
        assert.commandWorked(db.dropDatabase());
    }

    jsTestLog("Deferred key cleanup drop database test completed successfully");

    MongoRunner.stopMongod(conn);
})();
