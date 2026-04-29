/**
 * Tests that orphaned encryption keys are cleaned up on mongod startup.
 *
 * This test verifies that:
 * 1. When a database is dropped and mongod is restarted, the orphaned encryption
 *    key is automatically cleaned up during startup (even with periodic cleanup disabled).
 * 2. Databases that still exist are not affected.
 * 3. The server is fully functional after startup cleanup.
 *
 * @tags: [
 *   requires_wiredtiger,
 *   requires_persistence,
 * ]
 */
import {checkLog} from "src/mongo/shell/check_log.js";

(function () {
    "use strict";

    const keyFile = TestData.keyFileGood || "jstests/percona/tde/ekf";
    const cipherMode = TestData.cipherMode || "AES256-GCM";
    const numDocsPerCollection = 50;
    const testDbPrefix = "startup_cleanup_test_";
    const dbpath = MongoRunner.dataPath + "deferred_key_cleanup_on_startup";
    const logpath = dbpath + "/mongod.log";

    jsTestLog("Starting deferred key cleanup on startup test with cipher mode: " + cipherMode);

    // Helper function to create a database with data
    function createDatabaseWithData(conn, dbName) {
        const db = conn.getDB(dbName);
        const coll = db["data"];
        let docs = [];
        for (let d = 0; d < numDocsPerCollection; d++) {
            docs.push({_id: d, data: "test_data_" + d, dbName: dbName});
        }
        assert.commandWorked(coll.insertMany(docs));
        assert.eq(numDocsPerCollection, coll.countDocuments({}), "Document count mismatch in " + dbName);
    }

    // Helper function to verify database integrity
    function verifyDatabaseIntegrity(conn, dbName) {
        const db = conn.getDB(dbName);
        const coll = db["data"];
        assert.eq(numDocsPerCollection, coll.countDocuments({}), "Document count mismatch in " + dbName);
        for (let d = 0; d < Math.min(5, numDocsPerCollection); d++) {
            const doc = coll.findOne({_id: d});
            assert.neq(null, doc, "Missing document _id=" + d + " in " + dbName);
            assert.eq("test_data_" + d, doc.data, "Data mismatch for document _id=" + d);
        }
    }

    // Phase 1: Start mongod, create databases, drop some, stop mongod
    jsTestLog("Phase 1: Create databases and drop some before shutdown");

    let conn = MongoRunner.runMongod({
        dbpath: dbpath,
        enableEncryption: "",
        encryptionKeyFile: keyFile,
        encryptionCipherMode: cipherMode,
        setParameter: {
            // Disable periodic cleanup so we can verify that only startup cleanup runs
            encryptionKeyCleanupIntervalSeconds: 0,
        },
    });
    assert.neq(null, conn, "mongod failed to start with encryption enabled");

    // Create databases: some will be dropped, some will remain
    const droppedDbs = [];
    const survivingDbs = [];
    for (let i = 0; i < 6; i++) {
        const dbName = testDbPrefix + i;
        createDatabaseWithData(conn, dbName);
        if (i < 3) {
            droppedDbs.push(dbName);
        } else {
            survivingDbs.push(dbName);
        }
    }

    // Verify all databases are intact
    for (const dbName of droppedDbs.concat(survivingDbs)) {
        verifyDatabaseIntegrity(conn, dbName);
    }

    // Drop the first 3 databases
    for (const dbName of droppedDbs) {
        jsTestLog("Dropping database: " + dbName);
        assert.commandWorked(conn.getDB(dbName).dropDatabase());
    }

    // Force a checkpoint and wait for the drop-pending ident reaper to process.
    // The clean shutdown will also do a final checkpoint, which ensures the dropped
    // idents are fully removed from WT metadata before restart.
    assert.commandWorked(conn.adminCommand({fsync: 1}));
    sleep(3000);

    // Verify surviving databases are still intact
    for (const dbName of survivingDbs) {
        verifyDatabaseIntegrity(conn, dbName);
    }

    // Stop mongod cleanly - the shutdown checkpoint finalizes ident removal.
    // Orphaned encryption keys remain in the keydb.
    MongoRunner.stopMongod(conn);

    // Phase 2: Restart mongod with a log file and verify startup cleanup runs
    jsTestLog("Phase 2: Restart mongod and verify startup cleanup");

    conn = MongoRunner.runMongod({
        dbpath: dbpath,
        restart: true,
        enableEncryption: "",
        encryptionKeyFile: keyFile,
        encryptionCipherMode: cipherMode,
        logpath: logpath,
        setParameter: {
            // Keep periodic cleanup disabled
            encryptionKeyCleanupIntervalSeconds: 0,
        },
    });
    assert.neq(null, conn, "mongod failed to restart");

    // Verify the startup cleanup deleted the orphaned keys by checking the log file.
    // We use the log file (not the RAM buffer) because startup produces many log entries
    // that can push cleanup messages out of the limited RAM log buffer.
    // LOGV2 ID 29160 = "Deleting orphaned encryption key for non-existent database"
    for (const dbName of droppedDbs) {
        checkLog.containsJson(logpath, 29160, {keyId: dbName});
    }
    jsTestLog("Verified startup cleanup deleted orphaned keys for dropped databases");

    // Verify surviving databases are still intact after startup cleanup
    for (const dbName of survivingDbs) {
        verifyDatabaseIntegrity(conn, dbName);
    }
    jsTestLog("Verified surviving databases are intact after startup cleanup");

    // Phase 3: Verify system is fully functional after startup cleanup
    jsTestLog("Phase 3: Verify system is functional after startup cleanup");

    // Create new databases (some reusing names of previously dropped databases)
    for (const dbName of droppedDbs) {
        createDatabaseWithData(conn, dbName);
        verifyDatabaseIntegrity(conn, dbName);
    }
    jsTestLog("Created new databases reusing previously dropped names");

    // Clean up all test databases
    for (const dbName of droppedDbs.concat(survivingDbs)) {
        assert.commandWorked(conn.getDB(dbName).dropDatabase());
    }

    // Phase 4: Restart again to confirm cleanup of all test databases
    jsTestLog("Phase 4: Final restart to confirm all test keys are cleaned up");

    MongoRunner.stopMongod(conn);
    conn = MongoRunner.runMongod({
        dbpath: dbpath,
        restart: true,
        enableEncryption: "",
        encryptionKeyFile: keyFile,
        encryptionCipherMode: cipherMode,
        setParameter: {
            encryptionKeyCleanupIntervalSeconds: 0,
        },
    });
    assert.neq(null, conn, "mongod failed to restart for final verification");

    // Verify all test databases are gone
    const finalDbs = conn.getDB("admin").adminCommand({listDatabases: 1}).databases;
    for (const dbInfo of finalDbs) {
        assert(!dbInfo.name.startsWith(testDbPrefix), "Test database should not exist after restart: " + dbInfo.name);
    }

    jsTestLog("Deferred key cleanup on startup test completed successfully");

    MongoRunner.stopMongod(conn);
})();
