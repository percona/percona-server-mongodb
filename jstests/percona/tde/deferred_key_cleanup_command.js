/**
 * Tests the cleanupOrphanedEncryptionKeys admin command.
 *
 * This test verifies that:
 * 1. The command succeeds and cleans up orphaned keys on demand.
 * 2. The command does not remove keys for databases that still exist.
 * 3. The command is idempotent (safe to run multiple times).
 * 4. The command works when periodic cleanup is disabled.
 * 5. The command cleans up keys for databases dropped between invocations.
 *
 * @tags: [
 *   requires_wiredtiger,
 * ]
 */
import {checkLog} from "src/mongo/shell/check_log.js";

(function () {
    "use strict";

    const keyFile = TestData.keyFileGood || "jstests/percona/tde/ekf";
    const cipherMode = TestData.cipherMode || "AES256-GCM";
    const numDocsPerCollection = 50;
    const testDbPrefix = "cmd_cleanup_test_";

    jsTestLog("Starting deferred key cleanup command test with cipher mode: " + cipherMode);

    // Start mongod with periodic cleanup disabled to test command-only cleanup.
    // Use a log file so we can reliably check for cleanup messages (the RAM log
    // buffer returned by getLog has limited capacity).
    const dbpath = MongoRunner.dataPath + "deferred_key_cleanup_command";
    const logpath = dbpath + "/mongod.log";
    const conn = MongoRunner.runMongod({
        dbpath: dbpath,
        enableEncryption: "",
        encryptionKeyFile: keyFile,
        encryptionCipherMode: cipherMode,
        logpath: logpath,
        setParameter: {
            encryptionKeyCleanupIntervalSeconds: 0,
        },
    });
    assert.neq(null, conn, "mongod failed to start with encryption enabled");

    const adminDb = conn.getDB("admin");

    // Helper function to create a database with data
    function createDatabaseWithData(dbName) {
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
    function verifyDatabaseIntegrity(dbName) {
        const db = conn.getDB(dbName);
        const coll = db["data"];
        assert.eq(numDocsPerCollection, coll.countDocuments({}), "Document count mismatch in " + dbName);
        for (let d = 0; d < Math.min(5, numDocsPerCollection); d++) {
            const doc = coll.findOne({_id: d});
            assert.neq(null, doc, "Missing document _id=" + d + " in " + dbName);
            assert.eq("test_data_" + d, doc.data, "Data mismatch for document _id=" + d);
        }
    }

    // After dropDatabase, idents become "drop-pending" and are reaped by the
    // TimestampMonitor on its periodic tick (~1s). The reaper needs a checkpoint
    // to have happened, then it drops the idents from WiredTiger on the next tick.
    // We force a checkpoint (fsync) and then sleep to let the reaper process.
    function waitForIdentsToBeReaped() {
        assert.commandWorked(adminDb.runCommand({fsync: 1}));
        sleep(3000);
    }

    // Phase 1: Test command with no orphaned keys (no-op)
    jsTestLog("Phase 1: Run cleanup command with no orphaned keys");
    assert.commandWorked(adminDb.runCommand({cleanupOrphanedEncryptionKeys: 1}));
    jsTestLog("Cleanup command succeeded with no orphaned keys");

    // Phase 2: Create databases, drop some, run cleanup command
    jsTestLog("Phase 2: Create databases and drop some");

    const allDbs = [];
    const droppedDbs = [];
    const survivingDbs = [];
    for (let i = 0; i < 8; i++) {
        const dbName = testDbPrefix + i;
        createDatabaseWithData(dbName);
        allDbs.push(dbName);
        if (i < 4) {
            droppedDbs.push(dbName);
        } else {
            survivingDbs.push(dbName);
        }
    }

    // Verify all databases are intact
    for (const dbName of allDbs) {
        verifyDatabaseIntegrity(dbName);
    }

    // Drop databases 0-3
    for (const dbName of droppedDbs) {
        jsTestLog("Dropping database: " + dbName);
        assert.commandWorked(conn.getDB(dbName).dropDatabase());
    }

    // Wait for drop-pending idents to be reaped and removed from WT metadata
    waitForIdentsToBeReaped();

    jsTestLog("Phase 3: Run cleanup command to remove orphaned keys");

    assert.commandWorked(adminDb.runCommand({cleanupOrphanedEncryptionKeys: 1}));

    // Verify the cleanup deleted orphaned keys by checking the log file.
    // LOGV2 ID 29160 = "Deleting orphaned encryption key for non-existent database"
    for (const dbName of droppedDbs) {
        checkLog.containsJson(logpath, 29160, {keyId: dbName});
    }
    jsTestLog("Verified cleanup command deleted orphaned keys for dropped databases");

    // Verify surviving databases are still intact
    for (const dbName of survivingDbs) {
        verifyDatabaseIntegrity(dbName);
    }
    jsTestLog("Verified surviving databases are intact after cleanup");

    // Phase 4: Test idempotency - running cleanup again should be a no-op
    jsTestLog("Phase 4: Test idempotency - run cleanup again");
    assert.commandWorked(adminDb.runCommand({cleanupOrphanedEncryptionKeys: 1}));

    // Verify surviving databases are still intact
    for (const dbName of survivingDbs) {
        verifyDatabaseIntegrity(dbName);
    }
    jsTestLog("Cleanup command is idempotent - surviving databases still intact");

    // Phase 5: Drop more databases, run cleanup again
    jsTestLog("Phase 5: Drop remaining databases and run cleanup");

    for (const dbName of survivingDbs) {
        jsTestLog("Dropping database: " + dbName);
        assert.commandWorked(conn.getDB(dbName).dropDatabase());
    }

    // Wait for idents to be reaped
    waitForIdentsToBeReaped();

    assert.commandWorked(adminDb.runCommand({cleanupOrphanedEncryptionKeys: 1}));

    // Verify the cleanup deleted orphaned keys for the remaining databases
    for (const dbName of survivingDbs) {
        checkLog.containsJson(logpath, 29160, {keyId: dbName});
    }
    jsTestLog("Verified cleanup command deleted orphaned keys for all dropped databases");

    // Phase 6: Verify system is functional after all cleanups
    jsTestLog("Phase 6: Verify system is functional after cleanup");

    // Verify all test databases are gone
    const finalDbs = adminDb.adminCommand({listDatabases: 1}).databases;
    for (const dbInfo of finalDbs) {
        assert(!dbInfo.name.startsWith(testDbPrefix), "Test database should have been dropped: " + dbInfo.name);
    }

    // Create new databases to verify system works
    for (let i = 0; i < 3; i++) {
        const dbName = testDbPrefix + "final_" + i;
        createDatabaseWithData(dbName);
        verifyDatabaseIntegrity(dbName);
        assert.commandWorked(conn.getDB(dbName).dropDatabase());
    }

    // One final cleanup
    assert.commandWorked(adminDb.runCommand({cleanupOrphanedEncryptionKeys: 1}));

    jsTestLog("Deferred key cleanup command test completed successfully");

    MongoRunner.stopMongod(conn);
})();
