/**
 * Stress test for encryption key cleanup with aggressive cleanup intervals.
 *
 * This test runs 16 parallel threads, each performing 200 iterations of:
 * - Creating a unique database
 * - Creating collections and inserting documents
 * - Verifying data integrity
 * - Dropping the database
 *
 * The periodic key cleanup runs every 1 second, exercising the race condition
 * handling between dropDatabase and encryption key cleanup.
 *
 * @tags: [
 *   requires_wiredtiger,
 * ]
 */
import {funWithArgs} from "jstests/libs/parallel_shell_helpers.js";

(function () {
    "use strict";

    const keyFile = TestData.keyFileGood || "jstests/percona/tde/ekf";
    const cipherMode = TestData.cipherMode || "AES256-GCM";
    const cleanupIntervalSecs = 1;
    const numThreads = 16;
    const iterationsPerThread = 200;
    const numCollections = 2;
    const numDocsPerCollection = 50;

    jsTestLog("Starting deferred key cleanup STRESS test");
    jsTestLog(
        "Configuration: " +
            numThreads +
            " threads, " +
            iterationsPerThread +
            " iterations each, cipher mode: " +
            cipherMode,
    );

    // Start mongod with encryption and aggressive periodic key cleanup
    const conn = MongoRunner.runMongod({
        enableEncryption: "",
        encryptionKeyFile: keyFile,
        encryptionCipherMode: cipherMode,
        setParameter: {
            encryptionKeyCleanupIntervalSeconds: cleanupIntervalSecs,
        },
    });
    assert.neq(null, conn, "mongod failed to start with encryption enabled");

    const testDbPrefix = "stress_test_";
    const adminDb = conn.getDB("admin");

    // Worker function that runs in parallel shell
    function workerThread(threadId, iterations, numColls, numDocs, dbPrefix) {
        for (let iter = 0; iter < iterations; iter++) {
            const dbName = dbPrefix + threadId + "_iter_" + iter;
            const testDb = db.getSiblingDB(dbName);

            try {
                // Create collections with data
                for (let c = 0; c < numColls; c++) {
                    const collName = "coll_" + c;
                    const coll = testDb[collName];

                    // Insert documents
                    let docs = [];
                    for (let d = 0; d < numDocs; d++) {
                        docs.push({
                            _id: d,
                            threadId: threadId,
                            iteration: iter,
                            data: "stress_test_data_" + d + "_" + Math.random(),
                            timestamp: new Date(),
                        });
                    }
                    const insertResult = coll.insertMany(docs);
                    assert.commandWorked(insertResult);

                    // Verify document count
                    const count = coll.countDocuments({});
                    assert.eq(
                        numDocs,
                        count,
                        "Thread " +
                            threadId +
                            " iter " +
                            iter +
                            ": Document count mismatch in " +
                            dbName +
                            "." +
                            collName +
                            " - expected " +
                            numDocs +
                            ", got " +
                            count,
                    );

                    // Spot check a few documents for data integrity
                    for (let d = 0; d < Math.min(5, numDocs); d++) {
                        const doc = coll.findOne({_id: d});
                        assert.neq(null, doc, "Thread " + threadId + " iter " + iter + ": Missing document _id=" + d);
                        assert.eq(
                            threadId,
                            doc.threadId,
                            "Thread " + threadId + " iter " + iter + ": threadId mismatch for document _id=" + d,
                        );
                        assert.eq(
                            iter,
                            doc.iteration,
                            "Thread " + threadId + " iter " + iter + ": iteration mismatch for document _id=" + d,
                        );
                    }
                }

                // Drop the database
                const dropResult = testDb.dropDatabase();
                assert.commandWorked(dropResult);

                // Periodic progress logging
                if ((iter + 1) % 50 === 0) {
                    print("Thread " + threadId + ": Completed " + (iter + 1) + "/" + iterations + " iterations");
                }
            } catch (e) {
                print("Thread " + threadId + " iter " + iter + " ERROR: " + tojson(e));
                throw e;
            }
        }
        return {threadId: threadId, iterations: iterations, status: "success"};
    }

    jsTestLog("Starting " + numThreads + " parallel worker threads");

    // Launch parallel shells
    let threads = [];
    for (let t = 0; t < numThreads; t++) {
        const threadId = t;
        const thread = startParallelShell(
            funWithArgs(
                workerThread,
                threadId,
                iterationsPerThread,
                numCollections,
                numDocsPerCollection,
                testDbPrefix,
            ),
            conn.port,
        );
        threads.push(thread);
    }

    jsTestLog("All threads launched, waiting for completion...");

    // Wait for all threads to complete
    let allSucceeded = true;
    for (let t = 0; t < threads.length; t++) {
        try {
            threads[t]();
            jsTestLog("Thread " + t + " completed successfully");
        } catch (e) {
            jsTestLog("Thread " + t + " FAILED: " + tojson(e));
            allSucceeded = false;
        }
    }

    assert(allSucceeded, "One or more worker threads failed");

    jsTestLog("All threads completed. Waiting for final cleanup cycle...");

    // Wait for a few cleanup cycles to ensure all orphaned keys are processed
    sleep(cleanupIntervalSecs * 5 * 1000);

    jsTestLog("Verifying no test databases remain...");

    // Verify no test databases remain
    const finalDbs = adminDb.adminCommand({listDatabases: 1}).databases;
    let testDbsRemaining = [];
    for (const dbInfo of finalDbs) {
        if (dbInfo.name.startsWith(testDbPrefix)) {
            testDbsRemaining.push(dbInfo.name);
        }
    }
    assert.eq(0, testDbsRemaining.length, "Test databases should have been dropped: " + tojson(testDbsRemaining));

    jsTestLog("Final verification: Create and drop a few more databases");

    // Final verification: system should still be fully functional
    for (let i = 0; i < 5; i++) {
        const dbName = testDbPrefix + "final_verify_" + i;
        const db = conn.getDB(dbName);

        assert.commandWorked(db.test.insertOne({verify: true, index: i}));
        assert.eq(1, db.test.countDocuments({}));
        assert.commandWorked(db.dropDatabase());
    }

    jsTestLog("Stress test completed successfully!");
    jsTestLog("Total operations: " + numThreads * iterationsPerThread + " create/drop cycles");

    MongoRunner.stopMongod(conn);
})();
