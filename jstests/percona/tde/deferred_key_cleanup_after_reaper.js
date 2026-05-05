/**
 * Regression test for deferred encryption key cleanup signaling after the
 * drop-pending ident reaper runs.
 *
 * The original PSMDB-1997 design used a single dirty flag set by
 * dropCollectionsWithPrefix to trigger the periodic cleanup. That signal
 * fires while the dropped idents are still drop-pending in WT metadata —
 * findOrphanedEncryptionKeyIds correctly counts them as in-use, so the
 * tick consumes the flag without deleting anything. The actual orphans
 * only appear later, after the timestamp monitor fires and the reaper
 * runs WT_SESSION::drop on the idents at the next checkpoint. By then
 * the dirty flag is already cleared and no further signal triggers a
 * cleanup, so the orphan keys persist until the next dropDatabase, a
 * startup, or an admin cleanup command.
 *
 * The fix is to also mark the cleanup dirty whenever the reaper actually
 * drops idents — done from the storage-engine timestamp listener that
 * wraps dropIdentsOlderThan. With the fix in place, the post-checkpoint
 * sequence is:
 *
 *     1. dropDatabase  → markDirty (signal: drop happened)
 *     2. periodic tick → consumes flag, finds 0 orphans (idents drop-pending)
 *     3. checkpoint    → reaper runs WT_SESSION::drop
 *                      → markDirty (signal: idents are gone, keys may be orphan)
 *     4. periodic tick → consumes flag, finds the orphans, deletes them
 *
 * Without the fix step 3's markDirty doesn't happen and step 4 short-circuits.
 *
 * Detection strategy:
 *   1. Run mongod with encryptionKeyCleanupIntervalSeconds = 1.
 *   2. Create databases and drop them ALL up front. Then stop touching the
 *      server. This is the burst-then-quiet pattern that exposes the bug —
 *      no further dropDatabase calls re-arm the dirty flag.
 *   3. Force a checkpoint via fsync so the reaper can advance.
 *   4. Wait via assert.soon for the periodic job (ctx
 *      "OrphanedEncryptionKeyCleanup") to delete one row per dropped
 *      database. With the fix, this happens within a few seconds after
 *      fsync. Without the fix, it never happens — the test times out.
 *   5. Cross-check by running the admin cleanup command and asserting it
 *      finds zero candidates left over.
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
    const numCollections = 2;
    const numDocsPerCollection = 50;

    // Allow plenty of time for: reaper iteration + periodic tick. On slow CI
    // a checkpoint cycle can take several seconds.
    const settleTimeoutMs = 60 * 1000;
    const settleStepMs = 1 * 1000;

    jsTestLog("Starting reaper-triggered cleanup test (cipher mode: " + cipherMode + ")");

    const conn = MongoRunner.runMongod({
        enableEncryption: "",
        encryptionKeyFile: keyFile,
        encryptionCipherMode: cipherMode,
        setParameter: {
            encryptionKeyCleanupIntervalSeconds: cleanupIntervalSecs,
        },
    });
    assert.neq(null, conn, "mongod failed to start with encryption enabled");

    const testDbPrefix = "reaper_signal_";

    function getLatestCleanupSummary(conn, requiredTrigger) {
        const res = assert.commandWorked(conn.getDB("admin").runCommand({getLog: "global"}));
        const log = res.log;
        for (let i = log.length - 1; i >= 0; i--) {
            let entry;
            try {
                entry = JSON.parse(log[i]);
            } catch (e) {
                continue;
            }
            if (entry.id === 29169 && (!requiredTrigger || entry.attr.trigger === requiredTrigger)) {
                return {
                    trigger: entry.attr.trigger,
                    candidates: entry.attr.candidates,
                    deleted: entry.attr.deleted,
                };
            }
        }
        return null;
    }

    function countPeriodicDeletions(conn) {
        const res = assert.commandWorked(conn.getDB("admin").runCommand({getLog: "global"}));
        let count = 0;
        for (const line of res.log) {
            let entry;
            try {
                entry = JSON.parse(line);
            } catch (e) {
                continue;
            }
            if (entry.id === 29160 && entry.ctx === "OrphanedEncryptionKeyCleanup") {
                count += 1;
            }
        }
        return count;
    }

    function forceCheckpoint(conn) {
        assert.commandWorked(conn.getDB("admin").runCommand({fsync: 1}));
    }

    jsTestLog("Phase 1: create " + numDatabases + " databases with data");
    const dbNames = [];
    for (let i = 0; i < numDatabases; i++) {
        const dbName = testDbPrefix + i;
        const db = conn.getDB(dbName);
        for (let c = 0; c < numCollections; c++) {
            const coll = db["c_" + c];
            const docs = [];
            for (let d = 0; d < numDocsPerCollection; d++) {
                docs.push({_id: d, payload: "x".repeat(100)});
            }
            assert.commandWorked(coll.insertMany(docs));
        }
        dbNames.push(dbName);
    }

    const baselinePeriodicDeletions = countPeriodicDeletions(conn);
    jsTestLog("Baseline periodic deletions before drops: " + baselinePeriodicDeletions);

    jsTestLog("Phase 2: drop all " + numDatabases + " databases (burst), then go quiet");
    for (const dbName of dbNames) {
        assert.commandWorked(conn.getDB(dbName).dropDatabase());
    }

    jsTestLog("Phase 3: force a checkpoint so the reaper can run");
    forceCheckpoint(conn);

    jsTestLog(
        "Phase 4: wait for the reaper-triggered signal to drive periodic " +
            "cleanup (expect " +
            numDatabases +
            " periodic deletions within " +
            settleTimeoutMs / 1000 +
            " s)",
    );
    let lastObserved = -1;
    assert.soon(
        function () {
            const observed = countPeriodicDeletions(conn) - baselinePeriodicDeletions;
            if (observed !== lastObserved) {
                jsTestLog("  periodic deletions so far: " + observed + " / " + numDatabases);
                lastObserved = observed;
            }
            // Re-fsync each iteration so the reaper drains incrementally if it
            // needs multiple checkpoint cycles. With the fix, each ident drop
            // re-arms the dirty flag so the next tick rescans.
            forceCheckpoint(conn);
            return observed >= numDatabases;
        },
        "Periodic cleanup did not delete all expected keys within " +
            settleTimeoutMs / 1000 +
            " s. Observed " +
            lastObserved +
            " / " +
            numDatabases +
            " periodic deletions. " +
            "Without the reaper-triggered markEncryptionKeyCleanupDirty " +
            "fix, after dropDatabase the dirty flag is consumed by a tick " +
            "that finds no orphans (drop-pending idents are still in WT " +
            "metadata), and after the reaper drops the idents no signal " +
            "re-arms the flag — so the orphans persist until next " +
            "dropDatabase / startup / admin command.",
        settleTimeoutMs,
        settleStepMs,
    );

    jsTestLog("Phase 5: confirm no orphans remain via admin cleanup");
    assert.commandWorked(conn.getDB("admin").runCommand({cleanupOrphanedEncryptionKeys: 1}));

    const adminSummary = getLatestCleanupSummary(conn, "command");
    assert.neq(adminSummary, null, "expected to find a cleanup completion log entry with " + "trigger=command");
    jsTestLog("Admin cleanup summary: " + tojson(adminSummary));

    assert.eq(
        adminSummary.candidates,
        0,
        "Periodic cleanup should have deleted all orphaned keys " +
            "before the admin command ran, but the admin command found " +
            adminSummary.candidates +
            " candidate(s) left over.",
    );

    jsTestLog("Reaper-triggered cleanup test completed successfully");
    MongoRunner.stopMongod(conn);
})();
