/**
 * PSMDB-1997
 * Startup orphan encryption-key cleanup.
 *
 * Verifies:
 *   1. dropDatabase leaves the encryption key in the keystore (the fix's
 *      whole point - inline deletion races with checkpoint cleanup).
 *   2. On the next startup, the orphan-key cleanup deletes the keys.
 *   3. The cleanup runs AFTER abandoned WT idents are dropped, so a single
 *      restart suffices - the keys do not leak to the next startup.
 *   4. The cleanup is idempotent (a second restart deletes nothing).
 *
 * @tags: [requires_wiredtiger, requires_persistence]
 */
(function () {
    "use strict";

    run("chmod", "600", TestData.keyFileGood);

    const dbPath = MongoRunner.dataPath + "psmdb1997-orphan-key-cleanup";
    const dbNames = ["psmdb1997_a", "psmdb1997_b", "psmdb1997_c"];

    const startOpts = {
        dbpath: dbPath,
        enableEncryption: "",
        encryptionKeyFile: TestData.keyFileGood,
        encryptionCipherMode: TestData.cipherMode,
    };

    // First run: create then drop each database. The keys remain in the
    // keystore because per-database keys are no longer deleted inline.
    let conn = MongoRunner.runMongod(startOpts);
    for (const name of dbNames) {
        const sdb = conn.getDB(name);
        assert.commandWorked(sdb.c.insert({x: 1}));
        assert.commandWorked(sdb.c.createIndex({x: 1}));
        assert.commandWorked(sdb.dropDatabase());
    }
    MongoRunner.stopMongod(conn);

    // Second run: same dbpath, same keyfile. Startup must drop abandoned
    // idents (if any) and then clean up the orphan keys.
    conn = MongoRunner.runMongod(
        Object.merge(startOpts, {
            restart: true,
            cleanData: false,
        }),
    );

    const log = assert.commandWorked(conn.adminCommand({getLog: "global"})).log;
    let lastDropIdx = -1;
    let cleanupIdx = -1;
    let cleanupDeleted = -1;
    let cleanupCandidates = -1;
    for (let i = 0; i < log.length; i++) {
        const line = log[i];
        // 22251 = "Dropping unknown ident" (reconcileCatalogAndIdents)
        if (line.indexOf('"id":22251') !== -1) {
            lastDropIdx = i;
        }
        // 29169 = "Orphaned encryption key cleanup completed"
        if (line.indexOf('"id":29169') !== -1) {
            cleanupIdx = i;
            const m = line.match(/"deleted":(\d+)/);
            if (m) cleanupDeleted = parseInt(m[1]);
            const c = line.match(/"candidates":(\d+)/);
            if (c) cleanupCandidates = parseInt(c[1]);
        }
    }

    // The cleanup completion log line must be present.
    assert.gte(cleanupIdx, 0, 'expected "Orphaned encryption key cleanup completed" (logId 29169) in log');

    // Ordering: if reconcile dropped any idents this startup, the cleanup
    // line must come AFTER the last "Dropping unknown ident" line. This is
    // the property the PR enforces - cleanup runs after reconcile so keys
    // for the just-dropped idents are reclaimed in this same startup.
    if (lastDropIdx >= 0) {
        assert.lt(
            lastDropIdx,
            cleanupIdx,
            "orphan-key cleanup (logId 29169) must come after the last 'Dropping " + "unknown ident' (logId 22251)",
        );
    }

    // We dropped three databases in the first run, so at least three keys
    // must have been reclaimed (special keys like the master key are
    // excluded by EncryptionKeyDB::isSpecialKeyId, so they do not inflate
    // the count).
    assert.gte(
        cleanupDeleted,
        dbNames.length,
        "expected at least " +
            dbNames.length +
            " orphan keys deleted, got: " +
            cleanupDeleted +
            " (candidates=" +
            cleanupCandidates +
            ")",
    );

    // Third run: idempotency. Nothing to clean.
    MongoRunner.stopMongod(conn);
    conn = MongoRunner.runMongod(
        Object.merge(startOpts, {
            restart: true,
            cleanData: false,
        }),
    );
    const log2 = assert.commandWorked(conn.adminCommand({getLog: "global"})).log;
    let cleanupDeleted2 = -1;
    for (const line of log2) {
        if (line.indexOf('"id":29169') !== -1) {
            const m = line.match(/"deleted":(\d+)/);
            if (m) cleanupDeleted2 = parseInt(m[1]);
        }
    }
    assert.eq(cleanupDeleted2, 0, "on a second restart cleanup should find no orphans, got deleted=" + cleanupDeleted2);

    MongoRunner.stopMongod(conn);
})();
