/**
 * PSMDB-1997
 * Index-build spill on a TDE-enabled database.
 *
 * Regression test for an EncryptionKeyDB invariant crash that no other
 * jstest exercises. The crash path is:
 *
 *   index build exceeds maxIndexBuildMemoryUsageMegabytes
 *     -> FileBasedSpiller<...>::protectTmpData() with the collection's
 *        DatabaseName threaded into the sorter
 *     -> WiredTigerEncryptionHooks::dbKey(dbName, buf)
 *     -> EncryptionKeyDB::get_key_by_id(..., pe=nullptr)
 *
 * The "Most other spillers ($sort, $group, $bucketAuto, SBE sort, near,
 * text_or, spool, percentile_algo_accurate) pass dbName = boost::none,
 * which short-circuits in dbKey() before get_key_by_id is called. Only
 * the external-sort index build threads a real dbName through. This
 * makes the dbKey()->get_key_by_id(..., pe=nullptr) call the lone way
 * to ever trip an `invariant(pe)` on the per-DB path - so without this
 * test any future regression that adds such an invariant would pass CI.
 *
 * @tags: [requires_wiredtiger, requires_persistence]
 */
(function () {
    "use strict";

    run("chmod", "600", TestData.keyFileGood);

    const dbPath = MongoRunner.dataPath + "psmdb1997-index-build-spill";

    // 50 MB is the minimum effective value enforced by
    // validateMaxIndexBuildMemoryUsageMegabytesSetting() - see
    // src/mongo/db/index_builds/multi_index_block.idl.
    const maxMemUsageMB = 50;

    const conn = MongoRunner.runMongod({
        dbpath: dbPath,
        enableEncryption: "",
        encryptionKeyFile: TestData.keyFileGood,
        encryptionCipherMode: TestData.cipherMode,
        setParameter: {maxIndexBuildMemoryUsageMegabytes: maxMemUsageMB},
    });

    const testDB = conn.getDB("psmdb1997_spill_db");
    const coll = testDB.spill_target;

    // Each document carries a ~3 KiB unique string. With 30 000 docs the
    // bulk index builder accumulates ~90 MiB of key data, well past the
    // 50 MiB spill threshold.
    const docs = 30 * 1000;
    const filler = "x".repeat(3 * 1024);
    const bulk = coll.initializeUnorderedBulkOp();
    for (let i = 0; i < docs; i++) {
        bulk.insert({a: i, b: i.toString() + filler});
    }
    assert.commandWorked(bulk.execute());

    // Build the index on the long field. Without the fix this crashes
    // inside WiredTigerEncryptionHooks::protectTmpData the first time the
    // bulk builder spills; with the fix it returns successfully.
    assert.commandWorked(coll.createIndex({b: 1}));

    // Sanity check: a spill actually happened, so we know the test
    // exercised the encrypted-spill path rather than building entirely
    // in memory.
    const ss = testDB.serverStatus();
    assert(ss.hasOwnProperty("indexBulkBuilder"), "serverStatus is missing indexBulkBuilder section: " + tojson(ss));
    assert.gt(
        ss.indexBulkBuilder.spilledRanges,
        0,
        "expected at least one spilled range during the index build; got: " + tojson(ss.indexBulkBuilder),
    );

    // Verify the index actually works - this also forces a scan that
    // would surface decryption errors on the just-built index files.
    assert.eq(
        docs,
        coll
            .find({b: {$exists: true}})
            .hint({b: 1})
            .itcount(),
    );

    MongoRunner.stopMongod(conn);
})();
