/**
 * PSMDB-1997: WT-native TDE lifecycle hooks.
 *
 * Verifies the user-visible properties of the design without depending on
 * server internals that aren't exposed via an admin command:
 *
 *   1. A drop+recreate cycle of the same database name keeps data intact
 *      across the cycle. With generation keyIds (Phase 1), the recreated
 *      database is encrypted under a fresh "<dbName>.<UUID>" generation;
 *      with the deferred cleanup (Phase 4), the previous generation's row
 *      in table:key is reaped via WT_ENCRYPTOR::uri_dropped. Either piece
 *      missing manifests as either decryption failure on the recreated
 *      database (stale cached encryptor) or a panic in WT (key bytes gone
 *      while idents still reference them).
 *
 *   2. A long sequence of drop+create cycles in a single mongod process
 *      doesn't grow unbounded state. We don't currently have a debug
 *      command to read out the size of WT's per-keyid encryptor cache or
 *      the number of rows in the keys DB's table:key, so we exercise the
 *      cycle and rely on resmoke's validate-on-shutdown plus a final
 *      restart-and-read pass to confirm no corruption.
 *
 *   3. A graceful restart in the middle of cycles preserves data.
 *      seedRefcountsFromWtMetadata (Phase 4) walks WT metadata at startup
 *      and rebuilds the per-keyId refcount before the first user op can
 *      fire uri_dropped; without it the first post-restart drop would
 *      log a "no refcount entry for keyid" warning and leak the row.
 *
 * @tags: [requires_wiredtiger]
 */
(function () {
    "use strict";

    const keyFile = TestData.keyFileGood || "jstests/percona/tde/ekf";
    const cipherMode = TestData.cipherMode || "AES256-GCM";
    const dbpath = MongoRunner.dataPath + "tde_lifecycle";

    const startConn = (extraOpts) => {
        return MongoRunner.runMongod(
            Object.assign(
                {
                    dbpath: dbpath,
                    enableEncryption: "",
                    encryptionKeyFile: keyFile,
                    encryptionCipherMode: cipherMode,
                },
                extraOpts || {},
            ),
        );
    };

    // 1. Drop + recreate of the same database name keeps data intact.
    jsTestLog("Drop+recreate of same dbName preserves data");
    {
        let conn = startConn({});
        assert.neq(null, conn);

        let foo = conn.getDB("foo");
        assert.commandWorked(foo.bar.insertMany([{x: 1}, {x: 2}, {x: 3}]));
        assert.eq(3, foo.bar.countDocuments({}));

        // Drop the whole database. Phase 1 clears table:active_keyid for
        // "foo"; Phase 4 reaps "foo.<UUID-A>" once every URI under it
        // fires uri_dropped.
        assert.commandWorked(foo.dropDatabase());

        // Recreate. Phase 1 allocates a fresh "foo.<UUID-B>" -- a stale
        // cached encryptor from generation A would silently encrypt the
        // new data with the wrong key, which would surface as a WT_PANIC
        // on the readback below.
        foo = conn.getDB("foo");
        assert.commandWorked(foo.bar.insertOne({y: "newdata", a: 1}));
        assert.commandWorked(foo.bar.insertOne({y: "newdata", a: 2}));
        assert.eq(2, foo.bar.countDocuments({}));
        const docs = foo.bar.find({y: "newdata"}).sort({a: 1}).toArray();
        assert.eq(2, docs.length);
        assert.eq(1, docs[0].a);
        assert.eq(2, docs[1].a);

        MongoRunner.stopMongod(conn);
    }

    // 2. A loop of drop+create cycles in a single connection. The plan's
    //    long_connection.js property: WT's encryptor cache shouldn't grow
    //    unbounded per cycle. Without an admin command exposing the cache
    //    size we can't assert that directly here; we exercise the cycle
    //    and let resmoke's validate-on-shutdown catch corruption.
    jsTestLog("Repeated drop+create cycles in a single connection");
    {
        let conn = startConn({noCleanData: true});
        assert.neq(null, conn);

        for (let i = 0; i < 50; ++i) {
            const dbName = "cycle_" + i;
            let testDb = conn.getDB(dbName);
            assert.commandWorked(testDb.coll.insertOne({i: i, payload: "x".repeat(64)}));
            assert.eq(1, testDb.coll.countDocuments({}));
            assert.commandWorked(testDb.dropDatabase());
        }

        // After all the cycles, ensure normal operation still works (the
        // refcount machinery hasn't reaped a still-live keyId by mistake,
        // and the WT cache hasn't been corrupted).
        const verify = conn.getDB("after_cycles");
        assert.commandWorked(verify.sentinel.insertOne({ok: 1}));
        assert.eq(1, verify.sentinel.countDocuments({}));

        MongoRunner.stopMongod(conn);
    }

    // 3. Restart-in-the-middle: data created across multiple generations
    //    of the same dbName must remain readable after a clean restart.
    //    seedRefcountsFromWtMetadata is the load-bearing piece here.
    jsTestLog("Restart preserves data across generations");
    {
        let conn = startConn({noCleanData: true});
        assert.neq(null, conn);

        // Create a database, drop it, recreate it -- generation flip.
        let g = conn.getDB("genflip");
        assert.commandWorked(g.coll.insertOne({gen: "A"}));
        assert.commandWorked(g.dropDatabase());
        g = conn.getDB("genflip");
        assert.commandWorked(g.coll.insertOne({gen: "B"}));

        // Stop and restart cleanly.
        MongoRunner.stopMongod(conn);
        conn = startConn({noCleanData: true});
        assert.neq(null, conn);

        const after = conn.getDB("genflip");
        const allDocs = after.coll.find({}).toArray();
        assert.eq(1, allDocs.length, tojson(allDocs));
        assert.eq("B", allDocs[0].gen);

        // One more drop+create after the restart: the refcount-seeding
        // walk must have captured generation B's URI count, otherwise
        // this drop would log "no refcount entry for keyid" and leak the
        // row in table:key. We don't currently surface that warning to
        // the test, but resmoke's per-test log audits will flag it on
        // CI runs that look for it.
        assert.commandWorked(after.dropDatabase());

        const final = conn.getDB("genflip");
        assert.commandWorked(final.coll.insertOne({gen: "C"}));
        assert.eq(1, final.coll.countDocuments({}));

        MongoRunner.stopMongod(conn);
    }

    jsTestLog("drop_recreate_generation_keyid.js completed successfully");
})();
