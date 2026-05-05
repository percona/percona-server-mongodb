/**
 * Verifies the per-database keyId generation invariant: every drop+recreate
 * of a database produces a NEW keyId for the new generation, never reusing
 * the previous one.
 *
 * Why this matters: WiredTiger maintains a per-keyid encryptor cache for the
 * lifetime of the connection. Without generation keyIds, drop+recreate of
 * the same dbName would land on the same cached encryptor, which still
 * holds the old key bytes — producing data encrypted under a stale key
 * while a fresh row is being generated in `table:key`. Generations
 * (`<dbName>.<UUID>`) ensure each (re)create lands on a distinct cache
 * slot.
 *
 * Detection strategy:
 *   - Read mongod's WT "create table" log entries (id 51780). The config
 *     attribute embeds the encryption clause: `encryption=(name=percona,
 *     keyid="...")`. Parse the keyid out for collections in the test
 *     database.
 *   - Verify each generation matches `<dbName>.<UUID>`.
 *   - Verify successive drop+create cycles produce DIFFERENT generations.
 *   - Verify multiple collections within the same generation share the
 *     same keyId.
 *
 * @tags: [
 *   requires_wiredtiger,
 * ]
 */
(function () {
    "use strict";

    const keyFile = TestData.keyFileGood || "jstests/percona/tde/ekf";
    const cipherMode = TestData.cipherMode || "AES256-GCM";

    jsTestLog("Starting keyId generations test (cipher mode: " + cipherMode + ")");

    const conn = MongoRunner.runMongod({
        enableEncryption: "",
        encryptionKeyFile: keyFile,
        encryptionCipherMode: cipherMode,
    });
    assert.neq(null, conn, "mongod failed to start with encryption enabled");

    const dbName = "gentest";

    // Returns all "create table" (id 51780) log attribute strings whose
    // config clause names the given dbName as the keyid prefix. The
    // matching is done by string contains: a config carrying
    // `keyid="dbName."` (generation form) or `keyid="dbName"` (legacy form,
    // shouldn't happen on a freshly initialized server but the parser
    // tolerates it).
    function getKeyIdsForDb(conn, dbName) {
        const res = assert.commandWorked(conn.getDB("admin").runCommand({getLog: "global"}));
        const keyIds = [];
        const reGen = new RegExp('keyid=\\\\"(' + dbName + '\\.[^\\\\"]+)\\\\"');
        const reLegacy = new RegExp('keyid=\\\\"(' + dbName + ')\\\\"');
        for (const line of res.log) {
            let entry;
            try {
                entry = JSON.parse(line);
            } catch (e) {
                continue;
            }
            if (entry.id !== 51780) {
                continue;
            }
            const config = (entry.attr && entry.attr.config) || "";
            const m = config.match(reGen) || config.match(reLegacy);
            if (m) {
                keyIds.push(m[1]);
            }
        }
        return keyIds;
    }

    // ---------------------------------------------------------------------
    // Phase 1: first generation — populate dbName, capture its keyId
    // ---------------------------------------------------------------------
    jsTestLog("Phase 1: create " + dbName + " with two collections");
    assert.commandWorked(conn.getDB(dbName).c1.insertOne({_id: 1}));
    assert.commandWorked(conn.getDB(dbName).c2.insertOne({_id: 1}));

    const gen1Keys = getKeyIdsForDb(conn, dbName);
    jsTestLog("Generation 1 keyIds observed: " + tojson(gen1Keys));
    // Expect at least two (record store + index for _id) per collection;
    // all should be the same generation keyId.
    assert.gt(gen1Keys.length, 0, "expected at least one WT create table log entry for " + dbName);

    const gen1Keyset = new Set(gen1Keys);
    assert.eq(
        gen1Keyset.size,
        1,
        "all idents in the same database lifetime must share a keyId; " +
            "observed distinct keyIds " +
            tojson(Array.from(gen1Keyset)),
    );

    const gen1KeyId = gen1Keys[0];
    assert(
        gen1KeyId.startsWith(dbName + "."),
        "generation keyId must be of the form '<dbName>.<UUID>'; got: " + gen1KeyId,
    );

    // ---------------------------------------------------------------------
    // Phase 2: drop + recreate, expect a different keyId
    // ---------------------------------------------------------------------
    jsTestLog("Phase 2: drop and recreate " + dbName);
    assert.commandWorked(conn.getDB(dbName).dropDatabase());
    assert.commandWorked(conn.getDB(dbName).c1.insertOne({_id: 1}));

    const allKeysAfterRecreate = getKeyIdsForDb(conn, dbName);
    // The log accumulates — both generations show up. The newest entries
    // for this dbName are the recreated generation.
    const gen2KeyId = allKeysAfterRecreate[allKeysAfterRecreate.length - 1];
    jsTestLog("Generation 2 keyId observed: " + gen2KeyId);

    assert.neq(
        gen2KeyId,
        gen1KeyId,
        "drop+recreate must produce a NEW keyId, not reuse the " +
            "previous one. With generations off, both would be '" +
            dbName +
            "'. Got: gen1=" +
            gen1KeyId +
            ", gen2=" +
            gen2KeyId,
    );
    assert(
        gen2KeyId.startsWith(dbName + "."),
        "second generation keyId must also be of the form " + "'<dbName>.<UUID>'; got: " + gen2KeyId,
    );

    // ---------------------------------------------------------------------
    // Phase 3: third generation, again different
    // ---------------------------------------------------------------------
    jsTestLog("Phase 3: drop and recreate " + dbName + " again");
    assert.commandWorked(conn.getDB(dbName).dropDatabase());
    assert.commandWorked(conn.getDB(dbName).c1.insertOne({_id: 1}));

    const allKeysAfterThird = getKeyIdsForDb(conn, dbName);
    const gen3KeyId = allKeysAfterThird[allKeysAfterThird.length - 1];
    jsTestLog("Generation 3 keyId observed: " + gen3KeyId);

    assert.neq(gen3KeyId, gen1KeyId, "third generation must differ from first; got " + gen3KeyId);
    assert.neq(gen3KeyId, gen2KeyId, "third generation must differ from second; got " + gen3KeyId);

    jsTestLog("KeyId generations test completed: gen1=" + gen1KeyId + ", gen2=" + gen2KeyId + ", gen3=" + gen3KeyId);
    MongoRunner.stopMongod(conn);
})();
