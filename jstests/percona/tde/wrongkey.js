/**
 * PSMDB-246
 * Tests that starting instance from backup with the wrong
 * encryption key does not corrupt DB.
 * @tags: [requires_wiredtiger]
 */
(function() {
    'use strict';
	load('jstests/backup/_backup_helpers.js');

    // Run the original instance and fill it with data.
    var dbPath = MongoRunner.dataPath + 'original';
    var conn = MongoRunner.runMongod({
        dbpath: dbPath,
        enableEncryption: '',
        encryptionKeyFile: TestData.keyFileGood,
        encryptionCipherMode: TestData.cipherMode,
    });

    fillData(conn);
    var hashesOrig = computeHashes(conn);

    // Create backup.
    var backupPath = backup(conn);

    // Ensure we can still write after backup has finished
    // and the data written doesn't affect backed up values.
    fillData(conn, 500);

    // Stop the instance
    MongoRunner.stopMongod(conn);

    // Start with the wrong key - ensure it fails
    clearRawMongoProgramOutput();
    assert.throws(() => MongoRunner.runMongod({
        noCleanData: true,
        dbpath: backupPath,
        enableEncryption: '',
        encryptionKeyFile: TestData.keyFileWrong,
        encryptionCipherMode: TestData.cipherMode,
    }));
    assert(rawMongoProgramOutput().includes(
        "EncryptionKeyDB: Failed to start up WiredTiger under any compatibility version."));

    // Start with the correct key - ensure it succeeds and DBHash is correct
    var conn = MongoRunner.runMongod({
        noCleanData: true,
        dbpath: backupPath,
        enableEncryption: '',
        encryptionKeyFile: TestData.keyFileGood,
        encryptionCipherMode: TestData.cipherMode,
    });

    var hashesBackup = computeHashes(conn);
    assert.hashesEq(hashesOrig, hashesBackup);

    MongoRunner.stopMongod(conn);
})();
