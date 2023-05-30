/**
 * PSMDB-246
 * Tests that starting instance from backup with the wrong
 * encryption key does not corrupt DB (replica set version).
 * @tags: [requires_wiredtiger]
 */
(function() {
    'use strict';
	load('jstests/backup/_backup_helpers.js');

    run("chmod", "600", TestData.keyFileGood);
    run("chmod", "600", TestData.keyFileWrong);

    // Start the replica set and fill it with data.
    var name = 'wrongkey_replset';
    var rs = new ReplSetTest({
        name: name,
        nodes: 3,
    });

    rs.startSet({
        enableEncryption: '',
        encryptionKeyFile: TestData.keyFileGood,
        encryptionCipherMode: TestData.cipherMode,
    });
    rs.initiate();
    var primary = rs.getPrimary();
    fillData(primary);
    var secondary = rs.getSecondary();
    var hashesOrig = computeHashes(secondary);

    // Create backup.
    var backupPath = backup(secondary);

    // Ensure we can still write after backup has finished
    // and the data written doesn't affect backed up values.
    fillData(primary, 500);

    // Stop the instance
    rs.stop(secondary);

    // Start with the wrong key - ensure it fails
    print("Start from backup with the wrong key");
    assert.throws(() => rs.start(secondary, {
        noCleanData: true,
        dbpath: backupPath,
        enableEncryption: '',
        encryptionKeyFile: TestData.keyFileWrong,
        encryptionCipherMode: TestData.cipherMode,
    }, true));

    // Start with the correct key - ensure it succeeds and DBHash is correct
    print("Start from backup with the correct key");
    var secondary = rs.start(
        secondary,
        {
            noCleanData: true,
            dbpath: backupPath,
            enableEncryption: '',
            encryptionKeyFile: TestData.keyFileGood,
            encryptionCipherMode: TestData.cipherMode,
        },
        true);

    var hashesBackup = computeHashes(secondary);
    assert.hashesEq(hashesOrig, hashesBackup);

    rs.stopSet();;
})();
