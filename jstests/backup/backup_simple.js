load('jstests/backup/_backup_helpers.js');

(function() {
    'use strict';

    // Run the original instance and fill it with data.
    var dbPath = MongoRunner.dataPath + 'original';
    var conn = MongoRunner.runMongod({
        dbpath: dbPath,
    });

    fillData(conn);
    var hashesOrig = computeHashes(conn);

    // Create backup.
    var backupPath = backup(conn);
    // Ensure we can still write after backup has finished
    // and the data written doesn't affect backed up values.
    fillData(conn, 500);
    MongoRunner.stopMongod(conn);

    clearRawMongoProgramOutput();
    // Check that backup instanse has engine metadata copied.
    assert.throws(() => MongoRunner.runMongod({
        dbpath: backupPath,
        noCleanData: true,
        storageEngine: 'inMemory',
    }));
    // The log should contain specific error message to avoid false success
    assert(rawMongoProgramOutput().includes(
        "Location28662: Cannot start server. " +
        "Detected data files in " + backupPath +
        " created by the 'wiredTiger' storage engine, " +
        "but the specified storage engine was 'inMemory'."));

    // Run the backup instance.
    var conn = MongoRunner.runMongod({
        dbpath: backupPath,
        noCleanData: true,
    });

    var hashesBackup = computeHashes(conn);
    assert.hashesEq(hashesOrig, hashesBackup);

    MongoRunner.stopMongod(conn);
})();
