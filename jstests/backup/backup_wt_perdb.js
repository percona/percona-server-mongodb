load("jstests/backup/_backup_helpers.js");

(function () {
    "use strict";

    // Grab the storage engine, default is wiredTiger
    var storageEngine = jsTest.options().storageEngine || "wiredTiger";
    if (storageEngine !== "wiredTiger") {
        jsTest.log('Skipping test because storageEngine is not "wiredTiger"');
        return;
    }

    // Run the original instance and fill it with data.
    var dbPath = MongoRunner.dataPath + "original";
    var conn = MongoRunner.runMongod({
        dbpath: dbPath,
        directoryperdb: "",
    });

    fillData(conn);
    var hashesOrig = computeHashes(conn);

    // Create backup.
    var backupPath = backup(conn);
    // Ensure we can still write after backup has finished
    // and the data written doesn't affect backed up values.
    fillData(conn, 500);
    MongoRunner.stopMongod(conn);

    // Run the backup instance.
    var conn = MongoRunner.runMongod({
        dbpath: backupPath,
        directoryperdb: "",
        noCleanData: true,
    });

    var hashesBackup = computeHashes(conn);
    assert.hashesEq(hashesOrig, hashesBackup);

    MongoRunner.stopMongod(conn);
})();
