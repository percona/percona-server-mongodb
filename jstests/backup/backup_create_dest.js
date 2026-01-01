load("jstests/backup/_backup_helpers.js");

(function () {
    "use strict";

    // Run the original instance and fill it with data.
    var dbPath = MongoRunner.dataPath + "original";
    var conn = MongoRunner.runMongod({
        dbpath: dbPath,
    });

    fillData(conn);
    var hashesOrig = computeHashes(conn);

    // Do backup into existing folder.
    var backupPath = backup(conn, true);
    MongoRunner.stopMongod(conn);

    // Run the backup instance.
    var conn = MongoRunner.runMongod({
        dbpath: backupPath,
        noCleanData: true,
    });

    var hashesBackup = computeHashes(conn);
    assert.hashesEq(hashesOrig, hashesBackup);

    MongoRunner.stopMongod(conn);
})();
