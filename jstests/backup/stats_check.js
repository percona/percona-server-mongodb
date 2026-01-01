load("jstests/backup/_backup_helpers.js");

(function () {
    "use strict";

    // Run the original instance and fill it with data.
    var dbPath = MongoRunner.dataPath + "original";
    var conn = MongoRunner.runMongod({
        dbpath: dbPath,
    });

    fillData(conn);
    var statsOrig = getDB(conn).runCommand({dbStats: 1});
    assert.commandWorked(statsOrig);

    // Create backup.
    var backupPath = backup(conn);
    MongoRunner.stopMongod(conn);

    // Run the backup instance.
    var conn = MongoRunner.runMongod({
        dbpath: backupPath,
        noCleanData: true,
    });

    var statsBackup = getDB(conn).runCommand({dbStats: 1});
    assert.commandWorked(statsBackup);
    assert.eq(statsOrig.objects, statsBackup.objects, "objects doesn't match");
    assert.eq(statsOrig.dataSize, statsBackup.dataSize, "dataSize doesn't match");

    MongoRunner.stopMongod(conn);
})();
