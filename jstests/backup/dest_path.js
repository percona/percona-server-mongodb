(function () {
    "use strict";

    var conn = MongoRunner.runMongod({});

    var db = conn.getDB("test");
    // Non-admin execution
    assert.commandFailed(db.runCommand({createBackup: 1, backupDir: MongoRunner.dataPath}));

    var adminDB = db.getSiblingDB("admin");

    // Wrong value format
    assert.commandFailed(adminDB.runCommand({createBackup: 1, backupDir: 0}));

    // Non-existent path
    assert.commandFailed(adminDB.runCommand({createBackup: 1, backupDir: "/non-existent/path"}));

    // Relative path
    assert.commandFailed(adminDB.runCommand({createBackup: 1, backupDir: "../usr"}));

    MongoRunner.stopMongod(conn);
})();
