// Check that updates don't fail during backup.
load("jstests/backup/_backup_helpers.js");

var sleepTime = 2500;
var updateWorkers = 3;
// The minimum speed ratio backup should have compared to normal
// performance. Otherwise it's not 'hot' as writes are blocked for
// sufficient time.
var backupSpeedRatio = 0.25;

function countObjs(conn) {
    // Just go through all possible database names.
    var objs = 0;
    for (var i = 0; i < 10; i++) {
        var db = conn.getDB("db" + i);
        objs += db.stats().objects;
    }
    return objs;
}

(function () {
    "use strict";

    // Run the original instance.
    var dbPath = MongoRunner.dataPath + "original";
    var conn = MongoRunner.runMongod({
        dbpath: dbPath,
        port: 20100,
    });
    var signal = conn.getDB("signal").signal;

    // Start parallel update workers.
    var w = [];
    for (var i = 0; i < updateWorkers; i++) {
        w[i] = startParallelShell(function () {
            Random.setRandomSeed();
            db = db.getSiblingDB("db" + Random.randInt(10));
            var coll = db.getCollection("coll" + Random.randInt(10));
            var signal = db.getSiblingDB("signal").signal;
            while (signal.findOne() == null) {
                var key = "key" + Random.randInt(1000);
                assert.writeOK(coll.insert({k: 1}));
            }
        }, 20100);
    }

    // Wait for filling in some data.
    sleep(sleepTime);

    // Create backup.
    var objsSleep = countObjs(conn);
    var startTime = Date.now();
    backup(conn);

    // Signal workers.
    signal.insert({1: 1});
    var backupTime = Date.now() - startTime;

    for (var i = 0; i < updateWorkers; i++) {
        assert.eq(0, w[i](), "wrong shell's exit code");
    }

    // Ensure backup speed is good enough.
    var objsBackup = countObjs(conn) - objsSleep;
    assert.gte(objsBackup / backupTime, (backupSpeedRatio * objsSleep) / sleepTime, "hot backup is too slow");

    MongoRunner.stopMongod(conn);
})();
