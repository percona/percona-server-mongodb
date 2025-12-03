Random.setRandomSeed();

function getDB(conn) {
    return conn.getDB('db0');
}

function fillData(conn, count = 1000) {
    for (var i = 0, dbs = Random.randInt(10); i < dbs; i++) {
        var db = conn.getDB('db' + i);
        for (var j = 0, colls = Random.randInt(10) + 1; j < colls; j++) {
            var coll = db.getCollection('coll' + j);
            var entries = Math.ceil(count / (dbs * colls));
            for (var k = 0; k < entries; k++) {
                assert.writeOK(coll.insert({k: k}));
            }
        }
    }
}

function computeHashes(conn) {
    hashes = [];
    // Just go through all possible database names.
    for (var i = 0; i < 10; i++) {
        var db = conn.getDB('db' + i);
        hashes.push(db.runCommand({dbHash: 1}));
    }
    return hashes;
}

function backup(conn, createDest = false) {
    var backupPath = MongoRunner.dataPath + 'backup';
    if (createDest)
        mkdir(backupPath);
    var adminDB = conn.getDB('admin');
    assert.commandWorked(adminDB.runCommand({createBackup: 1, backupDir: backupPath}));
    return backupPath;
}

assert.hashesEq = function(orig, backup) {
    assert.eq(orig.length, backup.length, 'hash count doesn\'t match');
    for (var i = 0, len = orig.length; i < len; i++) {
        var hashOrig = orig[i];
        var hashBackup = backup[i];
        assert.eq(hashOrig.md5, hashBackup.md5, 'original and backup hashes don\'t match');
    }
};
