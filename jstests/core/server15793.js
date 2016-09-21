// Check that data size of the storage grows properly after updates.
// This checks that updateRecordEx works as expected.

(function() {
    "use strict";

    var t = db.server15793;
    t.drop();

    assert.writeOK(t.insert({key: 0}));
    var stats = db.runCommand({dbStats: 1});
    assert.commandWorked(stats);
    var origSize = stats.dataSize;

    // Do some updates of our only document.
    for (var i = 0; i < 10; i++) {
        var k = Random.randInt(100).toString();
        assert.writeOK(t.update({key: i}, {key: (i + 1), k: Random.randInt(100)}));
    }

    var stats = db.runCommand({dbStats: 1});
    assert.commandWorked(stats);
    assert.eq(stats.objects, 1, 'invalid objects value');
    // Check that our object grew as new fields were added.
    assert.gt(stats.dataSize, origSize, 'invalid dataSize value');
    // Check that our object didn't grow to be unexpectedly large.
    assert.lt(stats.dataSize, 2 * origSize, 'invalid dataSize value');
}());
