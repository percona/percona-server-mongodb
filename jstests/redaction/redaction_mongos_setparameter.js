(function() {
'use strict';

var conn = new ShardingTest({
    shards: 2,
    mongos: 1,
});
var db = conn.getDB('test');

// use setParameter to turn redaction on and getParameter to check current state
// as a side effect we ensure that default value is off
{
    var res = db.getSiblingDB('admin').runCommand({setParameter: 1, "redactClientLogData": true});
    assert.commandWorked(res, "setParameter failed to set redactClientLogData");
    assert.eq(res.was, false);
    res = db.getSiblingDB('admin').runCommand({getParameter: 1, "redactClientLogData": 1});
    assert.commandWorked(res, "getParameter failed to get redactClientLogData");
    assert.eq(res.redactClientLogData, true);
}

conn.stop();
})();
