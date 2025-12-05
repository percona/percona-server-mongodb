(function() {
'use strict';

var conn = MongoRunner.runMongod({});
var db = conn.getDB('test');

// if value provided to setParameter is not boolean error should occur
{
    var res = db.getSiblingDB('admin').runCommand({setParameter: 1, "redactClientLogData": 20});
    assert.commandFailed(res, "setParameter successfully assigned 20 to redactClientLogData");
    res = db.getSiblingDB('admin').runCommand({setParameter: 1, "redactClientLogData": "string"});
    assert.commandFailed(res, "setParameter successfully assigned 'string' to redactClientLogData");
}

MongoRunner.stopMongod(conn);
})();
