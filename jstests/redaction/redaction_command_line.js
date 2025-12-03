(function() {
'use strict';

// turn redaction on on the command line
var conn = MongoRunner.runMongod({redactClientLogData: ""});
var db = conn.getDB('test');

// compare reported redactClientLogData with the value set on the command line
{
    var res = db.getSiblingDB('admin').runCommand({getParameter: 1, "redactClientLogData": 1});
    assert.commandWorked(res, "getParameter failed to get redactClientLogData");
    assert.eq(res.redactClientLogData, true);
}

MongoRunner.stopMongod(conn);
})();
