// test that createDatabase isn't audited after restart

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

var testDBName = 'audit_no_createdb_restart';

auditTest('noCreateDatabaseRestart', function(m, restartServer) {
    testDB = m.getDB(testDBName);
    assert.commandWorked(testDB.dropDatabase());
    assert.commandWorked(testDB.createCollection('foo'));

    m.getDB('admin').shutdownServer();
    var auditPath = getDBPath() + '/auditLog.json';
    removeFile(auditPath);
    const beforeCmd = Date.now();
    m = restartServer();

    const beforeLoad = Date.now();
    auditColl = getAuditEventsCollection(m, testDBName);
    assert.eq(0,
              auditColl.count({
                  atype: "createDatabase",
                  ts: withinInterval(beforeCmd, beforeLoad),
                  'param.ns': testDBName,
                  result: 0,
              }),
              "FAILED, audit log: " + tojson(auditColl.find().toArray()));
}, {/* no special mongod options */});
