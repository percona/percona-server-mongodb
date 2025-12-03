// test that createColleciton gets audited

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

var testDBName = 'audit_create_collection';

auditTest('createCollection', function(m) {
    testDB = m.getDB(testDBName);
    const beforeCmd = Date.now();
    assert.commandWorked(testDB.createCollection('foo'));

    const beforeLoad = Date.now();
    auditColl = getAuditEventsCollection(m, testDBName);
    assert.eq(1,
              auditColl.count({
                  atype: "createCollection",
                  ts: withinInterval(beforeCmd, beforeLoad),
                  'param.ns': testDBName + '.' +
                      'foo',
                  result: 0,
              }),
              "FAILED, audit log: " + tojson(auditColl.find().toArray()));
}, {/* no special mongod options */});
