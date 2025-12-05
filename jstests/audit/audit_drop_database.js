// test that dropDatabase gets audited

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

var testDBName = 'audit_drop_database';

auditTest('dropDatabase', function(m) {
    var testDB = m.getDB(testDBName);
    assert.writeOK(testDB.getCollection('foo').insert({a: 1}));
    const beforeCmd = Date.now();
    assert.commandWorked(testDB.dropDatabase());

    const beforeLoad = Date.now();
    var auditColl = getAuditEventsCollection(m, testDBName);
    assert.eq(1,
              auditColl.count({
                  atype: "dropDatabase",
                  ts: withinInterval(beforeCmd, beforeLoad),
                  'param.ns': testDBName,
                  result: 0,
              }),
              "FAILED, audit log: " + tojson(auditColl.find().toArray()));
}, {/* no special mongod options */});
