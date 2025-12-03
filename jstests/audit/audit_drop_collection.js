// test that dropCollection gets audited

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

var testDBName = 'audit_drop_collection';

auditTest('dropCollection', function(m) {
    testDB = m.getDB(testDBName);
    var collName = 'foo';
    var coll = testDB.getCollection(collName);
    assert.writeOK(coll.insert({a: 17}));
    const beforeCmd = Date.now();
    assert(coll.drop());

    const beforeLoad = Date.now();
    var auditColl = getAuditEventsCollection(m, testDBName);
    assert.eq(1,
              auditColl.count({
                  atype: "dropCollection",
                  ts: withinInterval(beforeCmd, beforeLoad),
                  'param.ns': testDBName + '.' + collName,
                  result: 0,
              }),
              "FAILED, audit log: " + tojson(auditColl.find().toArray()));
}, {/* no special mongod options */});
