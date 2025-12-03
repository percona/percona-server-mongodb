// test that enableSharding gets audited

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

auditTestShard('enableSharding', function(st) {
    testDB = st.s0.getDB(jsTestName());
    assert.commandWorked(testDB.dropDatabase());
    const beforeCmd = Date.now();
    assert.commandWorked(st.s0.adminCommand({enableSharding: jsTestName()}));

    const beforeLoad = Date.now();
    auditColl = loadAuditEventsIntoCollection(
        st.s0, getDBPath() + '/auditLog-c0.json', testDB.getName(), 'auditEvents');
    assert.eq(1,
              auditColl.count({
                  atype: "enableSharding",
                  ts: withinInterval(beforeCmd, beforeLoad),
                  'param.ns': jsTestName(),
                  result: 0,
              }),
              "FAILED, audit log: " + tojson(auditColl.find().toArray()));
}, {/* no special mongod options */});
