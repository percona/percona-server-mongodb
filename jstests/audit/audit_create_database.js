// test that createDatabase gets audited

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

var testDBName = 'audit_create_database';

auditTest(
    'createDatabase',
    function(m) {
        testDB = m.getDB(testDBName);
        assert.commandWorked(testDB.dropDatabase());
        assert.commandWorked(testDB.createCollection('foo'));

        // mmapv1 does not generate 'createDatabase' event here
        // so skip this check when mmapv1 is active SE
        if (testDB.serverStatus().storageEngine.name === 'mmapv1') {
            return;
        }

        auditColl = getAuditEventsCollection(m);
        assert.eq(1, auditColl.count({
            atype: "createDatabase",
            ts: withinTheLastFewSeconds(),
            'params.ns': testDBName,
            result: 0,
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));
    },
    { /* no special mongod options */ }
);
