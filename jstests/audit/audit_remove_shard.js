// test that enableSharding gets audited

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

auditTestShard(
    'removeShard',
    function(st) {
        var port = allocatePorts(10)[9];
        var conn1 = MongoRunner.runMongod({dbpath: '/data/db/' + jsTestName() + '-extraShard-' + port, port: port,  shardsvr: ""});

        var hostandport = conn1.host;
        assert.commandWorked(st.s0.adminCommand({addshard: hostandport, name: 'removable'}));

        const beforeCmd = Date.now();
        var removeRet;
        do {
            removeRet = st.s0.adminCommand({removeShard: 'removable'});
            assert.commandWorked(removeRet);
        } while (removeRet.state != 'completed');

        const beforeLoad = Date.now();
        auditColl = loadAuditEventsIntoCollection(st.s0, getDBPath() + '/auditLog-c0.json', jsTestName(), 'auditEvents');
        assert.eq(2, auditColl.count({
            atype: "removeShard",
            ts: withinInterval(beforeCmd, beforeLoad),
            'param.shard': 'removable',
            result: 0,
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        MongoRunner.stopMongod(conn1);
    },
    { /* no special mongod options */ }
);
