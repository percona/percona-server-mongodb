// test that enableSharding gets audited

if (TestData.testData !== undefined) {
    load(TestData.testData + '/audit/_audit_helpers.js');
} else {
    load('jstests/audit/_audit_helpers.js');
}

auditTestShard(
    'removeShard',
    function(st) {
        let rsname = "testreplset";
        var port = allocatePorts(10)[9];
        var conn1 = MongoRunner.runMongod({dbpath: '/data/db/' + jsTestName() + '-extraShard-' + port, port: port,  shardsvr: "", replSet: rsname});

        var hostandport = conn1.host;
        assert.commandWorked(conn1.adminCommand({
            replSetInitiate: {
                "_id": rsname,
                "members": [{"_id": 0, "host": hostandport}]
            }
        }));

        let connstr = rsname + "/" + hostandport;
        assert.commandWorked(st.s0.adminCommand({addshard: connstr, name: 'removable'}));

        let cmdcnt = 0;
        const beforeCmd = Date.now();
        var removeRet;
        do {
            ++cmdcnt;
            removeRet = st.s0.adminCommand({removeShard: 'removable'});
            assert.commandWorked(removeRet);
        } while (removeRet.state != 'completed');

        const beforeLoad = Date.now();
        auditColl = loadAuditEventsIntoCollection(st.s0, getDBPath() + '/auditLog-c0.json', jsTestName(), 'auditEvents');
        assert.eq(cmdcnt, auditColl.count({
            atype: "removeShard",
            ts: withinInterval(beforeCmd, beforeLoad),
            'param.shard': 'removable',
            result: 0,
        }), "FAILED, audit log: " + tojson(auditColl.find().toArray()));

        MongoRunner.stopMongod(conn1);
    },
    { /* no special mongod options */ }
);
