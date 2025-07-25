// test that enableSharding gets audited

import {
    auditTestShard,
    getDBPath,
    loadAuditEventsIntoCollection,
    withinInterval
} from 'jstests/audit/_audit_helpers.js';

auditTestShard('addShard', function(st) {
    let rsname = "testreplset";
    let port = allocatePorts(10)[9];
    let conn1 = MongoRunner.runMongod({
        dbpath: getDBPath() + '/' + jsTestName() + '-extraShard-' + port,
        port: port,
        shardsvr: "",
        replSet: rsname
    });
    let hostandport = conn1.host;
    assert.commandWorked(conn1.adminCommand(
        {replSetInitiate: {"_id": rsname, "members": [{"_id": 0, "host": hostandport}]}}));

    let connstr = rsname + "/" + hostandport;
    const beforeCmd = Date.now();
    assert.commandWorked(st.s0.adminCommand({addshard: connstr}));

    const beforeLoad = Date.now();
    let auditColl = loadAuditEventsIntoCollection(
        st.s0, getDBPath() + '/auditLog-s0.json', jsTestName(), 'auditEvents');
    assert.eq(1,
              auditColl.count({
                  atype: "addShard",
                  ts: withinInterval(beforeCmd, beforeLoad),
                  'param.connectionString': connstr,
                  result: 0,
              }),
              "FAILED, audit log: " + tojson(auditColl.find().toArray()));

    MongoRunner.stopMongod(conn1);
}, {/* no special mongod options */});
