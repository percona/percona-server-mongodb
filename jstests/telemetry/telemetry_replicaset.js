(function() {
"use strict";
load('jstests/telemetry/_telemetry_helpers.js');

var telmTestRepl = function() {
    mkdir(telmPath);
    cleanupTelmDir();

    var replTest = new ReplSetTest({
        nodeOptions: { setParameter: setParameterOpts },
        nodes: [
            {/* primary */},
            {/* secondary */ rsConfig: {priority: 0}},
            {/* arbiter */ rsConfig: {arbiterOnly: true}}
        ]
    });
    replTest.startSet();
    replTest.initiate();

    sleep(3000);

    var telmFileList = listFiles(telmPath);
    assert.eq(3,telmFileList.length,telmFileList);

    //test replication_state
    var telmData = getTelmRawData();
    jsTest.log("Get RS tetemetry");
    jsTest.log(telmData);
    var primaryTelmData = getTelmDataByConn(replTest.nodes[0])[0];
    var secondaryTelmData = getTelmDataByConn(replTest.nodes[1])[0];
    var arbiterTelmData = getTelmDataByConn(replTest.nodes[2])[0];
    var dbReplicationId = primaryTelmData['db_replication_id'];
    assert.eq(primaryTelmData['replication_state'],'PRIMARY');
    assert.eq(secondaryTelmData['replication_state'],'SECONDARY');
    assert.eq(arbiterTelmData['replication_state'],'ARBITER');
    assert.eq(secondaryTelmData['db_replication_id'],dbReplicationId);
    assert.eq(arbiterTelmData['db_replication_id'],dbReplicationId);

    replTest.stopSet();
};

telmTestRepl();
}());
