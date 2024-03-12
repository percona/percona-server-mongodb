(function() {
"use strict";
load('jstests/telemetry/_telemetry_helpers.js');

var telmTestSharding = function() {
    mkdir(telmPath);
    cleanupTelmDir();

    var st = new ShardingTest({
        shards: 1,
        config: 1,
        mongos: 1,
        rs: { nodes: 1, setParameter: setParameterOpts },
        mongosOptions: { setParameter: setParameterOpts },
        configOptions: { setParameter: setParameterOpts }
    });

    sleep(3000);

    //test mongos + config_svr + shard_svr
    var telmFileList = listFiles(telmPath);
    assert.eq(3,telmFileList.length,telmFileList)

    cleanupTelmDir();
    //wait for sh init
    sleep(5000);
    var telmData = getTelmRawData();
    jsTest.log("Get sharded cluster telemetry");
    jsTest.log(telmData)
    assert.includes(telmData,'mongos');
    var configTelmData = getTelmDataByConn(st.config0)[0];
    var shardTelmData = getTelmDataByConn(st.shard0)[0];
    assert(configTelmData['db_cluster_id']);
    assert(shardTelmData['db_cluster_id']);
    assert.eq(configTelmData['db_cluster_id'],shardTelmData['db_cluster_id']);
    assert.eq(configTelmData['config_svr'],'true');
    assert.eq(shardTelmData['shard_svr'],'true');
    assert.eq(shardTelmData['config_svr'],'false');
    st.stop();
};

telmTestSharding();
}());
