(function() {
"use strict";
load('jstests/telemetry/_telemetry_helpers.js');

var telmTestSingle = function(storage) {
    mkdir(telmPath);
    cleanupTelmDir();

    var singleTest = MongoRunner.runMongod({
        setParameter: setParameterOpts,
        storageEngine: storage
    });

    //test perconaTelemetryGracePeriod
    sleep(1000);
    var telmFileList = listFiles(telmPath);
    assert.eq(0,telmFileList.length,telmFileList);

    sleep(2000);
    telmFileList = listFiles(telmPath);
    assert.eq(1,telmFileList.length,telmFileList);

    //test telemetry data
    var jsonTelmData = getTelmDataByConn(singleTest)[0];
    jsTest.log("Get single-node telemetry");
    jsTest.log(jsonTelmData);

    assert.eq('mongod',jsonTelmData['source'],jsonTelmData['source']);
    assert(jsonTelmData['percona_features'], "percona_features doesn't exist");
    assert(jsonTelmData['pillar_version'], "pillar_version doesn't exist");
    assert.eq(storage,jsonTelmData['storage_engine'],jsonTelmData['storage_engine']);
    assert(jsonTelmData['db_instance_id'],"db_instance_id doesn't exist");
    assert(jsonTelmData['db_internal_id'],"db_internal_id doesn't exist");
    assert(jsonTelmData['uptime'],"uptime doesn't exist");

    //test perconaTelemetryScrapeInterval
    sleep(5000);
    telmFileList = listFiles(telmPath);
    assert.eq(2,telmFileList.length,telmFileList);

    //test perconaTelemetryHistoryKeepInterval
    sleep(5000);
    telmFileList = listFiles(telmPath);
    assert.eq(2,telmFileList.length,telmFileList);

    //test disable perconaTelemetry
    assert.commandWorked(singleTest.getDB("admin").runCommand({setParameter: 1, "perconaTelemetry": false}));
    cleanupTelmDir();
    sleep(6000);
    telmFileList = listFiles(telmPath);
    assert.eq(0,telmFileList.length,telmFileList);

    //test enable perconaTelemetry
    assert.commandWorked(singleTest.getDB("admin").runCommand({setParameter: 1, "perconaTelemetry": true}));
    sleep(3000);
    telmFileList = listFiles(telmPath);
    assert.eq(1,telmFileList.length,telmFileList);

    MongoRunner.stopMongod(singleTest);
};

telmTestSingle("wiredTiger");
telmTestSingle("inMemory");
}());
