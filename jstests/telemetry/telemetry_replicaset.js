import {ReplSetTest} from "jstests/libs/replsettest.js";
import {
    telmPath,
    setParameterOpts,
    cleanupTelmDir,
    getTelmRawData,
    getTelmDataByConn,
    waitForTelm,
} from "jstests/telemetry/_telemetry_helpers.js";

(function () {
    "use strict";

    var telmTestRepl = function () {
        mkdir(telmPath);
        cleanupTelmDir();

        var replTest = new ReplSetTest({
            nodeOptions: {setParameter: setParameterOpts},
            nodes: [
                {
                    /* primary */
                },
                {/* secondary */ rsConfig: {priority: 0}},
                {/* arbiter */ rsConfig: {arbiterOnly: true}},
            ],
        });
        replTest.startSet();
        replTest.initiate();

        // Let every member reach its steady replication state before sampling telemetry,
        // then drop any telemetry captured during STARTUP so the files we read reflect the
        // settled PRIMARY/SECONDARY/ARBITER states. The first scrape can otherwise capture
        // a transient STARTUP state (more likely when startup is slow), which made the
        // replication_state asserts flaky. Counting distinct instances afterwards tolerates
        // extra files from repeated scrapes.
        replTest.awaitSecondaryNodes();
        cleanupTelmDir();
        // Wait until all three members have reported, capturing each node's telemetry from
        // the poll so we don't re-read and race a .tmp -> .json rename.
        var primaryTelmData, secondaryTelmData, arbiterTelmData;
        waitForTelm(
            () => {
                const primary = getTelmDataByConn(replTest.nodes[0]);
                const secondary = getTelmDataByConn(replTest.nodes[1]);
                const arbiter = getTelmDataByConn(replTest.nodes[2]);
                if (primary.length > 0 && secondary.length > 0 && arbiter.length > 0) {
                    primaryTelmData = primary[0];
                    secondaryTelmData = secondary[0];
                    arbiterTelmData = arbiter[0];
                    return true;
                }
                return false;
            },
            () =>
                "telemetry from 3 replica set members did not appear; files: " +
                tojson(listFiles(telmPath)),
        );

        //test replication_state
        var telmData = getTelmRawData();
        jsTest.log("Get RS tetemetry");
        jsTest.log(telmData);
        var dbReplicationId = primaryTelmData["db_replication_id"];
        assert.eq(primaryTelmData["replication_state"], "PRIMARY");
        assert.eq(secondaryTelmData["replication_state"], "SECONDARY");
        assert.eq(arbiterTelmData["replication_state"], "ARBITER");
        assert.eq(secondaryTelmData["db_replication_id"], dbReplicationId);
        assert.eq(arbiterTelmData["db_replication_id"], dbReplicationId);

        replTest.stopSet();
    };

    telmTestRepl();
})();
