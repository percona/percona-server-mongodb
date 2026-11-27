import {ShardingTest} from "jstests/libs/shardingtest.js";
import {
    telmPath,
    setParameterOpts,
    cleanupTelmDir,
    getTelmRawData,
    getTelmDataByConn,
    getTelmDataForMongos,
    countTelmInstances,
    waitForTelm,
    cleanupDir,
} from "jstests/telemetry/_telemetry_helpers.js";

(function () {
    "use strict";

    var telmTestSharding = function () {
        mkdir(telmPath);
        cleanupTelmDir();

        var st = new ShardingTest({
            shards: 1,
            config: 1,
            mongos: 1,
            rs: {nodes: 1, setParameter: setParameterOpts},
            mongosOptions: {setParameter: setParameterOpts},
            configOptions: {setParameter: setParameterOpts},
        });

        // Wait until all three roles (mongos + config server + shard) have written
        // telemetry. Counting distinct instances tolerates extra files from repeated
        // scrapes, which made the old "exactly 3 files after a 3s sleep" check flaky
        // (e.g. 5 files observed when startup was slow).
        waitForTelm(
            () => countTelmInstances() >= 3,
            () =>
                "telemetry from 3 instances did not appear; files: " + tojson(listFiles(telmPath)),
        );

        cleanupTelmDir();
        // Wait until every role has reported again after the cleanup, capturing the config
        // and shard telemetry from the poll so we don't re-read and race a .tmp -> .json
        // rename.
        var configTelmData, shardTelmData;
        waitForTelm(() => {
            const mongos = getTelmDataForMongos();
            const config = getTelmDataByConn(st.config0);
            const shard = getTelmDataByConn(st.shard0);
            if (mongos.length > 0 && config.length > 0 && shard.length > 0) {
                configTelmData = config[0];
                shardTelmData = shard[0];
                return true;
            }
            return false;
        }, "telemetry from mongos, config server and shard did not all reappear after cleanup");
        var telmData = getTelmRawData();
        jsTest.log("Get sharded cluster telemetry");
        jsTest.log(telmData);
        assert.includes(telmData, "mongos");
        assert(configTelmData["db_cluster_id"]);
        assert(shardTelmData["db_cluster_id"]);
        assert.eq(configTelmData["db_cluster_id"], shardTelmData["db_cluster_id"]);
        assert.eq(configTelmData["config_svr"], "true");
        assert.eq(shardTelmData["shard_svr"], "true");
        assert.eq(shardTelmData["config_svr"], "false");
        st.stop();
    };

    // True if `dir` exists (creating it if possible) and the current user can write to it.
    var isWritableDir = function (dir) {
        try {
            mkdir(dir);
            var probe = dir + "/telemetry_sharded_probe_" + Date.now();
            writeFile(probe, "");
            removeFile(probe);
            return true;
        } catch (e) {
            return false;
        }
    };

    var telmTestShardingDefaultPaths = function () {
        var mongodTelmPath = "/usr/local/percona/telemetry/psmdb";
        var mongosTelmPath = "/usr/local/percona/telemetry/psmdbs";
        // The default paths are system directories that only exist on hosts with PSMDB
        // installed or when running as root (e.g. CI). Elsewhere, only verify the defaults
        // via getParameter; file writing itself is covered by telmTestSharding().
        var canWrite = isWritableDir(mongodTelmPath) && isWritableDir(mongosTelmPath);
        if (canWrite) {
            cleanupDir(mongodTelmPath);
            cleanupDir(mongosTelmPath);
        }
        var setParameterOpt = {
            perconaTelemetryGracePeriod: 2,
            perconaTelemetryScrapeInterval: 5,
            perconaTelemetryHistoryKeepInterval: 9,
        };

        var st = new ShardingTest({
            shards: 1,
            config: 1,
            mongos: 1,
            rs: {nodes: 1, setParameter: setParameterOpt},
            mongosOptions: {setParameter: setParameterOpt},
            configOptions: {setParameter: setParameterOpt},
        });

        var telmPathOf = (conn) =>
            assert.commandWorked(conn.adminCommand({getParameter: 1, perconaTelemetryPath: 1}))
                .perconaTelemetryPath;
        assert.eq(telmPathOf(st.shard0), mongodTelmPath);
        assert.eq(telmPathOf(st.config0), mongodTelmPath);
        assert.eq(telmPathOf(st.s), mongosTelmPath);

        if (canWrite) {
            // Two mongods (config server + shard) and one mongos should report at their
            // respective default telemetry paths; poll on distinct instances rather than an
            // exact file count so repeated scrapes do not break the check.
            waitForTelm(
                () => countTelmInstances(mongodTelmPath) >= 2,
                () =>
                    "expected telemetry from 2 mongods at default path; files: " +
                    tojson(listFiles(mongodTelmPath)),
            );
            waitForTelm(
                () => countTelmInstances(mongosTelmPath) >= 1,
                () =>
                    "expected telemetry from mongos at default path; files: " +
                    tojson(listFiles(mongosTelmPath)),
            );
        } else {
            jsTest.log.info("Default telemetry paths are not writable; skipping the file check", {
                mongodTelmPath,
                mongosTelmPath,
            });
        }
        st.stop();
    };

    telmTestSharding();
    telmTestShardingDefaultPaths();
})();
