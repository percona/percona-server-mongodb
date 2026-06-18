import {
    telmPath,
    setParameterOpts,
    cleanupTelmDir,
    getTelmDataByConn,
    listTelmJsonFiles,
    waitForTelm,
    waitForTelmData,
} from "jstests/telemetry/_telemetry_helpers.js";

(function () {
    "use strict";

    var telmTestSingle = function (storage) {
        mkdir(telmPath);
        cleanupTelmDir();

        var singleTest = MongoRunner.runMongod({
            setParameter: setParameterOpts,
            storageEngine: storage,
        });
        var graceSec = setParameterOpts.perconaTelemetryGracePeriod;
        var scrapeSec = setParameterOpts.perconaTelemetryScrapeInterval;

        // Grace period: the first scrape runs one grace period after start, so the first
        // record's self-reported `uptime` (seconds since start, stamped server-side at
        // scrape time) must be at least the grace period. Checking the value the server
        // stamped is robust on slow machines -- unlike the old fixed shell-side sleep, which
        // raced a startup that had already consumed the grace. Capture the data from the
        // poll so we don't re-read and race a .tmp -> .json rename.
        var jsonTelmData = waitForTelmData(
            () => getTelmDataByConn(singleTest),
            "first telemetry file did not appear after grace period",
        )[0];
        jsTest.log("Get single-node telemetry");
        jsTest.log(jsonTelmData);

        assert.eq("mongod", jsonTelmData["source"], jsonTelmData["source"]);
        assert(jsonTelmData["percona_features"], "percona_features doesn't exist");
        assert(jsonTelmData["pillar_version"], "pillar_version doesn't exist");
        assert.eq(storage, jsonTelmData["storage_engine"], jsonTelmData["storage_engine"]);
        assert(jsonTelmData["db_instance_id"], "db_instance_id doesn't exist");
        assert(jsonTelmData["db_internal_id"], "db_internal_id doesn't exist");
        assert(jsonTelmData["uptime"], "uptime doesn't exist");
        var firstUptime = Number(jsonTelmData["uptime"]);
        assert.gte(
            firstUptime,
            graceSec,
            "first telemetry was written before the grace period elapsed",
        );

        // Scrape interval: a second scrape runs one scrape interval after the first, so a
        // record with a later uptime appears and the gap between the two equals the scrape
        // interval. Capture the later record from the poll and check the delta -- again
        // using the server-stamped uptime rather than shell-side timing.
        var secondUptime;
        waitForTelm(() => {
            const later = getTelmDataByConn(singleTest)
                .map((r) => Number(r["uptime"]))
                .filter((u) => u > firstUptime);
            if (later.length === 0) {
                return false;
            }
            secondUptime = Math.min(...later);
            return true;
        }, "second telemetry scrape did not appear after the scrape interval");
        assert.gte(
            secondUptime - firstUptime,
            scrapeSec,
            "second telemetry scrape ran before the scrape interval elapsed",
        );

        // test perconaTelemetryHistoryKeepInterval: old files are pruned, so the file
        // count stays bounded rather than growing with every scrape. Wait long enough
        // for files to age past the keep interval and for the next scrape to run cleanup.
        var historyKeepSec = setParameterOpts.perconaTelemetryHistoryKeepInterval;
        sleep((historyKeepSec + scrapeSec + 1) * 1000);
        assert.lte(listTelmJsonFiles().length, 2, listFiles(telmPath));

        //test disable perconaTelemetry: no new files are written after disabling
        assert.commandWorked(
            singleTest.getDB("admin").runCommand({setParameter: 1, "perconaTelemetry": false}),
        );
        cleanupTelmDir();
        // Wait longer than a scrape would take, then confirm nothing was written.
        sleep(
            (setParameterOpts.perconaTelemetryScrapeInterval +
                setParameterOpts.perconaTelemetryGracePeriod +
                1) *
                1000,
        );
        assert.eq(0, listTelmJsonFiles().length, listFiles(telmPath));

        //test enable perconaTelemetry
        assert.commandWorked(
            singleTest.getDB("admin").runCommand({setParameter: 1, "perconaTelemetry": true}),
        );
        waitForTelm(
            () => listTelmJsonFiles().length >= 1,
            "telemetry did not resume after re-enabling",
        );

        MongoRunner.stopMongod(singleTest);
    };

    telmTestSingle("wiredTiger");
    telmTestSingle("inMemory");
})();
