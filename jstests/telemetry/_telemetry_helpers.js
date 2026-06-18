// Telemetry is written to a per-run directory under the test's data path so that
// suites or jobs running concurrently on the same machine never collide on a single
// global location. Falls back to /tmp when not run under resmoke.
const _telmBase =
    typeof MongoRunner !== "undefined" && MongoRunner.dataPath ? MongoRunner.dataPath : "/tmp/";
export const telmPath = _telmBase + "psmdb_telemetry";
export const setParameterOpts = {
    perconaTelemetryPath: telmPath,
    perconaTelemetryGracePeriod: 2,
    perconaTelemetryScrapeInterval: 5,
    perconaTelemetryHistoryKeepInterval: 9,
};

export var cleanupDir = function (dir) {
    var files = listFiles(dir);
    files.forEach((file) => {
        removeFile(file.name);
    });
};

export var cleanupTelmDir = function () {
    cleanupDir(telmPath);
};

// Telemetry polls at this interval. The scrape interval is on the order of seconds, so the
// 200ms assert.soon default just spins; 1s keeps the tests responsive without the churn.
const kTelmPollIntervalMs = 1000;

// Metric files are named "<epoch-seconds>-<instanceId>.json" (see TelemetryThreadBase): the
// writer creates a ".tmp" first and atomically renames it to ".json" once fully written.
// Restricting to ".json" files therefore skips entries caught mid-write, so callers do not
// need to swallow parse errors from partially-written files.
export var listTelmJsonFiles = function (dir = telmPath) {
    return listFiles(dir).filter((file) => file.name.endsWith(".json"));
};

// The instance id is the file-name suffix, so it can be read without parsing the contents.
var telmInstanceIdFromFile = function (file) {
    var base = file.name.replace(/^.*\//, "").replace(/\.json$/, "");
    var dash = base.indexOf("-");
    return dash >= 0 ? base.substring(dash + 1) : base;
};

export var getTelmRawData = function () {
    var files = listFiles(telmPath);
    var data = "";
    files.forEach((file) => {
        data = data + cat(file.name);
    });
    return data;
};

var getTelmInstanceId = function (conn) {
    var cmdLineOpts = conn.getDB("admin").runCommand({getCmdLineOpts: 1});
    var dbPath = cmdLineOpts["parsed"]["storage"]["dbPath"];
    var telmId = _readDumpFile(dbPath + "/psmdb_telemetry.data");
    return telmId[0]["db_instance_id"].str;
};

export var getTelmDataByConn = function (conn) {
    var id = getTelmInstanceId(conn);
    var data = [];
    listTelmJsonFiles().forEach((file) => {
        if (telmInstanceIdFromFile(file) === id) {
            data.push(JSON.parse(cat(file.name)));
        }
    });
    return data;
};

export var getTelmDataForMongos = function () {
    var data = [];
    listTelmJsonFiles().forEach((file) => {
        const obj = JSON.parse(cat(file.name));
        if (obj.source === "mongos") {
            data.push(obj);
        }
    });
    return data;
};

// Number of distinct telemetry-producing instances represented under `dir` (defaults to
// telmPath). The scraper writes a fresh file on every scrape, so the raw file count grows
// with elapsed time/load; counting distinct instances by the instance id encoded in the
// file name (emitted by both mongod and mongos) is timing-independent and is the robust way
// to assert "N nodes reported". Reading the id from the name also avoids parsing files that
// may be caught mid-write.
export var countTelmInstances = function (dir = telmPath) {
    var ids = new Set();
    listTelmJsonFiles(dir).forEach((file) => {
        ids.add(telmInstanceIdFromFile(file));
    });
    return ids.size;
};

// Poll until `predicate` returns truthy, swallowing exceptions thrown while telemetry is
// still being produced (e.g. a node's psmdb_telemetry.data not written yet). Replaces
// fixed sleeps so the tests tolerate slow or variable startup/scrape timing.
export var waitForTelm = function (predicate, msg) {
    assert.soon(
        () => {
            try {
                return predicate();
            } catch (e) {
                return false;
            }
        },
        msg,
        undefined,
        kTelmPollIntervalMs,
    );
};

// Poll until `getter()` returns a non-empty array, swallowing the transient parse errors
// thrown while telemetry files are still being written (.tmp then renamed), and return
// that captured array. Callers reuse the returned data rather than reading again
// afterward, which would re-race an in-progress write.
export var waitForTelmData = function (getter, msg) {
    var captured;
    assert.soon(
        () => {
            try {
                var data = getter();
                if (data.length > 0) {
                    captured = data;
                    return true;
                }
            } catch (e) {
                // telemetry file still being written; retry on the next poll
            }
            return false;
        },
        msg,
        undefined,
        kTelmPollIntervalMs,
    );
    return captured;
};
