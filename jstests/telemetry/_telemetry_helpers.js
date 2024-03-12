const telmPath = "/usr/local/percona/telemetry/psmdb";
const setParameterOpts = {
    perconaTelemetryGracePeriod: 2,
    perconaTelemetryScrapeInterval: 5,
    perconaTelemetryHistoryKeepInterval: 9
};

var cleanupTelmDir = function() {
    var files = listFiles(telmPath);
    files.forEach((file) => {
        removeFile(file.name)
    });
};

var getTelmRawData = function() {
    var files = listFiles(telmPath);
    var data = '';
    files.forEach((file) => {
        data = data + cat(file.name)
    });
    return data;
};

var getTelmInstanceId = function(conn) {
    var cmdLineOpts = conn.getDB("admin").runCommand({getCmdLineOpts: 1});
    var dbPath = cmdLineOpts['parsed']['storage']['dbPath'];
    var telmId = _readDumpFile(dbPath + "/psmdb_telemetry.data");
    return telmId[0]['db_instance_id'].str;
};

var getTelmDataByConn = function(conn) {
    var id = getTelmInstanceId(conn);
    var files = listFiles(telmPath);
    var data = [] ;
    files.forEach((file) => {
        if (file.name.includes(id)) {
            data.push(JSON.parse(cat(file.name)))
        }
    });
    return data;
};
