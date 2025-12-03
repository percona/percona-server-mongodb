export const telmPath = "/tmp/psmdb";
export const setParameterOpts = {
    perconaTelemetryPath: telmPath,
    perconaTelemetryGracePeriod: 2,
    perconaTelemetryScrapeInterval: 5,
    perconaTelemetryHistoryKeepInterval: 9
};

export var cleanupDir = function(dir) {
    var files = listFiles(dir);
    files.forEach((file) => {
        removeFile(file.name)
    });
};

export var cleanupTelmDir = function() {
    cleanupDir(telmPath);
};

export var getTelmRawData = function() {
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

export var getTelmDataByConn = function(conn) {
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

export var getTelmDataForMongos = function() {
    var files = listFiles(telmPath);
    var data = [];
    files.forEach((file) => {
        const obj = JSON.parse(cat(file.name));
        if (obj.source === "mongos") {
            data.push(obj);
        }
    });
    return data;
}
