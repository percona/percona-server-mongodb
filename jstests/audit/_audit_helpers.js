var getDBPath = function() {
    return MongoRunner.dataDir !== undefined ?
           MongoRunner.dataDir : '/data/db';
}

var auditTest = function(name, fn, serverParams) {
    var loudTestEcho = function(msg) {
        s = '----------------------------- AUDIT UNIT TEST: ' + msg + '-----------------------------';
        print(Array(s.length + 1).join('-'));
        print(s);
    }

    loudTestEcho(name + ' STARTING ');
    removeFile(auditPath);
    var dbpath = getDBPath();
    var auditPath = dbpath + '/auditLog.json';
    removeFile(auditPath);
    var port = allocatePorts(1);
    var conn
    var startServer = function(extraParams) {
        params = Object.merge(mongodOptions(serverParams), extraParams);
        if (serverParams === undefined || serverParams.config === undefined) {
            params = Object.merge({
                auditDestination: 'file',
                auditPath: auditPath,
                auditFormat: 'JSON'
            }, params);
        }
        conn = MongoRunner.runMongod(
            Object.merge({
                port: port,
                dbpath: dbpath,
            }, params)
        );
        return conn;
    }
    var stopServer = function() {
        MongoRunner.stopMongod(conn);
    }
    var restartServer = function() {
        stopServer();
        return startServer({ noCleanData: true });
    }
    try {
        fn(startServer(), restartServer);
    } finally {
        MongoRunner.stopMongod(conn);
    }
    loudTestEcho(name + ' PASSED ');
}

var auditTestRepl = function(name, fn, serverParams) {
    var loudTestEcho = function(msg) {
        s = '----------------------------- AUDIT REPL UNIT TEST: ' + msg + '-----------------------------';
        print(Array(s.length + 1).join('-'));
        print(s);
    }

    loudTestEcho(name + ' STARTING ');
    var replTest = new ReplSetTest({ name: 'auditTestReplSet', cleanData: true, nodes: 2, nodeOptions: mongodOptions(serverParams) });
    replTest.startSet({ auditDestination: 'file' });
    var config = {
        _id: 'auditTestReplSet',
        members: [
            { _id: 0, host: getHostName() + ":" + replTest.ports[0], priority: 2 },
            { _id: 1, host: getHostName() + ":" + replTest.ports[1], priority: 1 },
        ]
    };
    replTest.initiate(config);
    fn(replTest);
    loudTestEcho(name + ' PASSED ');
}

var auditTestShard = function(name, fn, serverParams) {
    var loudTestEcho = function(msg) {
        s = '----------------------------- AUDIT SHARDED UNIT TEST: ' + msg + '-----------------------------';
        print(Array(s.length + 1).join('-'));
        print(s);
    }

    loudTestEcho(name + ' STARTING ');

    var dbpath = getDBPath();
    var st = new ShardingTest({ name: 'auditTestSharding',
                                verbose: 1,
                                mongos: [
                                    Object.merge({
                                        auditPath: dbpath + '/auditLog-s0.json',
                                        auditDestination: 'file',
                                        auditFormat: 'JSON'
                                    }, serverParams),
                                    Object.merge({
                                        auditPath: dbpath + '/auditLog-s1.json',
                                        auditDestination: 'file',
                                        auditFormat: 'JSON'
                                    }, serverParams),
                                ],
                                shards: 2,
                                config: 1,
                                other: {
                                    shardOptions: Object.merge({
                                        auditDestination: 'file',
                                        auditFormat: 'JSON'
                                    }, mongodOptions(serverParams)),
                                    configOptions: {
                                        auditPath: dbpath + '/auditLog-c0.json',
                                        auditDestination: 'file',
                                        auditFormat: 'JSON'
                                    },
                                },
                              });
    try {
        fn(st);
    } finally {
        st.stop();
    }
    loudTestEcho(name + ' PASSED ');
}

// Drop the existing audit events collection, import
// the audit json file, then return the new collection.
var getAuditEventsCollection = function(m, dbname, primary, useAuth) {
    var adminDB = m.getDB('admin');
    var auth = ((useAuth !== undefined) && (useAuth != false)) ? true : false;
    if (auth) {
        assert(adminDB.auth('admin','admin'), "could not auth as admin (pwd admin)");
    }

    // the audit log is specifically parsable by mongoimport,
    // so we use that to conveniently read its contents.
    var auditOptions = adminDB.runCommand('auditGetOptions');
    var auditPath = auditOptions.path;
    var auditCollectionName = 'auditCollection';
    return loadAuditEventsIntoCollection(m, auditPath, dbname, auditCollectionName, primary, auth);
}

// Load audit log events into a named collection
var loadAuditEventsIntoCollection = function(m, filename, dbname, collname, primary, auth) {
    var db = primary !== undefined ? primary.getDB(dbname) : m.getDB(dbname);

    // Make all audit events durable
    // To make "non-durable" events like auth checks or app messages durable
    // we need to put some "durable" events after them.
    // Those extra events won't affect our tests because all tests search
    // events only in strict time range  (beforeCmd, beforeLoad).
    var fooColl = db.getCollection('foo' + Date.now());
    fooColl.insert({a:1});
    fooColl.drop();
    sleep(110);

    // drop collection
    db[collname].drop();
    // load data from audit log file
    var auditCollection = db.getCollection(collname);
    cat(filename)
        .split('\n')
        .filter(line => line.length > 0)
        .forEach(ev => auditCollection.insert(parseJsonCanonical(ev)));

    // there should be no duplicate audit log lines
    assert.commandWorked(auditCollection.createIndex(
        { atype: 1, ts: 1, local: 1, remote: 1, users: 1, param: 1, result: 1 },
        { unique: true }
    ));

    return auditCollection;
}

// Get a query that matches any timestamp generated in the interval
// of (t - n) <= t <= now for some time t.
var withinFewSecondsBefore = function(t, n) {
    fewSecondsAgo = t - ((n !== undefined ? n : 3) * 1000);
    return { '$gte' : new Date(fewSecondsAgo), '$lte': new Date() };
}

// Get a query that matches any timestamp generated in the interval
// of t <= x <= e for some timestamps t and e.
var withinInterval = function(t, e = Date.now())  {
    return { '$gte': new Date(t), '$lte': new Date(e) };
}

// Create Admin user.  Used for authz tests.
var createAdminUserForAudit = function (m) {
    var adminDB = m.getDB('admin');
    adminDB.createUser( {'user':'admin', 
                      'pwd':'admin', 
                      'roles' : ['readWriteAnyDatabase',
                                 'userAdminAnyDatabase',
                                 'clusterAdmin']} );
}

// Creates a User with limited permissions. Used for authz tests.
var createNoPermissionUserForAudit = function (m, db) {
    var passwordUserNameUnion = 'tom';
    var adminDB = m.getDB('admin');
    adminDB.auth('admin','admin');
    db.createUser( {'user':'tom', 'pwd':'tom', 'roles':[]} );
    adminDB.logout();
    return passwordUserNameUnion;
}

// Extracts mongod options from TestData and appends them to the object
var mongodOptions = function(o) {
    if ('storageEngine' in TestData && TestData.storageEngine != "") {
        o.storageEngine = TestData.storageEngine;
    }
    return o;
}
