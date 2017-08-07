(function() {
    'use strict';

    // in "slow queries" mode only 'slow' or 'collscan' is possible

    // set collScanLimit to 500 and enable 'slow queries' profiling mode
    var conn = MongoRunner.runMongod({profile: 1, slowms: 150, collScanLimit: 500});
    var db = conn.getDB('test');

    // now we have collScanLimit set to 500
    // insert 1000 documents into test collection
    for (var i = 0; i < 1000; i++) {
        db.batch.insert( { n: i, tag: "collScanLimit test" } );
    }

    // do select operation and ensure it is profiled with 'collscan' value in 'profileCause'
    // (it should be profiled because number of scanned documents is greater than current collScanLimit)
    db.batch.find( { n: 25 } ).forEach( printjsononeline );

    // put some slow events and check their behavior
    for (var i = 0; i < 10; i++) {
        db.batch.count( { $where: "(this.n == 0) ? (sleep(200) || true) : false" } );
    }

    // check 'collscan' operations
    var cnt = db.system.profile.count( { op: "query", ns: "test.batch", keysExamined: 0, docsExamined: 1000, profileCause: "collscan" } );
    assert.eq(cnt, 1, "failed to profile COLLSCAN operation");
    // check 'slow' operations
    cnt = db.system.profile.count( { op: "command", ns: "test.batch", profileCause: "slow" } );
    assert.eq(cnt, 10, "failed to profile slow operations");
    // ensure there is no other operations
    cnt = db.system.profile.count( { ns: "test.batch", profileCause: { $nin: [ "collscan", "slow" ]} } );
    assert.eq(cnt, 0, "wrong 'profileCause' value detected in 'slow queries' profiling mode");


    // clear system.profile collection
    db.runCommand( { profile: 0 });
    db.system.profile.drop();

    // now check reasons in "all queries" mode
    db.runCommand( { profile: 2, collscanlimit: -1 } );
    db.batch.find( { n: 25 } ).forEach( printjsononeline );
    db.batch.find( { n: 25 } ).forEach( printjsononeline );
    db.batch.find( { n: 25 } ).forEach( printjsononeline );

    cnt = db.system.profile.count( { ns: "test.batch", profileCause: "all" } );
    assert.eq(cnt, 3, "wrong 'profileCause' value detected in 'slow queries' profiling mode");

    // create some 'random' operations
    db.runCommand( { profile: 2, ratelimit: 5 } );
    for (var i = 0; i < 1000; i++) {
        db.batch.insert( { n: i, tag: "randomly profiled" } );
    }
    cnt = db.system.profile.count( { op: "insert", ns: "test.batch", "query.documents.0.tag": "randomly profiled" } );
    assert(10 < cnt, "randomly profiled operations are missing");

    MongoRunner.stopMongod(conn);
})();
