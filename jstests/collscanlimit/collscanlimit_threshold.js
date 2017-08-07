(function() {
    'use strict';

    // set collScanLimit to 500 and enable 'slow queries' profiling mode
    var conn = MongoRunner.runMongod({profile: 1, collScanLimit: 500});
    var db = conn.getDB('test');

    // now we have collScanLimit set to 500
    // insert 1000 documents into test collection
    for (var i = 0; i < 1000; i++) {
        db.batch.insert( { n: i, tag: "collScanLimit test" } );
    }

    // do select operation and ensure it is profiled
    // (it should be profiled because number of scanned documents is greater than current collScanLimit)
    db.batch.find( { n: 25 } ).forEach( printjsononeline );
    var cnt = db.system.profile.count( { op: "query", ns: "test.batch", keysExamined: 0, docsExamined: 1000, profileCause: "collscan" } );
    assert.eq(cnt, 1, "failed to profile COLLSCAN operation");

    db.batch.find( { n: 25 } ).forEach( printjsononeline );
    cnt = db.system.profile.count( { op: "query", ns: "test.batch", keysExamined: 0, docsExamined: 1000, profileCause: "collscan" } );
    assert.eq(cnt, 2, "failed to profile COLLSCAN operation");

    // now set higher threshold value and ensure the same select operation is not profiled
    db.runCommand( { profile: 1, collscanlimit: 10000 } );
    db.batch.find( { n: 25 } ).forEach( printjsononeline );
    cnt = db.system.profile.count( { op: "query", ns: "test.batch", keysExamined: 0, docsExamined: 1000, profileCause: "collscan" } );
    assert.eq(cnt, 2, "COLLSCAN operation was profiled despite it should not");

    MongoRunner.stopMongod(conn);
})();
