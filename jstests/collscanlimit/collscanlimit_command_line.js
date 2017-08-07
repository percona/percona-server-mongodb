(function() {
    'use strict';

    // set collScanLimit 1000 on the command line
    var conn = MongoRunner.runMongod({collScanLimit: 1000});
    var db = conn.getDB('test');

    // compare reported collScanLimit with the value set on the command line
    {
        var ps = db.getProfilingStatus();
        assert.eq(ps.was, 0);
        assert.eq(ps.slowms, 100);
        assert.eq(ps.collscanlimit, 1000);
    }

    MongoRunner.stopMongod(conn);
})();
