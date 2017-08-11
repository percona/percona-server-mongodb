(function() {
    'use strict';

    var conn = MongoRunner.runMongod({});
    var db = conn.getDB('test');

    // use setParameter to set COLLSCAN profiling threshold and getParameter to check current state
    {
        var res = db.getSiblingDB('admin').runCommand( { setParameter: 1, "profilingCollScanLimit": 1000 } );
        assert.commandWorked(res, "setParameter failed to set profilingCollScanLimit");
        assert.eq(res.was, 0);
        res = db.getSiblingDB('admin').runCommand( { getParameter: 1, "profilingCollScanLimit": 1 } );
        assert.commandWorked(res, "getParameter failed to get profilingCollScanLimit");
        assert.eq(res.profilingCollScanLimit, 1000);

        // check setting boolean true
        res = db.getSiblingDB('admin').runCommand( { setParameter: 1, "profilingCollScanLimit": true } );
        assert.commandWorked(res, "setParameter failed to set profilingCollScanLimit");
        assert.eq(res.was, 1000);
        res = db.getSiblingDB('admin').runCommand( { getParameter: 1, "profilingCollScanLimit": 1 } );
        assert.commandWorked(res, "getParameter failed to get profilingCollScanLimit");
        assert.eq(res.profilingCollScanLimit, 1);

        // check setting boolean false
        res = db.getSiblingDB('admin').runCommand( { setParameter: 1, "profilingCollScanLimit": false } );
        assert.commandWorked(res, "setParameter failed to set profilingCollScanLimit");
        assert.eq(res.was, 1);
        res = db.getSiblingDB('admin').runCommand( { getParameter: 1, "profilingCollScanLimit": 1 } );
        assert.commandWorked(res, "getParameter failed to get profilingCollScanLimit");
        assert.eq(res.profilingCollScanLimit, 0);
    }

    MongoRunner.stopMongod(conn);
})();
