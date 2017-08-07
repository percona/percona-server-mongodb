(function() {
    'use strict';

    var conn = MongoRunner.runMongod({});
    var db = conn.getDB('test');

    // use runCommand(profile) to set collScanLimit and to check current state
    {
        var res = db.runCommand( { profile: 2, slowms: 150, collscanlimit: 1000 } );
        assert.commandWorked(res, "'profile' command failed to set profiling options");
        assert.eq(res.was, 0);
        assert.eq(res.slowms, 100);
        assert.eq(res.collscanlimit, -1);
        res = db.runCommand( { profile: -1 } );
        assert.commandWorked(res, "'profile' command failed to get current configuration");
        assert.eq(res.was, 2);
        assert.eq(res.slowms, 150);
        assert.eq(res.collscanlimit, 1000);
    }

    MongoRunner.stopMongod(conn);
})();
