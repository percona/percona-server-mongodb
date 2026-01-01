(function () {
    "use strict";

    var conn = MongoRunner.runMongod({});
    var db = conn.getDB("test");

    // check default values
    {
        var ps = db.getProfilingStatus();
        assert.eq(ps.was, 0);
        assert.eq(ps.slowms, 100);
        assert.eq(ps.ratelimit, 1);
    }

    MongoRunner.stopMongod(conn);
})();
