(function () {
    "use strict";

    var conn = MongoRunner.runMongod();
    var db = conn.getDB("test");

    // for compatibility reasons zero rate limit value will be converted to 1 thus disabling filtering profiling events

    // use setParameter to set rate limit 0
    {
        var res = db.getSiblingDB("admin").runCommand({setParameter: 1, "profilingRateLimit": 0});
        assert.commandWorked(res, "setParameter failed to set profilingRateLimit");
    }

    // check that actual rate limit is set to 1
    {
        var ps = db.getProfilingStatus();
        assert.eq(ps.ratelimit, 1);
    }

    // use profile command to set rate limit 0
    {
        var res = db.runCommand({profile: 2, slowms: 150, ratelimit: 0});
        assert.commandWorked(res, "'profile' command failed to set profiling options");
    }

    // check that actual rate limit is set to 1
    {
        var ps = db.getProfilingStatus();
        assert.eq(ps.ratelimit, 1);
    }

    MongoRunner.stopMongod(conn);
})();
