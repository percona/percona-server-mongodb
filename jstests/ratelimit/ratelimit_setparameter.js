(function () {
    "use strict";

    var conn = MongoRunner.runMongod({});
    var db = conn.getDB("test");

    // use setParameter to set rate limit and getParameter to check current state
    {
        var res = db.getSiblingDB("admin").runCommand({setParameter: 1, "profilingRateLimit": 79});
        assert.commandWorked(res, "setParameter failed to set profilingRateLimit");
        assert.eq(res.was, 1);
        res = db.getSiblingDB("admin").runCommand({getParameter: 1, "profilingRateLimit": 1});
        assert.commandWorked(res, "getParameter failed to get profilingRateLimit");
        assert.eq(res.profilingRateLimit, 79);
    }

    // check that we cannot use setParameter to set non-default rate limit when sampleRate is non-default
    {
        // set default rate limit and non-default sampleRate
        var res = db.runCommand({profile: 2, ratelimit: 1, sampleRate: 0.5});
        assert.commandWorked(res, "successfully set prohibited parameter values");

        // try to set non-default rate limit (should fail)
        var res = db.getSiblingDB("admin").runCommand({setParameter: 1, "profilingRateLimit": 79});
        assert.commandFailed(res, "setParameter succefully set profilingRateLimit when it should not");
    }

    MongoRunner.stopMongod(conn);
})();
