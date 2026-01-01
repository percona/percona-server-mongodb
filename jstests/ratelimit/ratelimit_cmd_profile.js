(function () {
    "use strict";

    var conn = MongoRunner.runMongod({});
    var db = conn.getDB("test");

    // use runCommand(profile) to set rateLimit and to check current state
    {
        var res = db.runCommand({profile: 2, slowms: 150, ratelimit: 3});
        assert.commandWorked(res, "'profile' command failed to set profiling options");
        assert.eq(res.was, 0);
        assert.eq(res.slowms, 100);
        assert.eq(res.ratelimit, 1);
        res = db.runCommand({profile: -1});
        assert.commandWorked(res, "'profile' command failed to get current configuration");
        assert.eq(res.was, 2);
        assert.eq(res.slowms, 150);
        assert.eq(res.ratelimit, 3);
    }

    // simultaneous usage of ratelimit and sampleRate parameters
    {
        // simultaneous non-default values for both parameters are prohibited
        var res = db.runCommand({profile: 2, ratelimit: 5, sampleRate: 0.5});
        assert.commandFailed(res, "successfully set prohibited parameter values");

        // default value for ratelimit allows us to set sampleRate
        res = db.runCommand({profile: 2, ratelimit: 1, sampleRate: 0.5});
        assert.commandWorked(res, "cannot set sampleRate along with default ratelimit");
        // implicit default ratelimit value works the same
        res = db.runCommand({profile: 2, sampleRate: 0.7});
        assert.commandWorked(res, "cannot set sampleRate along with default ratelimit");
        res = db.runCommand({profile: -1});
        assert.commandWorked(res, "'profile' command failed to get current configuration");
        assert.eq(res.was, 2);
        assert.eq(res.ratelimit, 1);
        assert.eq(res.sampleRate, 0.7);

        // default value for sampleRate allows us to set ratelimit
        res = db.runCommand({profile: 2, ratelimit: 5, sampleRate: 1.0});
        assert.commandWorked(res, "cannot set sampleRate along with default ratelimit");
        // implicit default sampleRate value works the same
        res = db.runCommand({profile: 2, ratelimit: 7});
        assert.commandWorked(res, "cannot set sampleRate along with default ratelimit");
        res = db.runCommand({profile: -1});
        assert.commandWorked(res, "'profile' command failed to get current configuration");
        assert.eq(res.was, 2);
        assert.eq(res.ratelimit, 7);
        assert.eq(res.sampleRate, 1.0);
    }

    MongoRunner.stopMongod(conn);
})();
