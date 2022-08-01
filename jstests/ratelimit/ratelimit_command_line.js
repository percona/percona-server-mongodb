(function() {
    'use strict';

    // set rateLimit 100 on the command line
    var conn = MongoRunner.runMongod({rateLimit: 100});
    var db = conn.getDB('test');

    // compare reported rateLimit with the value set on the command line
    {
        var ps = db.getProfilingStatus();
        assert.eq(ps.was, 0);
        assert.eq(ps.slowms, 100);
        assert.eq(ps.ratelimit, 100);
    }

    MongoRunner.stopMongod(conn);

    // ensure that mongod can start with non-default slowOpSampleRate
    conn = MongoRunner.runMongod( {slowOpSampleRate: 0.7} );
    assert(conn !== null, "cannot start mongod with --slowOpSampleRate specified");
    MongoRunner.stopMongod(conn);

    // if one of the parameters has default value then mongod should start
    conn = MongoRunner.runMongod( {rateLimit: 1, slowOpSampleRate: 0.7} );
    assert(conn !== null, "cannot start mongod with --slowOpSampleRate specified");
    MongoRunner.stopMongod(conn);

    conn = MongoRunner.runMongod( {rateLimit: 100, slowOpSampleRate: 1.0} );
    assert(conn !== null, "cannot start mongod with --slowOpSampleRate specified");
    MongoRunner.stopMongod(conn);

    // ensure that mongod does not accept non-default values for both --rateLimit and --slowOpSampleRate
    clearRawMongoProgramOutput();
    assert.throws(() => MongoRunner.runMongod({rateLimit: 100, slowOpSampleRate: 0.7}));
    assert(rawMongoProgramOutput().includes(
        "Can't specify non-default values for both --rateLimit and --slowOpSampleRate options."));
})();
