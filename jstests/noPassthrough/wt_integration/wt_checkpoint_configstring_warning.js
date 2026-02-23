/**
 * Verifies mongod logs a warning when the WiredTiger engine config string includes
 * "checkpoint=", since this config may cause WiredTiger to start its own internal periodic
 * checkpointing thread while mongod already runs its own periodic checkpointing thread,
 * potentially resulting in duplicate checkpointing.
 */

const conn = MongoRunner.runMongod({
    wiredTigerEngineConfigString: "checkpoint=(wait=100000)",
});
assert(conn);

// We expect to see a warning from running mongod with checkpointing in the wiredTigerEngineConfigString.
checkLog.containsJson(conn, 10781300);

MongoRunner.stopMongod(conn);
