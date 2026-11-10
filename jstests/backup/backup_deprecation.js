/**
 * Checks that the deprecated createBackup command tells its callers about the deprecation:
 *  - successful replies, and error replies for errors the command reports itself (rather than
 *    by throwing), have a `warning` field;
 *  - the help text mentions the deprecation;
 *  - warning 29176 is logged on each call.
 */
(function () {
    "use strict";

    const kLogId = 29176;
    const kDeprecationMsg =
        "The `createBackup` command has been deprecated and will be removed " +
        "in version 9.0; use Percona Backup for MongoDB instead";

    const conn = MongoRunner.runMongod();
    const adminDB = conn.getDB("admin");

    function checkDeprecationLogLines(expectedCount) {
        const lines = checkLog.getFilteredLogMessages(adminDB, kLogId, {});
        assert.eq(expectedCount, lines.length, tojson(lines));
        for (const line of lines) {
            assert.eq("W", line.s, tojson(line));
            assert.eq(kDeprecationMsg, line.msg, tojson(line));
        }
    }

    // A fresh mongod hasn't logged the warning yet.
    checkDeprecationLogLines(0);

    // 1. A successful call has the warning in its reply and logs it.
    const backupDir = MongoRunner.dataPath + "backup_deprecation";
    const res = assert.commandWorked(adminDB.runCommand({createBackup: 1, backupDir: backupDir}));
    assert.eq(kDeprecationMsg, res.warning, tojson(res));
    checkDeprecationLogLines(1);
    // Only the reply and the log matter here, so the backup itself isn't needed.
    removeFile(backupDir);

    // 2. Error replies the command builds itself (errmsgRun returns false) have the warning too,
    // and the warning is logged again: once per call.
    const errRes = assert.commandFailed(adminDB.runCommand({createBackup: 1, backupDir: "relative/path"}));
    assert.eq(kDeprecationMsg, errRes.warning, tojson(errRes));
    checkDeprecationLogLines(2);

    // 3. The help text mentions the deprecation. A help request doesn't run the command, so
    // nothing new is logged.
    const helpRes = assert.commandWorked(adminDB.runCommand({createBackup: 1, help: true}));
    assert(helpRes.help.includes(kDeprecationMsg), tojson(helpRes));
    checkDeprecationLogLines(2);

    MongoRunner.stopMongod(conn);
})();
