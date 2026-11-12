/**
 * Checks that the deprecated `createBackup` command tells its callers about the deprecation:
 *  - the help text mentions the deprecation;
 *  - successful replies, and error replies for errors the command reports itself,
 *    have a `warning` field;
 *  - warning 29176 is logged on each call.
 */
import {after, before, beforeEach, describe, it} from "jstests/libs/mochalite.js";

const kLogId = 29176;
const kDeprecationMsg =
    "The `createBackup` command has been deprecated and will be removed " +
    "in version 9.0; use Percona Backup for MongoDB instead";

// Checks that the global log has exactly `expectedCount` deprecation entries.
// Note. Each test case below clears the log first (see `beforeEach`), so
// these are the entries the case itself caused.
function assertDeprecationLogged(adminDb, expectedCount) {
    const lines = checkLog.getFilteredLogMessages(adminDb, kLogId, {});
    assert(Array.isArray(lines), "getLog failed");
    assert.eq(expectedCount, lines.length, "wrong count of deprecation log entries: " + tojson(lines));
    for (const line of lines) {
        assert.eq("W", line.s, "wrong log entry severity: " + tojson(line));
        assert.eq(kDeprecationMsg, line.msg, "wrong log entry message: " + tojson(line));
    }
}

describe("`createBackup` deprecation", function () {
    before(function () {
        this.conn = MongoRunner.runMongod();
        this.adminDb = this.conn.getDB("admin");
    });

    after(function () {
        // If `before` fails, there is no `mongod` to stop
        if (this.conn) {
            MongoRunner.stopMongod(this.conn);
        }
    });

    beforeEach(function () {
        assert.commandWorked(this.adminDb.runCommand({clearLog: "global"}));
    });

    it("mentions the deprecation in the help text", function () {
        const helpRes = assert.commandWorked(this.adminDb.runCommand({createBackup: 1, help: true}));

        assert(helpRes.help.includes(kDeprecationMsg), "help reply: " + tojson(helpRes));
        // A help request doesn't run the command, so nothing is logged.
        assertDeprecationLogged(this.adminDb, 0);
    });

    it("puts the deprecation msg in a successful reply and the log", function () {
        const backupDir = MongoRunner.dataPath + "backup_deprecation";
        try {
            const res = assert.commandWorked(this.adminDb.runCommand({createBackup: 1, backupDir: backupDir}));

            assert.eq(kDeprecationMsg, res.warning, "reply: " + tojson(res));
            assertDeprecationLogged(this.adminDb, 1);
        } finally {
            // Remove the backup directory even if some assertion fails.
            removeFile(backupDir);
        }
    });

    // When `createBackup` detects an error itself (i.e. `CreateBackupCommand::errmsgRun` returns
    // `false`), both the reply and the log have the warning.
    it("puts the deprecation msg in an error reply and the log", function () {
        const res = assert.commandFailed(this.adminDb.runCommand({createBackup: 1, backupDir: "relative/path"}));

        // Make sure the reply comes from the intended `errmsg` path.
        assert.eq("Destination path must be absolute", res.errmsg, "reply: " + tojson(res));
        assert.eq(kDeprecationMsg, res.warning, "reply: " + tojson(res));
        assertDeprecationLogged(this.adminDb, 1);
    });

    // When `createBackup` hits an unexpected error (i.e. `CreateBackupCommand::errmsgRun` throws),
    // the log has the warning but the reply doesn't, because the server discards the partial reply
    // and builds the error reply from the exception.
    //
    // Note: strictly speaking, every reply should contain the warning, but implementing that
    // isn't worth the effort.
    it("puts the deprecation msg in the log but not in an error reply", function () {
        // A non-string `backupDir` makes `BSONElement::String()` throw (code 13111).
        const res = assert.commandFailedWithCode(this.adminDb.runCommand({createBackup: 1, backupDir: 42}), 13111);

        assert(!("warning" in res), "reply: " + tojson(res));
        assertDeprecationLogged(this.adminDb, 1);
    });
});
