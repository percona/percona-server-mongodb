// Tests that the validate command itself can be interrupted by maxTimeMS.
//
// A failpoint such as failCommand or maxTimeAlwaysTimeOut expires in the command path, before
// validate walks the collection, so the test passes even when an engine never checks the deadline.
// The record scan calls checkForInterrupt() every 4096 records. This test times one full scan and
// then repeats it with maxTimeMS set inside that measured scan.

"use strict";

(function () {
    if (db.serverStatus().storageEngine.name === "mmapv1") {
        print("Validate command cannot be interrupted on 'mmapv1' storage engine. Skipping test.");
        return;
    }

    const ns = db.getName() + ".validate_interrupt";
    const t = db.validate_interrupt;
    t.drop();

    // First checkForInterrupt() in the record scan.
    const kInterruptIntervalNumRecords = 4096;
    const kBatch = 100000;
    const kMaxRecords = 8 * 1000 * 1000;
    let records = 0;

    function insertMore(extra) {
        let left = extra;
        while (left > 0) {
            const bulk = t.initializeUnorderedBulkOp();
            const n = Math.min(kBatch, left);
            for (let i = 0; i < n; i++) {
                bulk.insert({a: records});
                records++;
            }
            assert.commandWorked(bulk.execute());
            left -= n;
        }
    }

    // 20303: record scan started. 20306: validation finished. 5160301: validate caught an interrupt.
    function validationEvents() {
        const logs = assert.commandWorked(db.adminCommand({getLog: "global"})).log;
        const events = [];
        for (const line of logs) {
            let obj;
            try {
                obj = JSON.parse(line);
            } catch (e) {
                continue;
            }
            if (!obj.attr || obj.attr.namespace !== ns) {
                continue;
            }
            if (obj.id === 20303 || obj.id === 20306 || obj.id === 5160301) {
                events.push({id: obj.id, at: new Date(obj.t.$date).getTime()});
            }
        }
        return events;
    }

    function latestScanMillis(events) {
        let start = null;
        let millis = null;
        for (const ev of events) {
            if (ev.id === 20303) {
                start = ev.at;
            } else if (ev.id === 20306 && start !== null) {
                millis = ev.at - start;
                start = null;
            }
        }
        return millis;
    }

    function latestScanWasInterrupted(events) {
        let started = false;
        let interrupted = false;
        for (const ev of events) {
            if (ev.id === 20303) {
                started = true;
                interrupted = false;
            } else if (ev.id === 20306) {
                started = false;
                interrupted = false;
            } else if (ev.id === 5160301 && started) {
                interrupted = true;
            }
        }
        return interrupted;
    }

    insertMore(Math.max(kInterruptIntervalNumRecords, 500000));

    let res = null;
    let maxTimeMS = null;
    while (records <= kMaxRecords) {
        const probeStarted = Date.now();
        const probe = t.runCommand({validate: t.getName(), full: true});
        const probeWallMs = Date.now() - probeStarted;
        assert.commandWorked(probe, "validate probe failed:\n" + tojson(probe));

        const scanMs = latestScanMillis(validationEvents());
        assert(scanMs !== null, "validate did not log the record scan for " + ns);

        // maxTimeMS starts at command start, before the record scan. Land one third of the way
        // through the scan that just finished.
        const beforeScanMs = Math.max(0, probeWallMs - scanMs);
        maxTimeMS = beforeScanMs + Math.max(1, Math.floor(scanMs / 3));

        res = t.runCommand({validate: t.getName(), full: true, maxTimeMS: maxTimeMS});
        if (
            res.ok === 0 &&
            res.code === ErrorCodes.MaxTimeMSExpired &&
            latestScanWasInterrupted(validationEvents())
        ) {
            break;
        }

        if (res.ok === 0 && res.code !== ErrorCodes.MaxTimeMSExpired) {
            const expiredBeforeScan =
                res.code === ErrorCodes.CommandFailed &&
                res.errmsg &&
                res.errmsg.indexOf("MaxTimeMSExpired") !== -1;
            assert(expiredBeforeScan, "validate failed for an unexpected reason:\n" + tojson(res));
        }

        // The scan finished inside the budget, or the deadline expired before the scan started.
        // More records make the scan longer than the work before it.
        if (records * 2 > kMaxRecords) {
            break;
        }
        insertMore(records);
        res = null;
    }

    assert.commandFailedWithCode(
        res,
        ErrorCodes.MaxTimeMSExpired,
        "validate command did not time out during the record scan:\n" + tojson(res),
    );
    assert(
        latestScanWasInterrupted(validationEvents()),
        "validate timed out before the record scan started, maxTimeMS=" +
            maxTimeMS +
            " records=" +
            records +
            "\n" +
            tojson(res),
    );
})();
