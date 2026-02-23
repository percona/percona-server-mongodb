/**
 * Tests that initial sync waits correctly for its sync source's lastStableRecoveryTimestamp to advance past the initial sync node's beginApplyingTimestamp.
 *
 * @tags: [requires_persistence]
 */
import {configureFailPoint, kDefaultWaitForFailPointTimeout} from "jstests/libs/fail_point_util.js";
import {ReplSetTest} from "jstests/libs/replsettest.js";

const [dbName, collName] = [jsTestName(), "testColl"];

const rst = new ReplSetTest({nodes: 1});

rst.startSet();
rst.initiate();

const primary = rst.getPrimary();
const primaryDb = primary.getDB(dbName);
const primaryColl = primaryDb.getCollection(collName);

rst.awaitReplication();
// Insert some initial data.
const stableTimestamp = assert.commandWorked(primaryColl.insert([{_id: 1}, {_id: 2}, {_id: 3}]));

const holdStableTsPrimary = configureFailPoint(primary, "holdStableTimestampAtSpecificTimestamp", {
    timestamp: stableTimestamp,
});

// Insert some more data.
assert.commandWorked(primaryColl.insert([{_id: 4}, {_id: 5}, {_id: 6}]));

// Spin up initial sync node.
jsTestLog("Starting up initial sync node and test that initial sync times out");
let initialSyncNode = rst.add({
    rsConfig: {priority: 0},
    setParameter: {
        "failpoint.initialSyncHangBeforeCreatingOplog": tojson({mode: "alwaysOn"}),
        "numInitialSyncAttempts": 1,
        // Set a lower timeout to speed up the test.
        "initialSyncWaitForSyncSourceLastStableRecoveryTsRetryPeriodSecs": 10,
    },
});
rst.reInitiate();

assert.commandWorked(
    initialSyncNode.adminCommand({
        waitForFailPoint: "initialSyncHangBeforeCreatingOplog",
        timesEntered: 1,
        maxTimeMS: kDefaultWaitForFailPointTimeout,
    }),
);

// Hang the initialSyncNode before initial sync finishes so we can check initial sync failure.
const beforeFinishFailPoint = configureFailPoint(initialSyncNode, "initialSyncHangBeforeFinish");

assert.commandWorked(
    initialSyncNode.adminCommand({configureFailPoint: "initialSyncHangBeforeCreatingOplog", mode: "off"}),
);

jsTestLog("Waiting for initial sync to fail on the initialSyncNode");
beforeFinishFailPoint.wait();
const replSetStatus = assert.commandWorked(initialSyncNode.adminCommand({replSetGetStatus: 1}));
// The initial sync should have failed.
assert.eq(replSetStatus.initialSyncStatus.failedInitialSyncAttempts, 1, () => tojson(replSetStatus.initialSyncStatus));
const failStatusMsg = replSetStatus.initialSyncStatus.initialSyncAttempts[0].status;
const expectedStatus = "Failed to wait for stale recovery timestamp to advance";
assert(failStatusMsg.includes(expectedStatus), `Status ${failStatusMsg} does not contain expected status msg`);
beforeFinishFailPoint.off();

// Get rid of the failed node so the fixture can stop properly.  We expect it to stop with
// an fassert.
assert.eq(MongoRunner.EXIT_ABRUPT, waitMongoProgram(initialSyncNode.port));
rst.remove(initialSyncNode);
rst.reInitiate();

// Spin up initial sync node again.
jsTestLog("Spinning up initial sync node again and verify that it succeeds if stable timestamp advances on primary");
const kMaxTimeout = 24 * 60 * 60;
initialSyncNode = rst.add({
    rsConfig: {priority: 0},
    setParameter: {
        "failpoint.initialSyncHangBeforeCreatingOplog": tojson({mode: "alwaysOn"}),
        "numInitialSyncAttempts": 1,
        // Set max timeout to prevent test from racing.
        "initialSyncWaitForSyncSourceLastStableRecoveryTsRetryPeriodSecs": kMaxTimeout,
    },
});
rst.reInitiate();

const config = assert.commandWorked(primary.adminCommand({replSetGetConfig: 1}));
assert.commandWorked(
    initialSyncNode.adminCommand({
        waitForFailPoint: "initialSyncHangBeforeCreatingOplog",
        timesEntered: 1,
        maxTimeMS: kDefaultWaitForFailPointTimeout,
    }),
);

assert.commandWorked(
    initialSyncNode.adminCommand({configureFailPoint: "initialSyncHangBeforeCreatingOplog", mode: "off"}),
);

jsTestLog("Wait for the first attempt to fail");
// Hang the initialSyncNode after the first wait attempt fails.
const hangAfterWaitFp = configureFailPoint(initialSyncNode, "initialSyncHangAfterWaitForLastStableRecoveryTimestamp");
// Also set up a failpoint to hang before initial sync finishes.
const hangBeforeFinishFp = configureFailPoint(initialSyncNode, "initialSyncHangBeforeFinish");
assert.commandWorked(
    initialSyncNode.adminCommand({configureFailPoint: "initialSyncHangBeforeCreatingOplog", mode: "off"}),
);

hangAfterWaitFp.wait();

jsTestLog("Allowing primary to advance its stable timestamp again");
holdStableTsPrimary.off();
// Insert some more data.
assert.commandWorked(primaryColl.insert([{_id: 7}, {_id: 8}, {_id: 9}]));
hangAfterWaitFp.off();

jsTestLog("Waiting for initial sync to complete");
hangBeforeFinishFp.wait();
hangBeforeFinishFp.off();
rst.awaitSecondaryNodes();

rst.stopSet();
