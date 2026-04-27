/**
 * Tests that a rollback directory is created for oplog entries during replica set rollback, and
 * verifies that the rolled back oplogs are written to that directory.
 *
 * @tags: [
 *   requires_persistence,
 *   requires_fcv_81,
 *   requires_mongobridge,
 * ]
 */

import {RollbackTest} from "jstests/replsets/libs/rollback_test.js";

function runRollbackOplogsTest(shouldCreateRollbackFiles) {
    jsTestLog("Testing createRollbackDataFiles = " + shouldCreateRollbackFiles);
    const rollbackTest = new RollbackTest(jsTestName());
    const rollbackNode = rollbackTest.getPrimary();
    const secondTermPrimary = rollbackTest.getSecondary();
    assert.commandWorked(
        rollbackNode.getDB("admin").adminCommand({setParameter: 1, createRollbackDataFiles: shouldCreateRollbackFiles}),
    );
    assert.commandWorked(
        secondTermPrimary
            .getDB("admin")
            .adminCommand({setParameter: 1, createRollbackDataFiles: shouldCreateRollbackFiles}),
    );

    const dbName = "test";
    const collName = "rollbackColl";

    // Isolate the rollbackNode (current primary node) and insert documents (which will be rolled
    // back).
    rollbackTest.transitionToRollbackOperations();
    assert.commandWorked(rollbackNode.getDB(dbName)[collName].insert({"a": 1}));
    assert.commandWorked(rollbackNode.getDB(dbName)[collName].insert({"a": 2}));
    const rst = rollbackTest.getTestFixture();
    const oplogsToRollback = rst.findOplog(rollbackNode, {}).toArray();

    // Elect the previous secondary as the new primary.
    rollbackTest.transitionToSyncSourceOperationsBeforeRollback();
    assert.commandWorked(secondTermPrimary.getDB(dbName)[collName].insert({"b": 1}));

    // Reconnect the isolated node and rollback should start.
    rollbackTest.transitionToSyncSourceOperationsDuringRollback();
    // Transition back to steady state.
    rollbackTest.transitionToSteadyStateOperations();

    // Check for rollback files.
    const rollbackNodePath = rst.getDbPath(rollbackNode);
    const oplogRollbackDir = rollbackNodePath + "/rollback/local.oplog.rs";
    assert.eq(pathExists(oplogRollbackDir), shouldCreateRollbackFiles, oplogRollbackDir);
    if (shouldCreateRollbackFiles) {
        const listRollbackFiles = listFiles(oplogRollbackDir);
        assert.gt(listRollbackFiles.length, 0, "Expected rollback files in " + oplogRollbackDir);
        let oplogsRolledBack = [];
        let filesAreEncrypted = false;
        for (let i = 0; i < listRollbackFiles.length; i++) {
            const rollbackFile = listRollbackFiles[i].name;
            if (
                rollbackFile.endsWith(".enc") ||
                rollbackFile.endsWith(".aes256-cbc") ||
                rollbackFile.endsWith(".aes256-gcm")
            ) {
                print("Bypassing check of rollback file data since it is encrypted: " + rollbackFile);
                filesAreEncrypted = true;
                break;
            }
            oplogsRolledBack = oplogsRolledBack.concat(_readDumpFile(rollbackFile));
        }
        if (!filesAreEncrypted) {
            assert.contains(oplogsToRollback[0], oplogsRolledBack);
            assert.contains(oplogsToRollback[1], oplogsRolledBack);
        }
    }
    rst.stopSet();
}
runRollbackOplogsTest(true);
runRollbackOplogsTest(false);
