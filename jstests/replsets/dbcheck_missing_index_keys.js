/**
 * Test missing index keys check in dbCheck. The missing index keys check logs errors in the
 * healthlog for every document that has a field that is indexed but the index key for it does not
 * exist in the index. The healthlog entry contains a list of all missing index keys.
 *
 * @tags: [
 *   featureFlagSecondaryIndexChecksInDbCheck
 * ]
 */

import {ReplSetTest} from "jstests/libs/replsettest.js";
import {
    checkHealthLog,
    clearHealthLog,
    forEachNonArbiterNode,
    insertDocsWithMissingIndexKeys,
    runDbCheck
} from "jstests/replsets/libs/dbcheck_utils.js";

// Skipping data consistency checks because data is inserted into primary and secondary separately.
TestData.skipCollectionAndIndexValidation = true;
TestData.skipCheckDBHashes = true;

const dbName = "dbCheckMissingIndexKeysCheck";
const collName = "dbCheckMissingIndexKeysCheck-collection";

const replSet = new ReplSetTest({name: jsTestName(), nodes: 2});
replSet.startSet();
replSet.initiateWithHighElectionTimeout();

const primary = replSet.getPrimary();
const primaryDb = primary.getDB(dbName);
const secondary = replSet.getSecondary();
const secondaryDb = secondary.getDB(dbName);

const doc1 = {
    a: 1
};
const doc2 = {
    a: 1,
    b: 1
};

const errQuery = {
    operation: "dbCheckBatch",
    severity: "error",
};

const missingKeyErrQuery = {
    ...errQuery,
    msg: "Document has missing index keys",
};

// Return a dbCheck health log query for 'numMissing' missing index keys.
function getMissingIndexKeysQuery(numMissing) {
    return {
        operation: "dbCheckBatch",
        severity: "error",
        msg: "Document has missing index keys",
        "data.context.recordID": {$exists: true},
        $and: [
            {"data.context.missingIndexKeys": {$exists: true}},
            {$expr: {$eq: [{$size: "$data.context.missingIndexKeys"}, numMissing]}}
        ],
        "data.context.missingIndexKeys": {$elemMatch: {"indexSpec": {$exists: true}}}
    };
}

function checkMissingIndexKeys(doc, numDocs = 1, maxDocsPerBatch = 10000) {
    clearHealthLog(replSet);
    primaryDb[collName].drop();

    // Create indexes and insert docs without inserting corresponding index keys.
    insertDocsWithMissingIndexKeys(replSet, dbName, collName, doc, numDocs);

    runDbCheck(replSet, primary.getDB(dbName), collName, {
        maxDocsPerBatch: maxDocsPerBatch,
        validateMode: "dataConsistencyAndMissingIndexKeysCheck"
    });

    let missingIndexKeysQuery = {
        ...getMissingIndexKeysQuery(Object.keys(doc).length),
        "data.context.missingIndexKeys.0.keyString.a": 1
    };
    if (Object.keys(doc).length > 1) {
        missingIndexKeysQuery = {
            ...missingIndexKeysQuery,
            "data.context.missingIndexKeys.1.keyString.b": 1
        };
    }

    forEachNonArbiterNode(replSet, function(node) {
        // Verify that dbCheck caught the missing index keys inconsistency and logged one health log
        // entry per inconsistency.
        checkHealthLog(node.getDB("local").system.healthlog, missingIndexKeysQuery, numDocs);
        // Verify that dbCheck did not log any additional errors outside of the missing keys
        // inconsistency.
        checkHealthLog(node.getDB("local").system.healthlog, errQuery, numDocs);
    });
}

function testMultipleMissingKeys() {
    jsTestLog(
        "Testing that dbCheck logs error in health log for each document with missing index key.");

    // Test for documents with 1 or multiple missing index keys.
    checkMissingIndexKeys(doc1);
    checkMissingIndexKeys(doc2);

    // Test for multiple documents with missing index keys in 1 batch.
    checkMissingIndexKeys(doc1, 10);
    checkMissingIndexKeys(doc2, 10);

    // Test for multiple batches with missing index keys.
    checkMissingIndexKeys(doc1, 10, 2);
}

function testMultipleDocsOneInconsistency() {
    jsTestLog(
        "Testing that dbCheck catches the case where there are multiple identical docs but only one of them has an inconsistency");
    clearHealthLog(replSet);
    primaryDb[collName].drop();

    // Insert multiple docs that are consistent.
    insertDocsWithMissingIndexKeys(replSet, dbName, collName, doc1, 10, false, false);

    // Insert one doc that is inconsistent.
    insertDocsWithMissingIndexKeys(replSet, dbName, collName, doc1, 1, true, true);

    runDbCheck(replSet,
               primaryDb,
               collName,
               {validateMode: "dataConsistencyAndMissingIndexKeysCheck"},
               true);

    forEachNonArbiterNode(replSet, function(node) {
        // Verify that only one missing keys inconsistency was caught.
        checkHealthLog(node.getDB("local").system.healthlog,
                       {...missingKeyErrQuery, "data.context.missingIndexKeys.0.keyString.a": 1},
                       1);
        // Verify that there were no other error entries in the health log.
        checkHealthLog(node.getDB("local").system.healthlog, errQuery, 1);
    });
}

function testNoInconsistencies() {
    jsTestLog("Testing that dbCheck does not log an error when there are no index inconsistencies");
    clearHealthLog(replSet);
    primaryDb[collName].drop();

    // Insert documents without any inconsistencies.
    insertDocsWithMissingIndexKeys(replSet, dbName, collName, doc1, 2, false, false);

    runDbCheck(replSet,
               primaryDb,
               collName,
               {validateMode: "dataConsistencyAndMissingIndexKeysCheck"},
               true);

    // Verify that no error health log entries were logged.
    forEachNonArbiterNode(replSet, function(node) {
        checkHealthLog(node.getDB("local").system.healthlog, errQuery, 0);
    });
}

function testPrimaryOnly() {
    jsTestLog(
        "Testing that dbCheck logs error in health log for missing index keys on the primary.");

    clearHealthLog(replSet);
    primaryDb[collName].drop();

    // Insert a document that has missing index keys on the primary only.
    insertDocsWithMissingIndexKeys(replSet, dbName, collName, doc1, 1, true, false);
    replSet.awaitReplication();

    runDbCheck(replSet,
               primary.getDB(dbName),
               collName,
               {validateMode: "dataConsistencyAndMissingIndexKeysCheck"},
               true);

    // Verify that the primary has a missing key health log entry, but the secondary does not.
    checkHealthLog(
        primary.getDB("local").system.healthlog,
        {...getMissingIndexKeysQuery(1), "data.context.missingIndexKeys.0.keyString.a": 1},
        1);
    checkHealthLog(secondary.getDB("local").system.healthlog, getMissingIndexKeysQuery(1), 0);

    // Verify that both the primary and secondary don't have any other errors.
    checkHealthLog(primary.getDB("local").system.healthlog, errQuery, 1);
    checkHealthLog(secondary.getDB("local").system.healthlog, errQuery, 0);
}

function testSecondaryOnly() {
    jsTestLog(
        "Testing that dbCheck logs error in health log for missing index keys on the secondary.");

    clearHealthLog(replSet);
    primaryDb[collName].drop();

    // Insert a document that has missing index keys on the secondary only.
    insertDocsWithMissingIndexKeys(replSet, dbName, collName, doc1, 1, false, true);
    replSet.awaitReplication();

    runDbCheck(replSet,
               primary.getDB(dbName),
               collName,
               {validateMode: "dataConsistencyAndMissingIndexKeysCheck"},
               true);

    // Verify that the secondary has a missing key health log entry, but the primary does not.
    checkHealthLog(primary.getDB("local").system.healthlog, getMissingIndexKeysQuery(1), 0);
    checkHealthLog(
        secondary.getDB("local").system.healthlog,
        {...getMissingIndexKeysQuery(1), "data.context.missingIndexKeys.0.keyString.a": 1},
        1);

    // Verify that both the primary and secondary don't have any other errors.
    checkHealthLog(primary.getDB("local").system.healthlog, errQuery, 0);
    checkHealthLog(secondary.getDB("local").system.healthlog, errQuery, 1);
}

testMultipleMissingKeys();
testMultipleDocsOneInconsistency();
testNoInconsistencies();
testPrimaryOnly();
testSecondaryOnly();

replSet.stopSet();
