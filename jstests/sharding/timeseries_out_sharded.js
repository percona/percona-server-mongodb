/**
 * Verifies that $out can write to time-series collections from sharded collections. An
 * identical test for non-sharded source collections exist in
 * jstests/core/timeseries/timeseries_out_nonsharded.js
 *
 *
 * @tags: [
 *   # TimeseriesAggTests doesn't handle stepdowns.
 *   does_not_support_stepdowns,
 *   # We need a timeseries collection.
 *   requires_timeseries,
 *   # TODO (SERVER-70605): Remove this tag once the time-series always compressed buckets feature
 *   # flag can be removed.
 *   multiversion_incompatible,
 * ]
 */
import {TimeseriesAggTests} from "jstests/core/timeseries/libs/timeseries_agg_helpers.js";
import {ShardingTest} from "jstests/libs/shardingtest.js";

const numHosts = 10;
const splitPoint = numHosts / 2;
const numIterations = 20;

const st = new ShardingTest({shards: 2});
const dbName = "test";
const testDB = st.s.getDB(dbName);
const targetCollName = "out_time";
const bucketCollFullName = `${dbName}.system.buckets.in`;
assert.commandWorked(testDB.adminCommand({enableSharding: dbName, primaryShard: st.shard0.name}));

let [inColl, observerInColl] =
    TimeseriesAggTests.prepareInputCollections(numHosts, numIterations, true, testDB);

// Split the data over 2 shards. The test data has tags uniformly distributed from 1-10, so for half
// the data to be on each shard, we will split at tags = 5.
testDB.adminCommand({shardCollection: inColl.getFullName(), key: {'tags': 1}});
assert.commandWorked(st.s.adminCommand({split: bucketCollFullName, middle: {'meta': splitPoint}}));
assert.commandWorked(st.s.adminCommand({
    movechunk: bucketCollFullName,
    find: {'meta': splitPoint},
    to: st.shard1.shardName,
    _waitForDelete: true
}));
observerInColl.createIndex({tags: 1});
st.shardColl(observerInColl.getName(), {'tags': 1}, {'tags': splitPoint}, true, dbName);

function runTest({
    observer: observerPipeline,
    timeseries: timeseriesPipeline,
    drop: shouldDrop = true,
    value: valueToCheck = null,
    outputDB: outputDB = testDB
}) {
    let expectedTSOptions = null;
    if (!shouldDrop) {
        // To test if an index is preserved by $out when replacing an existing collection.
        assert.commandWorked(outputDB[targetCollName].createIndex({usage_guest: 1}));
        // To test if $out preserves the original collection options.
        let collections = outputDB.getCollectionInfos({name: targetCollName});
        assert.eq(collections.length, 1, collections);
        expectedTSOptions = collections[0]["options"]["timeseries"];
    } else {
        expectedTSOptions = timeseriesPipeline[0]["$out"]["timeseries"];
    }

    // Gets the expected results from a non time-series observer input collection.
    const expectedResults = TimeseriesAggTests.getOutputAggregateResults(
        observerInColl, observerPipeline, null, shouldDrop, testDB);

    // Gets the actual results from a time-series input collection.
    const actualResults = TimeseriesAggTests.getOutputAggregateResults(
        inColl, timeseriesPipeline, null, shouldDrop, testDB);

    // Verifies that the number of measurements is same as expected.
    TimeseriesAggTests.verifyResults(actualResults, expectedResults);
    if (valueToCheck) {
        for (var i = 0; i < expectedResults.length; ++i) {
            assert.eq(actualResults[i], {"time": valueToCheck}, actualResults);
        }
    }

    let collections = outputDB.getCollectionInfos({name: targetCollName});
    assert.eq(collections.length, 1, collections);

    // Verifies a time-series collection was not made, if that is expected.
    if (!expectedTSOptions) {
        assert(!collections[0]["options"]["timeseries"], collections);
        return;
    }

    // Verifies the time-series options are correct, if a time-series collection is expected.
    let actualOptions = collections[0]["options"]["timeseries"];
    for (let option in expectedTSOptions) {
        assert.eq(expectedTSOptions[option], actualOptions[option], actualOptions);
    }

    // Verifies the original index is maintained, if $out is replacing an existing collection.
    if (!shouldDrop) {
        let indexSpecs = outputDB[targetCollName].getIndexes();
        assert.eq(indexSpecs.filter(index => index.name == "usage_guest_1").length, 1);
    }
}

// Tests that $out works with a source time-series collections writing to a non-timeseries
// collection.
runTest({observer: [{$out: "observer_out"}], timeseries: [{$out: targetCollName}]});

// Tests that $out creates a time-series collection when the collection does not exist.
let timeseriesPipeline = TimeseriesAggTests.generateOutPipeline(
    targetCollName, dbName, {timeField: "time", metaField: "tags"});
runTest({observer: [{$out: "observer_out"}], timeseries: timeseriesPipeline});

// Test that $out can replace an existing time-series collection without the 'timeseries' option.
// Change an option in the existing time-series collections.
assert.commandWorked(testDB.runCommand({collMod: targetCollName, expireAfterSeconds: 3600}));
// Run the $out stage.
timeseriesPipeline = [{$out: targetCollName}];
runTest({observer: [{$out: "observer_out"}], timeseries: timeseriesPipeline, drop: false});

// Test that $out can replace an existing time-series collection with the 'timeseries' option.
let newDate = new Date();
let observerPipeline = [{$set: {"time": newDate}}, {$out: "observer_out"}];
timeseriesPipeline = TimeseriesAggTests.generateOutPipeline(
    targetCollName, dbName, {timeField: "time", metaField: "tags"}, {$set: {"time": newDate}});
// Run the $out stage and confirm all the documents have the new value.
runTest({observer: observerPipeline, timeseries: timeseriesPipeline, drop: false, value: newDate});

// Test that an error is raised if the target collection is a sharded time-series collection.
assert.throwsWithCode(() => observerInColl.aggregate([{$out: inColl.getName()}]),
                      ErrorCodes.IllegalOperation);

// Tests that an error is raised when trying to create a time-series collection from a non
// time-series collection.
let pipeline = TimeseriesAggTests.generateOutPipeline("observer_out", dbName, {timeField: "time"});
assert.throwsWithCode(() => inColl.aggregate(pipeline), 7268700);
assert.throwsWithCode(() => observerInColl.aggregate(pipeline), 7268700);

// Tests that an error is raised for invalid timeseries options.
pipeline = TimeseriesAggTests.generateOutPipeline(
    targetCollName, dbName, {timeField: "time", invalidField: "invalid"});
assert.throwsWithCode(() => inColl.aggregate(pipeline), ErrorCodes.IDLUnknownField);
assert.throwsWithCode(() => observerInColl.aggregate(pipeline), ErrorCodes.IDLUnknownField);

// Tests that an error is raised if the user changes the 'timeField'.
pipeline =
    TimeseriesAggTests.generateOutPipeline(targetCollName, dbName, {timeField: "usage_guest_nice"});
assert.throwsWithCode(() => inColl.aggregate(pipeline), 7406103);
assert.throwsWithCode(() => observerInColl.aggregate(pipeline), 7406103);

// Tests that an error is raised if the user changes the 'metaField'.
pipeline = TimeseriesAggTests.generateOutPipeline(
    targetCollName, dbName, {timeField: "time", metaField: "usage_guest_nice"});
assert.throwsWithCode(() => inColl.aggregate(pipeline), 7406103);
assert.throwsWithCode(() => observerInColl.aggregate(pipeline), 7406103);

// Tests that an error is raised if the user changes 'bucketManSpanSeconds'.
pipeline = TimeseriesAggTests.generateOutPipeline(
    targetCollName,
    dbName,
    {timeField: "time", bucketMaxSpanSeconds: 330, bucketRoundingSeconds: 330});
assert.throwsWithCode(() => inColl.aggregate(pipeline), 7406103);
assert.throwsWithCode(() => observerInColl.aggregate(pipeline), 7406103);

// Tests that an error is raised if the user changes 'granularity'.
pipeline = TimeseriesAggTests.generateOutPipeline(
    targetCollName, dbName, {timeField: "time", granularity: "minutes"});
assert.throwsWithCode(() => inColl.aggregate(pipeline), 7406103);
assert.throwsWithCode(() => observerInColl.aggregate(pipeline), 7406103);

// Tests that an error is raised if a conflicting view exists.
assert.commandWorked(testDB.createCollection("view_out", {viewOn: "out"}));
pipeline = TimeseriesAggTests.generateOutPipeline("view_out", dbName, {timeField: "time"});
assert.throwsWithCode(() => inColl.aggregate(pipeline), 7268700);
assert.throwsWithCode(() => observerInColl.aggregate(pipeline), 7268700);

// Test that we can output to a non existant database. non-timeseries output
const destDB = testDB.getSiblingDB("outDifferentDB");
assert.commandWorked(destDB.dropDatabase());
runTest({observer: [{$out: "observer_out"}], timeseries: [{$out: targetCollName}]});

// Test that we can output to a non existant database. timeseries output
assert.commandWorked(destDB.dropDatabase());
timeseriesPipeline = TimeseriesAggTests.generateOutPipeline(
    targetCollName, destDB.getName(), {timeField: "time", metaField: "tags"});
runTest({
    observer: [{$out: {db: destDB.getName(), coll: "observer_out"}}],
    timeseries: timeseriesPipeline,
    outputDB: destDB
});

st.stop();
