/**
 * Tests that if a moveCollection command is issued while there is an ongoing moveCollection
 * operation for the same collection with the same destination shard, the command joins with the
 * ongoing moveCollection instance.
 *
 * @tags: [
 *   does_not_support_stepdowns,
 *   uses_atclustertime,
 * ]
 */
import {Thread} from "jstests/libs/parallelTester.js";
import {ReshardingTest} from "jstests/sharding/libs/resharding_test_fixture.js";
import {runJoinsExistingOperationTest} from "jstests/sharding/libs/resharding_test_joins_operation.js";

// Generates a new thread to run moveCollection.
const makeMoveCollectionThread = (mongosHost, ns, extraArgs) => {
    return new Thread(
        (mongosHost, ns, toShard) => {
            const mongoS = new Mongo(mongosHost);
            assert.commandWorked(mongoS.adminCommand({moveCollection: ns, toShard: toShard}));
        },
        mongosHost,
        ns,
        extraArgs.toShard,
    );
};

const reshardingTest = new ReshardingTest();
reshardingTest.setup();
const donorShardNames = reshardingTest.donorShardNames;
const recipientShardNames = reshardingTest.recipientShardNames;
const sourceCollection = reshardingTest.createUnshardedCollection({
    ns: "reshardingDb.coll",
    primaryShardName: donorShardNames[0],
});

runJoinsExistingOperationTest(reshardingTest, {
    opType: "moveCollection",
    operationArgs: {toShard: recipientShardNames[0]},
    makeJoiningThreadFn: makeMoveCollectionThread,
    joiningThreadExtraArgs: {toShard: recipientShardNames[0]},
});

reshardingTest.teardown();
