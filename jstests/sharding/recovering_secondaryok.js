/**
 * This tests that secondaryOk'd queries in sharded setups get correctly routed when a secondary
 * goes into RECOVERING state, and don't break
 * @tags: [
 *    # TODO (SERVER-88125): Re-enable this test or add an explanation why it is incompatible.
 *    embedded_router_incompatible,
 * ]
 */

// Shard secondaries are restarted, which may cause that shard's primary to stepdown while it does
// not see the secondaries. Either the primary connection gets reset, or the primary could change.
TestData.skipCheckingUUIDsConsistentAcrossCluster = true;

import {awaitRSClientHosts} from "jstests/replsets/rslib.js";
import {ReplSetTest} from "jstests/libs/replsettest.js";
import {ShardingTest} from "jstests/libs/shardingtest.js";

var shardTest =
    new ShardingTest({name: "recovering_secondaryok", shards: 2, mongos: 2, other: {rs: true}});

var mongos = shardTest.s0;
var mongosSOK = shardTest.s1;
mongosSOK.setSecondaryOk();

const dbName = "test";
var dbase = mongos.getDB(dbName);
var coll = dbase.getCollection("foo");
var collSOk = mongosSOK.getCollection("" + coll);

var rsA = shardTest.rs0;
var rsB = shardTest.rs1;

assert.commandWorked(rsA.getPrimary().getDB("test_a").dummy.insert({x: 1}));
assert.commandWorked(rsB.getPrimary().getDB("test_b").dummy.insert({x: 1}));

rsA.awaitReplication();
rsB.awaitReplication();

print("1: initial insert");

assert.commandWorked(coll.save({_id: -1, a: "a", date: new Date()}));
assert.commandWorked(coll.save({_id: 1, b: "b", date: new Date()}));

print("2: shard collection");

shardTest.shardColl(coll,
                    /* shardBy */ {_id: 1},
                    /* splitAt */ {_id: 0},
                    /* move chunk */ {_id: 0},
                    /* dbname */ null,
                    /* waitForDelete */ true);

print("3: test normal and secondaryOk queries");

// Make shardA and rsA the same
var shardA = shardTest.getShard(coll, {_id: -1});
var shardAColl = shardA.getCollection("" + coll);

if (shardA.name == rsB.getURL()) {
    var swap = rsB;
    rsB = rsA;
    rsA = swap;
}

rsA.awaitReplication();
rsB.awaitReplication();

// Because of async migration cleanup, we need to wait for this condition to be true
assert.soon(function() {
    return coll.find().itcount() == collSOk.find().itcount();
});

assert.eq(shardAColl.find().itcount(), 1);
assert.eq(shardAColl.findOne()._id, -1);

print("5: make one of the secondaries RECOVERING");

var secs = rsA.getSecondaries();
var goodSec = secs[0];
var badSec = secs[1];

assert.commandWorked(badSec.adminCommand("replSetMaintenance"));
rsA.waitForState(badSec, ReplSetTest.State.RECOVERING);

print("6: stop non-RECOVERING secondary");

rsA.stop(goodSec);

print("7: check our regular and secondaryOk query");

assert.eq(2, coll.find().itcount());
assert.eq(2, collSOk.find().itcount());

print("8: restart both our secondaries clean");

rsA.restart(rsA.getSecondaries(), {remember: true, startClean: true}, undefined, 5 * 60 * 1000);

print("9: wait for recovery");

rsA.waitForState(rsA.getSecondaries(), ReplSetTest.State.SECONDARY, 5 * 60 * 1000);

print("10: check our regular and secondaryOk query");

// We need to make sure our nodes are considered accessible from mongos - otherwise we fail
// See SERVER-7274
awaitRSClientHosts(coll.getMongo(), rsA.nodes, {ok: true});
awaitRSClientHosts(coll.getMongo(), rsB.nodes, {ok: true});

// We need to make sure at least one secondary is accessible from mongos - otherwise we fail
// See SERVER-7699
awaitRSClientHosts(collSOk.getMongo(), [rsA.getSecondaries()[0]], {secondary: true, ok: true});
awaitRSClientHosts(collSOk.getMongo(), [rsB.getSecondaries()[0]], {secondary: true, ok: true});

print("SecondaryOk Query...");
var sOKCount = collSOk.find().itcount();

var collCount = null;
try {
    print("Normal query...");
    collCount = coll.find().itcount();
} catch (e) {
    printjson(e);

    // There may have been a stepdown caused by step 8, so we run this twice in a row. The first
    // time can error out.
    print("Error may have been caused by stepdown, try again.");
    collCount = coll.find().itcount();
}

assert.eq(collCount, sOKCount);

shardTest.stop();
