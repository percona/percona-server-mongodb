(function() {
'use strict';

// set rateLimit to 5 and slowms to 5000ms, also enable 'all queries' profiling mode
// here we need a big slowms value to prevent sporadic failures because of random slow inserts
var conn = MongoRunner.runMongod({profile: 2, slowms: 5000, rateLimit: 5});
var db = conn.getDB('test');

//{
//    var res = db.runCommand( { profile: 2, slowms: 150, ratelimit: 5 } );
//    assert.commandWorked(res, "'profile' command failed to set profiling options");
//}

// now we have rateLimit set to 5
// let's check real distribution
for (var i = 0; i < 1000; i++) {
    db.batch.insert({n: i, tag: "rateLimit test"});
}

var cnt = db.system.profile.count({op: "insert", ns: "test.batch"});
assert(
    170 < cnt && cnt < 230,
    "rateLimit failed to filter events (" + cnt + ")" + tojson(db.system.profile.find().toArray()));

// check that all profiled events have correct 'rateLimit' value
var cnt2 = db.system.profile.count({op: "insert", ns: "test.batch", rateLimit: 5});

if (cnt != cnt2) {
    db.system.profile.find().forEach(printjsononeline);
}

assert.eq(cnt, cnt2);

// lower slowms value for the next part of test
db.runCommand({profile: 2, slowms: 150, ratelimit: 5});

// put some slow events and check their behavior
for (var i = 0; i < 10; i++) {
    db.batch.count({$where: "(this.n == 0) ? (sleep(200) || true) : false"});
}

// ensure that rateLimit is 1 for slow queries despite the fact current rateLimit is set to 5
// also ensure that all slow queries are profiled
var cnt3 =
    db.system.profile.count({op: "command", ns: "test.batch", millis: {$gte: 200}, rateLimit: 1});
if (cnt3 != 10) {
    db.system.profile.find({op: "command", ns: "test.batch"}).forEach(printjsononeline);
}
assert.eq(cnt3, 10);

MongoRunner.stopMongod(conn);
})();
