// @tags: [
//   requires_fastcount,
//   # Primary-driven index builds must have batched writes enabled which config.image_collection
//   # does not support.
//   primary_driven_index_builds_incompatible_with_retryable_writes,
// ]

const t = db[jsTestName()];
t.drop();

assert.commandWorked(t.insert({x: 1}));
const ret = t.findAndModify({query: {x: 1}, update: {$set: {x: 2}}, new: true});
assert.eq(2, ret.x, tojson(ret));

assert.eq(1, t.count());
