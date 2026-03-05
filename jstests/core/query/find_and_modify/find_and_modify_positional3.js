/**
 * @tags: [
 *   # Primary-driven index builds must have batched writes enabled which config.image_collection
 *   # does not support.
 *   primary_driven_index_builds_incompatible_with_retryable_writes,
 * ]
 */
const c = db[jsTestName()];
c.drop();

assert.commandWorked(c.insert({a: [1, 2]}));

c.findAndModify({query: {a: 1}, update: {$set: {"a.$": 5}}});

assert.eq(5, c.findOne().a[0]);
