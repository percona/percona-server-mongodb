// This is for ngram fts by matt.lee
// @tags: [assumes_no_implicit_index_creation]
(function() {
    "use strict";

    const coll = db.text1;
    coll.drop();

    assert.commandWorked(coll.createIndex({name:"text"}, {default_language: "ngram", name: "x_ngramtext"}));

    assert.writeOK(coll.insert({ _id: 1, name: "MongoDB 3.6은 2016/12일 릴리즈되었습니다." }));
    assert.writeOK(coll.insert({ _id: 2, name: "MongoDB 3.6은 2016-12일 릴리저되었습니다." }));
    assert.writeOK(coll.insert({ _id: 3, name: "MongoDB 3.6은 2016+12일 릴리즈되었습니다." }));
    assert.writeOK(coll.insert({ _id: 4, name: "MongoDB 3.6은 2016*12일 릴리저되었습니다." }));

    var res_count;

    // Single keyword without any special things
    res_count = coll.find({ $text: { $search: "2016" } }).count();
    assert.eq(4, res_count, "Result count is not matched for keyword '2016'");

    // Single keyword contains special character
    res_count = coll.find({ $text: { $search: "2016/12" } }).count();
    assert.eq(1, res_count, "Result count is not matched for keyword '2016/12'");

    res_count = coll.find({ $text: { $search: "2016-12" } }).count();
    assert.eq(1, res_count, "Result count is not matched for keyword '2016-12'");

    res_count = coll.find({ $text: { $search: "2016+12" } }).count();
    assert.eq(1, res_count, "Result count is not matched for keyword '2016+12'");

    res_count = coll.find({ $text: { $search: "2016*12" } }).count();
    assert.eq(1, res_count, "Result count is not matched for keyword '2016*12'");

    // Not found
    res_count = coll.find({ $text: { $search: "2016#12" } }).count();
    assert.eq(0, res_count, "Result count is not matched for keyword '2016#12'");

    // Phrase search
    res_count = coll.find({ $text: { $search: "\"2016/12\"" } }).count();
    assert.eq(1, res_count, "Result count is not matched for phrase '\"2016/12\"'");

    res_count = coll.find({ $text: { $search: "\"2016-12\"" } }).count();
    assert.eq(1, res_count, "Result count is not matched for phrase '\"2016-12\"'");

    res_count = coll.find({ $text: { $search: "\"2016+12\"" } }).count();
    assert.eq(1, res_count, "Result count is not matched for phrase '\"2016+12\"'");

    res_count = coll.find({ $text: { $search: "\"2016*12\"" } }).count();
    assert.eq(1, res_count, "Result count is not matched for phrase '\"2016*12\"'");

    // Not found
    res_count = coll.find({ $text: { $search: "\"2016#12\"" } }).count();
    assert.eq(0, res_count, "Result count is not matched for phrase '\"2016#12\"'");

    // Index meta info
    const index = coll.getIndexes().find(index => index.name === "x_ngramtext");
    assert.neq(index, undefined);
    assert.gte(index.textIndexVersion, 3, tojson(index));
    assert.eq(index.default_language, "ngram", tojson(index));
}());
