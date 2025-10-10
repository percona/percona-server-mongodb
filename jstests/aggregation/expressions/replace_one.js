// Test $replaceOne aggregation expressions.

import "jstests/libs/query/sbe_assert_error_override.js";

import {assertArrayEq} from "jstests/aggregation/extras/utils.js";

const coll = db.replace_one;
coll.drop();

function runAndAssert(inputStr, findStr, replacementStr, expectedResult) {
    assertArrayEq({
        actual: coll.aggregate([{
                        $project: {
                            f: {
                                $replaceOne:
                                    {input: inputStr, find: findStr, replacement: replacementStr}
                            }
                        }
                    }])
                    .toArray(),
        expected: expectedResult
    });
}

function runAndAssertThrows(args, code) {
    const error = assert.throws(
        () => coll.aggregate([{$project: {args, result: {$replaceOne: args}}}]).toArray());
    assert.commandFailedWithCode(error, code);
}

assert.commandWorked(coll.insertMany([
    // Test find one.
    {_id: 0, in : "albatross", find: "ross", replace: "rachel"},
    {_id: 1, in : "albatross", find: "", replace: "one "},
    {_id: 2, in : "albatross", find: "", replace: ""},
    {_id: 3, in : "", find: "", replace: "foo"},
    {_id: 4, in : "", find: "", replace: ""},
    // Test find none.
    {_id: 5, in : "albatross", find: "rachel", replace: "ross"},
    {_id: 6, in : "", find: "rachel", replace: "ross"},
    {_id: 7, in : "", find: "rachel", replace: ""},
    // Test finding many only replaces first occurrence.
    {_id: 8, in : "an antelope is an animal", find: "an", replace: ""},
    {_id: 9, in : "an antelope is an animal", find: "an", replace: "this"},
    // Test that any combination of null and non-null arguments returns null.
    {_id: 10, in : null, find: null, replace: null},
    {_id: 11, in : "a", find: null, replace: null},
    {_id: 12, in : null, find: "b", replace: null},
    {_id: 13, in : null, find: null, replace: "c"},
    {_id: 14, in : "a", find: "b", replace: null},
    {_id: 15, in : null, find: "b", replace: "c"},
    {_id: 16, in : "a", find: "b", replace: null},
    // Test that combinations of missing and non-missing arguments returns null.
    {_id: 17},
    {_id: 18, in : "a"},
    {_id: 19, find: "b"},
    {_id: 20, replace: "c"},
    {_id: 21, in : "a", find: "b"},
    {_id: 22, find: "b", replace: "c"},
    {_id: 23, in : "a", find: "b"},
    {_id: 24, in : null, find: null},
    {_id: 25, find: null, replace: null},
    {_id: 26, in : null, replace: null},
]));

runAndAssert("$in", "$find", "$replace", [
    {_id: 0, f: "albatrachel"},
    {_id: 1, f: "one albatross"},
    {_id: 2, f: "albatross"},
    {_id: 3, f: "foo"},
    {_id: 4, f: ""},
    {_id: 5, f: "albatross"},
    {_id: 6, f: ""},
    {_id: 7, f: ""},
    {_id: 8, f: " antelope is an animal"},
    {_id: 9, f: "this antelope is an animal"},
    {_id: 10, f: null},
    {_id: 11, f: null},
    {_id: 12, f: null},
    {_id: 13, f: null},
    {_id: 14, f: null},
    {_id: 15, f: null},
    {_id: 16, f: null},
    {_id: 17, f: null},
    {_id: 18, f: null},
    {_id: 19, f: null},
    {_id: 20, f: null},
    {_id: 21, f: null},
    {_id: 22, f: null},
    {_id: 23, f: null},
    {_id: 24, f: null},
    {_id: 25, f: null},
    {_id: 26, f: null},
]);

//
// Reset and test that if any input is not a string, replaceOne fails with an error.
//

assert(coll.drop());
assert.commandWorked(coll.insertOne({
    obj_field: {a: 1, b: 1, c: {d: 2}},
    arr_field1: [1, 2, 3, "c"],
    arr_field2: ["aaaaa"],
    int_field: 1,
    dbl_field: 1.0,
    null_field: null,
    str_field: "foo",
}));

// replacement is not a string
const invalidReplacementCode = 10503902;
// find is not a string or regex
const invalidFindCode = 10503901;
// input is not a string
const invalidInputCode = 10503904;

runAndAssertThrows({input: "$obj_field", find: "$str_field", replacement: "$str_field"},
                   invalidInputCode);
runAndAssertThrows({input: "$arr_field1", find: "$str_field", replacement: "$str_field"},
                   invalidInputCode);
runAndAssertThrows({input: "$int_field", find: "$str_field", replacement: "$str_field"},
                   invalidInputCode);
runAndAssertThrows({input: "$dbl_field", find: "$str_field", replacement: "$str_field"},
                   invalidInputCode);

runAndAssertThrows({input: "$str_field", find: "$obj_field", replacement: "$str_field"},
                   invalidFindCode);
runAndAssertThrows({input: "$str_field", find: "$arr_field1", replacement: "$str_field"},
                   invalidFindCode);
runAndAssertThrows({input: "$str_field", find: "$int_field", replacement: "$str_field"},
                   invalidFindCode);
runAndAssertThrows({input: "$str_field", find: "$dbl_field", replacement: "$str_field"},
                   invalidFindCode);

runAndAssertThrows({input: "$str_field", find: "$str_field", replacement: "$obj_field"},
                   invalidReplacementCode);
runAndAssertThrows({input: "$str_field", find: "$str_field", replacement: "$arr_field1"},
                   invalidReplacementCode);
runAndAssertThrows({input: "$str_field", find: "$str_field", replacement: "$int_field"},
                   invalidReplacementCode);
runAndAssertThrows({input: "$str_field", find: "$str_field", replacement: "$dbl_field"},
                   invalidReplacementCode);

runAndAssertThrows({input: "$str_field", find: "$arr_field2", replacement: "$dbl_field"},
                   invalidFindCode);
runAndAssertThrows({input: "$obj_field", find: "$arr_field2", replacement: "$str_field"},
                   invalidInputCode);
runAndAssertThrows({input: "$int_field", find: "$arr_field2", replacement: "$dbl_field"},
                   invalidInputCode);
runAndAssertThrows({input: "$arr_field2", find: "$arr_field2", replacement: "$arr_field2"},
                   invalidInputCode);

//
// Test always throws when invalid fields are given, even if some fields are also null or missing.
//

runAndAssertThrows({input: "$obj_field", find: "$null_field", replacement: "$str_field"},
                   invalidInputCode);
runAndAssertThrows({input: "$obj_field", find: "$missing_field", replacement: "$str_field"},
                   invalidInputCode);
runAndAssertThrows({input: "$obj_field", find: "$str_field", replacement: "$null_field"},
                   invalidInputCode);
runAndAssertThrows({input: "$obj_field", find: "$str_field", replacement: "$missing_field"},
                   invalidInputCode);
runAndAssertThrows({input: "$obj_field", find: "$missing_field", replacement: "$null_field"},
                   invalidInputCode);
runAndAssertThrows({input: "$obj_field", find: "$null_field", replacement: "$missing_field"},
                   invalidInputCode);
runAndAssertThrows({input: "$obj_field", find: "$missing_field", replacement: "$missing_field"},
                   invalidInputCode);
runAndAssertThrows({input: "$obj_field", find: "$null_field", replacement: "$null_field"},
                   invalidInputCode);

runAndAssertThrows({input: "$null_field", find: "$obj_field", replacement: "$str_field"},
                   invalidFindCode);
runAndAssertThrows({input: "$missing_field", find: "$obj_field", replacement: "$str_field"},
                   invalidFindCode);
runAndAssertThrows({input: "$str_field", find: "$obj_field", replacement: "$null_field"},
                   invalidFindCode);
runAndAssertThrows({input: "$str_field", find: "$obj_field", replacement: "$missing_field"},
                   invalidFindCode);
runAndAssertThrows({input: "$missing_field", find: "$obj_field", replacement: "$null_field"},
                   invalidFindCode);
runAndAssertThrows({input: "$null_field", find: "$obj_field", replacement: "$missing_field"},
                   invalidFindCode);
runAndAssertThrows({input: "$missing_field", find: "$obj_field", replacement: "$missing_field"},
                   invalidFindCode);
runAndAssertThrows({input: "$null_field", find: "$obj_field", replacement: "$null_field"},
                   invalidFindCode);

runAndAssertThrows({input: "$null_field", find: "$str_field", replacement: "$obj_field"},
                   invalidReplacementCode);
runAndAssertThrows({input: "$missing_field", find: "$str_field", replacement: "$obj_field"},
                   invalidReplacementCode);
runAndAssertThrows({input: "$str_field", find: "$null_field", replacement: "$obj_field"},
                   invalidReplacementCode);
runAndAssertThrows({input: "$str_field", find: "$missing_field", replacement: "$obj_field"},
                   invalidReplacementCode);
runAndAssertThrows({input: "$missing_field", find: "$null_field", replacement: "$obj_field"},
                   invalidReplacementCode);
runAndAssertThrows({input: "$null_field", find: "$missing_field", replacement: "$obj_field"},
                   invalidReplacementCode);
runAndAssertThrows({input: "$missing_field", find: "$missing_field", replacement: "$obj_field"},
                   invalidReplacementCode);
runAndAssertThrows({input: "$null_field", find: "$null_field", replacement: "$obj_field"},
                   invalidReplacementCode);
