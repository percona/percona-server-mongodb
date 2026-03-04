/**
 * Test explain output (especially 'rejectedPlans') for join optimization.
 *
 * @tags: [
 *   requires_fcv_83,
 *   requires_sbe
 * ]
 */

import {section, subSection} from "jstests/libs/query/pretty_md.js";
import {assertArrayEq} from "jstests/aggregation/extras/utils.js";
import {prettyPrintWinningPlan, prettyPrintRejectedPlans} from "jstests/query_golden/libs/pretty_plan.js";
import {
    joinTestWrapper,
    getJoinTestResultsAndExplain,
    verifyExplainOutput,
} from "jstests/query_golden/libs/join_opt.js";

const coll = db[jsTestName()];
coll.drop();
assert.commandWorked(coll.insertMany([{_id: 0, a: 1}]));

// Create a fully-connected 4-node join (after implicit edges are added in).
const pipeline = [
    {$lookup: {from: coll.getName(), localField: "a", foreignField: "a", as: "a1"}},
    {$unwind: "$a1"},
    {$lookup: {from: coll.getName(), localField: "a1.a", foreignField: "a", as: "a2"}},
    {$unwind: "$a2"},
    {$lookup: {from: coll.getName(), localField: "a2.a", foreignField: "a", as: "a3"}},
    {$unwind: "$a3"},
];

joinTestWrapper(() => {
    assert.commandWorked(db.adminCommand({setParameter: 1, internalEnableJoinOptimization: false}));
    const baseRes = coll.aggregate(pipeline).toArray();

    section("Test getting rejected plan out of explain");
    const [actual, explain] = getJoinTestResultsAndExplain("Bottom-up, zig-zag, 4-node join", coll, pipeline, {
        setParameter: 1,
        internalEnableJoinOptimization: true,
        internalJoinReorderMode: "bottomUp",
        internalJoinPlanTreeShape: "zigZag",
    });

    assertArrayEq({expected: baseRes, actual});
    verifyExplainOutput(explain, true /* joinOptExpectedInExplainOutput */);
    subSection("Winning plan");
    prettyPrintWinningPlan(explain);
    subSection("Rejected plans");
    prettyPrintRejectedPlans(explain);
});
