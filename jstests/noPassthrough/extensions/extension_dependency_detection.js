/**
 * Tests apply_pipeline_suffix_dependencies for extension source stages, verifies that
 * applyPipelineSuffixDependencies is not invoked on transform stages, and exercises mixed
 * pipelines where both server and extension stages participate in dependency analysis.
 *
 * $trackDepsSource is a source stage that accepts {meta: <name>, var: <name>} and records whether that
 * metadata field / variable is needed by its downstream pipeline, and whether the full document is
 * needed. It emits {_id: 0, neededMeta: <bool>, neededVar: <bool>, neededWholeDoc: <bool>}.
 *
 * $trackDepsTransform is a transform stage that overrides applyPipelineSuffixDependencies and
 * records whether it was invoked. Whether the callback was called is observable via the stage's
 * serialized/explain output: {depsCallbackCalled: <bool>}.
 *
 * $readNDocuments desugars to $produceIds + $_internalSearchIdLookup. $produceIds overrides
 * applyPipelineSuffixDependencies to conditionally produce $score metadata based on whether the
 * suffix references it, and declares providedMetadataFields: ["score"] in its static properties.
 *
 * $addFieldsMatch desugars into server-side $addFields + $match stages at parse time.
 *
 * @tags: [
 *   featureFlagExtensionsAPI,
 *   featureFlagExtensionsOptimizations,
 * ]
 */
import {getStageFromSplitPipeline} from "jstests/libs/query/analyze_plan.js";
import {checkPlatformCompatibleWithExtensions, withExtensions} from "jstests/noPassthrough/libs/extension_helpers.js";

checkPlatformCompatibleWithExtensions();

function assertDeps(coll, metaName, varName, downstream, expectedMeta, expectedVar, expectedWholeDoc) {
    const pipeline = [{$trackDepsSource: {meta: metaName, var: varName}}, ...downstream];
    const results = coll.aggregate(pipeline).toArray();
    assert.gte(results.length, 1, `Expected at least one result for pipeline: ${tojson(pipeline)}`);
    // On a sharded cluster each shard emits one document. The dependency
    // analysis result is identical across shards, so verify they all agree.
    for (let i = 1; i < results.length; i++) {
        assert.eq(
            results[i].neededMeta,
            results[0].neededMeta,
            `Shard results disagree on neededMeta for pipeline: ${tojson(pipeline)}`,
        );
        assert.eq(
            results[i].neededVar,
            results[0].neededVar,
            `Shard results disagree on neededVar for pipeline: ${tojson(pipeline)}`,
        );
        assert.eq(
            results[i].neededWholeDoc,
            results[0].neededWholeDoc,
            `Shard results disagree on neededWholeDoc for pipeline: ${tojson(pipeline)}`,
        );
    }
    const {neededMeta, neededVar, neededWholeDoc} = results[0];
    assert.eq(neededMeta, expectedMeta, `neededMeta for pipeline: ${tojson(pipeline)}`);
    assert.eq(neededVar, expectedVar, `neededVar for pipeline: ${tojson(pipeline)}`);
    assert.eq(neededWholeDoc, expectedWholeDoc, `neededWholeDoc for pipeline: ${tojson(pipeline)}`);
}

function runSourceTests(coll) {
    // Metadata not referenced downstream, with or without additional stages.
    assertDeps(
        coll,
        "searchSequenceToken",
        "NOW",
        [],
        false /*expectedMeta*/,
        false /*expectedVar*/,
        false /*expectedWholeDoc*/,
    );
    assertDeps(
        coll,
        "searchScore",
        "NOW",
        [{$limit: 10}, {$project: {neededMeta: 1, neededVar: 1, neededWholeDoc: 1}}],
        false /*expectedMeta*/,
        false /*expectedVar*/,
        false /*expectedWholeDoc*/,
    );

    // Metadata referenced downstream.
    assertDeps(
        coll,
        "searchSequenceToken",
        "NOW",
        [{$project: {token: {$meta: "searchSequenceToken"}, neededMeta: 1, neededVar: 1, neededWholeDoc: 1}}],
        true /*expectedMeta*/,
        false /*expectedVar*/,
        false /*expectedWholeDoc*/,
    );
    assertDeps(
        coll,
        "searchSequenceToken",
        "NOW",
        [
            {$limit: 100},
            {$project: {token: {$meta: "searchSequenceToken"}, neededMeta: 1, neededVar: 1, neededWholeDoc: 1}},
        ],
        true /*expectedMeta*/,
        false /*expectedVar*/,
        false /*expectedWholeDoc*/,
    );

    // Variable referenced downstream.
    assertDeps(
        coll,
        "searchSequenceToken",
        "NOW",
        [{$addFields: {timestamp: "$$NOW"}}],
        false /*expectedMeta*/,
        true /*expectedVar*/,
        true /*expectedWholeDoc*/,
    );
    assertDeps(
        coll,
        "searchSequenceToken",
        "NOW",
        [{$limit: 100}, {$addFields: {timestamp: "$$NOW"}}],
        false /*expectedMeta*/,
        true /*expectedVar*/,
        true /*expectedWholeDoc*/,
    );

    // Variable referenced downstream — USER_ROLES.
    assertDeps(
        coll,
        "searchScore",
        "USER_ROLES",
        [{$addFields: {ct: "$$USER_ROLES"}}],
        false /*expectedMeta*/,
        true /*expectedVar*/,
        true /*expectedWholeDoc*/,
    );

    // Both metadata and variable referenced downstream.
    assertDeps(
        coll,
        "searchSequenceToken",
        "NOW",
        [{$addFields: {token: {$meta: "searchSequenceToken"}, timestamp: "$$NOW"}}],
        true /*expectedMeta*/,
        true /*expectedVar*/,
        true /*expectedWholeDoc*/,
    );

    // $addFields implies needsWholeDocument.
    assertDeps(
        coll,
        "searchSequenceToken",
        "NOW",
        [{$addFields: {score: {$meta: "searchSequenceToken"}}}],
        true /*expectedMeta*/,
        false /*expectedVar*/,
        true /*expectedWholeDoc*/,
    );

    // needsWholeDocument: inclusive projection does not need the whole document.
    assertDeps(
        coll,
        "searchSequenceToken",
        "NOW",
        [{$project: {neededMeta: 1, neededVar: 1, neededWholeDoc: 1}}],
        false /*expectedMeta*/,
        false /*expectedVar*/,
        false /*expectedWholeDoc*/,
    );

    // Variable not referenced downstream — should not be needed.
    assertDeps(
        coll,
        "searchScore",
        "USER_ROLES",
        [{$addFields: {timestamp: "$$NOW"}}],
        false /*expectedMeta*/,
        false /*expectedVar*/,
        true /*expectedWholeDoc*/,
    );
}

/**
 * Verify via explain that applyPipelineSuffixDependencies was not invoked on $trackDepsTransform.
 */
function assertTransformDepsNotCalled(coll, pipeline) {
    const explain = coll.explain().aggregate(pipeline);
    const stageObj = getStageFromSplitPipeline(explain, "$trackDepsTransform");
    assert.neq(stageObj, null, `$trackDepsTransform not found in explain output: ${tojson(explain)}`);
    assert.eq(
        stageObj["$trackDepsTransform"].depsCallbackCalled,
        false,
        `applyPipelineSuffixDependencies should not be invoked on transform stages. Explain: ${tojson(explain)}`,
    );
}

function runTransformNegativeTests(coll) {
    // Transform stage alone — callback should not be invoked.
    assertTransformDepsNotCalled(coll, [{$trackDepsTransform: {}}]);

    // Callback should not fire even when downstream stages reference metadata and variables.
    assertTransformDepsNotCalled(coll, [
        {$trackDepsTransform: {}},
        {$addFields: {token: {$meta: "searchSequenceToken"}, timestamp: "$$NOW"}},
    ]);

    // Mixed suffix with both extension transform and server stages. The source stage's suffix
    // deps should reflect the full suffix. The transform should not be invoked.
    {
        const pipeline = [
            {$trackDepsSource: {meta: "searchSequenceToken", var: "NOW"}},
            {$trackDepsTransform: {}},
            {
                $project: {
                    token: {$meta: "searchSequenceToken"},
                    neededMeta: 1,
                    neededVar: 1,
                    neededWholeDoc: 1,
                },
            },
        ];
        assertTransformDepsNotCalled(coll, pipeline);

        const results = coll.aggregate(pipeline).toArray();
        assert.gte(results.length, 1, `Expected at least one result: ${tojson(results)}`);
        assert.eq(
            results[0].neededMeta,
            true,
            `Source stage should detect metadata needed through mixed suffix: ${tojson(results[0])}`,
        );
        assert.eq(results[0].neededVar, false, `No variable reference in mixed suffix: ${tojson(results[0])}`);
        // $trackDepsTransform is in the suffix and all extension stages unconditionally
        // declare needWholeDocument=true in getDependencies.
        assert.eq(
            results[0].neededWholeDoc,
            true,
            `Extension transform in suffix should cause needWholeDocument: ${tojson(results[0])}`,
        );
    }
}

/**
 * Tests where both host and extension stages participate in dependency analysis in the same
 * pipeline.
 */
function runMixedPipelineTests(coll) {
    // Extension source ($readNDocuments/$produceIds) conditionally produces score metadata based
    // on dep analysis. Verify that when the suffix references {$meta: "score"}, the metadata is
    // produced and flows through host stages correctly.
    {
        const results = coll
            .aggregate([{$readNDocuments: {numDocs: 1}}, {$project: {_id: 1, score: {$meta: "score"}}}])
            .toArray();
        assert.eq(results.length, 1, `Expected 1 result, got: ${tojson(results)}`);
        assert.eq(
            results[0].score,
            results[0]._id * 5,
            `Expected score = _id * 5 from $produceIds dep analysis: ${tojson(results[0])}`,
        );
    }

    // Score metadata flows through $limit.
    {
        const results = coll
            .aggregate([{$readNDocuments: {numDocs: 1}}, {$limit: 10}, {$addFields: {myScore: {$meta: "score"}}}])
            .toArray();
        assert.eq(results.length, 1, `Expected 1 result, got: ${tojson(results)}`);
        assert.eq(
            results[0].myScore,
            results[0]._id * 5,
            `Score metadata should flow through $limit: ${tojson(results[0])}`,
        );
    }

    // When metadata is not referenced, $produceIds should not produce it.
    {
        const results = coll.aggregate([{$readNDocuments: {numDocs: 1}}, {$project: {_id: 1, val: 1}}]).toArray();
        assert.eq(results.length, 1, `Expected 1 result, got: ${tojson(results)}`);
        assert(
            !results[0].hasOwnProperty("score"),
            `Score should not appear when suffix doesn't reference it: ${tojson(results[0])}`,
        );
    }

    // Extension source ($trackDepsSource) with a suffix that includes a desugared extension stage
    // ($addFieldsMatch). The desugared host stages should participate in dep analysis: $addFields
    // implies needsWholeDocument.
    assertDeps(
        coll,
        "searchSequenceToken",
        "NOW",
        [{$addFieldsMatch: {field: "extra", value: 1, filter: {$gt: ["$extra", 0]}}}],
        false /*expectedMeta*/,
        false /*expectedVar*/,
        true /*expectedWholeDoc*/,
    );

    // Extension source + desugared extension stage + host stage referencing metadata. The
    // $addFieldsMatch desugars into host stages, and a downstream $project references metadata. The
    // inclusive $project limits field deps (needsWholeDoc: false) but the metadata reference is
    // still detected.
    assertDeps(
        coll,
        "searchSequenceToken",
        "NOW",
        [
            {$addFieldsMatch: {field: "extra", value: 1, filter: {$gt: ["$extra", 0]}}},
            {$project: {token: {$meta: "searchSequenceToken"}, neededMeta: 1, neededVar: 1, neededWholeDoc: 1}},
        ],
        true /*expectedMeta*/,
        false /*expectedVar*/,
        false /*expectedWholeDoc*/,
    );

    // Extension source + extension transform + desugared extension suffix. Combines all of
    // extension source, extension transform (passthrough), and desugared extension stage expanding
    // to host stages.
    {
        const pipeline = [
            {$trackDepsSource: {meta: "searchSequenceToken", var: "NOW"}},
            {$trackDepsTransform: {}},
            {$addFieldsMatch: {field: "extra", value: 1, filter: {$gt: ["$extra", 0]}}},
            {$project: {token: {$meta: "searchSequenceToken"}, neededMeta: 1, neededVar: 1, neededWholeDoc: 1}},
        ];
        assertTransformDepsNotCalled(coll, pipeline);

        const results = coll.aggregate(pipeline).toArray();
        assert.gte(results.length, 1, `Expected at least one result: ${tojson(results)}`);
        assert.eq(
            results[0].neededMeta,
            true,
            `Source should detect metadata through transform + desugared stages: ${tojson(results[0])}`,
        );
        // $trackDepsTransform (extension stage) unconditionally declares needWholeDocument=true
        // in getDependencies, overriding the inclusive $project at the end.
        assert.eq(
            results[0].neededWholeDoc,
            true,
            `Extension transform in suffix should cause needWholeDocument: ${tojson(results[0])}`,
        );
    }

    // Extension source + extension transform + variable reference through desugared stages.
    assertDeps(
        coll,
        "searchSequenceToken",
        "NOW",
        [{$trackDepsTransform: {}}, {$addFieldsMatch: {field: "ts", value: "$$NOW", filter: {$gt: ["$ts", 0]}}}],
        false /*expectedMeta*/,
        true /*expectedVar*/,
        true /*expectedWholeDoc*/,
    );
}

function runTests(conn, shardingTest) {
    const db = conn.getDB("test");
    const coll = db[jsTestName()];

    // Insert documents so the collection exists and $readNDocuments can find them.
    assert.commandWorked(coll.insertMany(Array.from({length: 10}, (_, i) => ({_id: i, val: i * 10}))));

    // Non-existent metadata type returns an error.
    assert.throwsWithCode(() => coll.aggregate([{$trackDepsSource: {meta: "UNKNOWN_META"}}]).toArray(), 17308);

    // Run on unsharded collection. On mongos this exercises the fromRouter path where the full
    // pipeline is forwarded to a single shard without splitting.
    runSourceTests(coll);
    runTransformNegativeTests(coll);
    runMixedPipelineTests(coll);

    if (shardingTest) {
        assert.commandWorked(db.adminCommand({shardCollection: coll.getFullName(), key: {_id: 1}}));
        assert.commandWorked(db.adminCommand({split: coll.getFullName(), middle: {_id: 5}}));
        assert.commandWorked(
            db.adminCommand({
                moveChunk: coll.getFullName(),
                find: {_id: 5},
                to: shardingTest.shard1.shardName,
            }),
        );

        // Verify the pipeline actually splits via explain.
        {
            const pipeline = [
                {$trackDepsSource: {meta: "searchSequenceToken", var: "NOW"}},
                {$project: {token: {$meta: "searchSequenceToken"}, neededMeta: 1, neededVar: 1, neededWholeDoc: 1}},
            ];
            const explain = coll.explain().aggregate(pipeline);
            assert(
                explain.hasOwnProperty("splitPipeline"),
                "Expected splitPipeline in explain output: " + tojson(explain),
            );
        }

        // Re-run on the now-sharded collection, where the pipeline splits across shards.
        runSourceTests(coll);
        runTransformNegativeTests(coll);
        runMixedPipelineTests(coll);
    }
}

withExtensions(
    {
        "libtrack_deps_mongo_extension.so": {},
        "libread_n_documents_mongo_extension.so": {},
        "libadd_fields_match_mongo_extension.so": {},
    },
    runTests,
    ["standalone", "sharded"],
    {shards: 2},
);
