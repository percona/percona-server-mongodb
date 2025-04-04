import {
    getAggPlanStages,
    getPlanStages,
    getQueryPlanners,
    getWinningPlan
} from "jstests/libs/analyze_plan.js";
import {checkSbeFullyEnabled, checkSbeRestrictedOrFullyEnabled} from "jstests/libs/sbe_util.js";

/**
 * Class containing common test functions used in query_settings_index_application_* tests.
 */
export class QuerySettingsIndexHintsTests {
    /**
     * Create a query settings utility class.
     */
    constructor(qsutils) {
        this.qsutils = qsutils;
        this.indexA = {a: 1};
        this.indexB = {b: 1};
        this.indexAB = {a: 1, b: 1};
    }

    /**
     * Asserts that after executing 'command' the most recent query plan from cache would have
     * 'querySettings' set.
     */
    assertQuerySettingsInCacheForCommand(command,
                                         querySettings,
                                         collOrViewName = this.qsutils.collName) {
        // Single solution plans are not cached in classic, therefore do not perform plan cache
        // checks for classic.
        const db = this.qsutils.db;
        if (!checkSbeFullyEnabled(db)) {
            return;
        }

        // Checking plan cache for query settings doesn't work reliably if collections are moved
        // between shards randomly because that causes plan cache invalidation.
        if (TestData.runningWithBalancer) {
            return;
        }

        // If the collection used is a view, determine the underlying collection being used.
        const collInfo = db.getCollectionInfos({name: collOrViewName})[0];
        const collName = collInfo.options.viewOn || collOrViewName;

        // Clear the plan cache before running any queries.
        db[collName].getPlanCache().clear();

        // Take the newest plan cache entry (based on 'timeOfCreation' sorting) and ensure that it
        // contains the 'settings'.
        assert.commandWorked(db.runCommand(command));
        const planCacheStatsAfterRunningCmd = db[collName].getPlanCache().list();
        assert.gte(planCacheStatsAfterRunningCmd.length,
                   1,
                   "Expecting at least 1 entry in query plan cache");
        planCacheStatsAfterRunningCmd.forEach(
            plan => assert.docEq(querySettings, plan.querySettings, plan));
    }

    assertIndexUse(cmd, expectedIndex, stagesExtractor, expectedStrategy) {
        const explain = assert.commandWorked(db.runCommand({explain: cmd}));
        const stagesUsingIndex = stagesExtractor(explain);
        if (expectedIndex !== undefined) {
            assert.gte(stagesUsingIndex.length, 1, explain);
        }
        for (const stage of stagesUsingIndex) {
            if (expectedIndex !== undefined) {
                assert.docEq(stage.keyPattern, expectedIndex, explain);
            }

            if (expectedStrategy !== undefined) {
                assert.docEq(stage.strategy, expectedStrategy, explain);
            }
        }
    }

    assertIndexScanStage(cmd, expectedIndex) {
        return this.assertIndexUse(cmd, expectedIndex, (explain) => {
            return getQueryPlanners(explain)
                .map(getWinningPlan)
                .flatMap(winningPlan => getPlanStages(winningPlan, "IXSCAN"));
        });
    }

    assertLookupJoinStage(cmd, expectedIndex, isSecondaryCollAView, expectedStrategy) {
        // $lookup stage is only pushed down to find in SBE and not in classic and only for
        // collections (not views).
        const db = this.qsutils.db;
        const expectPushDown = checkSbeRestrictedOrFullyEnabled(db) && !isSecondaryCollAView;
        if (!expectPushDown && expectedIndex != undefined) {
            return this.assertLookupPipelineStage(cmd, expectedIndex);
        }

        this.assertIndexUse(cmd, expectedIndex, (explain) => {
            return getQueryPlanners(explain)
                .map(getWinningPlan)
                .flatMap(winningPlan => getPlanStages(winningPlan, "EQ_LOOKUP"))
                .map(stage => {
                    stage.keyPattern = stage.indexKeyPattern;
                    return stage;
                });
        }, expectedStrategy);
    }

    assertLookupPipelineStage(cmd, expectedIndex) {
        const indexToKeyPatternMap = {"a_1": {a: 1}, "b_1": {b: 1}, "a_1_b_1": {a: 1, b: 1}};
        return this.assertIndexUse(cmd, expectedIndex, (explain) => {
            return getAggPlanStages(explain, "$lookup").map(stage => {
                let {indexesUsed, ...stageData} = stage;
                assert.eq(indexesUsed.length, 1, stage);
                stageData.keyPattern = indexToKeyPatternMap[indexesUsed[0]];
                return stageData;
            });
        });
    }

    assertDistinctScanStage(cmd, expectedIndex) {
        return this.assertIndexUse(cmd, expectedIndex, (explain) => {
            return getQueryPlanners(explain)
                .map(getWinningPlan)
                .flatMap(winningPlan => getPlanStages(winningPlan, "DISTINCT_SCAN"));
        });
    }

    assertCollScanStage(cmd, allowedDirections) {
        const explain = assert.commandWorked(this.qsutils.db.runCommand({explain: cmd}));
        const collscanStages = getQueryPlanners(explain)
                                   .map(getWinningPlan)
                                   .flatMap(winningPlan => getPlanStages(winningPlan, "COLLSCAN"));
        assert.gte(collscanStages.length, 1, explain);
        for (const collscanStage of collscanStages) {
            assert(allowedDirections.includes(collscanStage.direction), explain);
        }
    }

    /**
     * Ensure query settings are applied as expected in a straightforward scenario.
     */
    assertQuerySettingsIndexApplication(querySettingsQuery, ns) {
        const query = this.qsutils.withoutDollarDB(querySettingsQuery);
        for (const index of [this.indexA, this.indexB, this.indexAB]) {
            const settings = {indexHints: {ns, allowedIndexes: [index]}};
            this.qsutils.withQuerySettings(querySettingsQuery, settings, () => {
                this.assertIndexScanStage(query, index);
                this.assertQuerySettingsInCacheForCommand(query, settings);
            });
        }
    }

    /**
     * Ensure query plan cache contains query settings for the namespace 'ns'.
     */
    assertGraphLookupQuerySettingsInCache(querySettingsQuery, ns) {
        const query = this.qsutils.withoutDollarDB(querySettingsQuery);
        for (const allowedIndexes of [[this.indexA, this.indexB],
                                      [this.indexA, this.indexAB],
                                      [this.indexAB, this.indexB]]) {
            const settings = {indexHints: {ns, allowedIndexes}};
            this.qsutils.withQuerySettings(querySettingsQuery, settings, () => {
                this.assertQuerySettingsInCacheForCommand(query, settings, ns.coll);
            });
        }
    }

    /**
     * Ensure query settings are applied in a situation of the equi-join over namespace 'ns'.
     */
    assertQuerySettingsLookupJoinIndexApplication(querySettingsQuery, ns, isSecondaryCollAView) {
        const query = this.qsutils.withoutDollarDB(querySettingsQuery);
        for (const index of [this.indexA, this.indexAB]) {
            const settings = {indexHints: {ns, allowedIndexes: [index]}};
            this.qsutils.withQuerySettings(querySettingsQuery, settings, () => {
                this.assertLookupJoinStage(query, index, isSecondaryCollAView);
                this.assertQuerySettingsInCacheForCommand(query, settings);
            });
        }
    }

    /**
     * Ensure query settings are applied in a situation of $lookup equi-join for both collections.
     */
    assertQuerySettingsIndexAndLookupJoinApplications(querySettingsQuery,
                                                      mainNs,
                                                      secondaryNs,
                                                      isSecondaryCollAView) {
        const query = this.qsutils.withoutDollarDB(querySettingsQuery);
        for (const [mainCollIndex, secondaryCollIndex] of selfCrossProduct(
                 [this.indexA, this.indexAB])) {
            const settings = {
                indexHints: [
                    {ns: mainNs, allowedIndexes: [mainCollIndex]},
                    {ns: secondaryNs, allowedIndexes: [secondaryCollIndex]},
                ]
            };

            this.qsutils.withQuerySettings(querySettingsQuery, settings, () => {
                this.assertIndexScanStage(query, mainCollIndex);
                this.assertLookupJoinStage(query, secondaryCollIndex, isSecondaryCollAView);
                this.assertQuerySettingsInCacheForCommand(query, settings);
            });
        }
    }

    /**
     * Ensure query settings are applied in a situation of $lookup sub-pipeline.
     */
    assertQuerySettingsLookupPipelineIndexApplication(querySettingsQuery, ns) {
        const query = this.qsutils.withoutDollarDB(querySettingsQuery);
        for (const index of [this.indexA, this.indexB, this.indexAB]) {
            const settings = {indexHints: {ns, allowedIndexes: [index]}};
            this.qsutils.withQuerySettings(querySettingsQuery, settings, () => {
                this.assertLookupPipelineStage(query, index);
                this.assertQuerySettingsInCacheForCommand(query, settings);
            });
        }
    }

    /**
     * Ensure query settings are applied in a situation of $lookup sub-pipeline for both
     * collections.
     */
    assertQuerySettingsIndexAndLookupPipelineApplications(querySettingsQuery, mainNs, secondaryNs) {
        const query = this.qsutils.withoutDollarDB(querySettingsQuery);
        for (const [mainCollIndex, secondaryCollIndex] of selfCrossProduct(
                 [this.indexA, this.indexB, this.indexAB])) {
            const settings = {
                indexHints: [
                    {ns: mainNs, allowedIndexes: [mainCollIndex]},
                    {ns: secondaryNs, allowedIndexes: [secondaryCollIndex]},
                ]
            };

            this.qsutils.withQuerySettings(querySettingsQuery, settings, () => {
                this.assertIndexScanStage(query, mainCollIndex);
                this.assertLookupPipelineStage(query, secondaryCollIndex);
                this.assertQuerySettingsInCacheForCommand(query, settings);
            });
        }
    }

    /**
     * Ensure query settings '$natural' hints are applied as expected in a straightforward scenario.
     * This test case covers the following scenarios:
     * - Only forward scans allowed.
     * - Only backward scans allowed.
     * - Both forward and backward scans allowed.
     */
    assertQuerySettingsNaturalApplication(querySettingsQuery, ns, additionalHints = []) {
        const query = this.qsutils.withoutDollarDB(querySettingsQuery);
        const naturalForwardScan = {$natural: 1};
        const naturalForwardSettings = {
            indexHints: [{ns, allowedIndexes: [naturalForwardScan]}, ...additionalHints]
        };
        this.qsutils.withQuerySettings(querySettingsQuery, naturalForwardSettings, () => {
            this.assertCollScanStage(query, ["forward"]);
            this.assertQuerySettingsInCacheForCommand(query, naturalForwardSettings);
        });

        const naturalBackwardScan = {$natural: -1};
        const naturalBackwardSettings = {
            indexHints: [{ns, allowedIndexes: [naturalBackwardScan]}, ...additionalHints]
        };
        this.qsutils.withQuerySettings(querySettingsQuery, naturalBackwardSettings, () => {
            this.assertCollScanStage(query, ["backward"]);
            this.assertQuerySettingsInCacheForCommand(query, naturalBackwardSettings);
        });

        const naturalAnyDirectionSettings = {
            indexHints: [
                {ns, allowedIndexes: [naturalForwardScan, naturalBackwardScan]},
                ...additionalHints
            ]
        };
        this.qsutils.withQuerySettings(querySettingsQuery, naturalAnyDirectionSettings, () => {
            this.assertCollScanStage(query, ["forward", "backward"]);
            this.assertQuerySettingsInCacheForCommand(query, naturalAnyDirectionSettings);
        });
    }

    /**
     * Ensure that the hint gets ignored when query settings for the particular query are set.
     */
    assertQuerySettingsIgnoreCursorHints(querySettingsQuery, ns) {
        const query = this.qsutils.withoutDollarDB(querySettingsQuery);
        const queryWithHint = {...query, hint: this.indexA};
        const settings = {indexHints: {ns, allowedIndexes: [this.indexAB]}};
        const getWinningPlansForQuery = (query) => {
            const explain = assert.commandWorked(db.runCommand({explain: query}));
            return getQueryPlanners(explain).map(getWinningPlan);
        };

        this.qsutils.withQuerySettings(querySettingsQuery, settings, () => {
            const winningPlanWithoutCursorHint = getWinningPlansForQuery(query);
            const winningPlanWithCursorHint = getWinningPlansForQuery(queryWithHint);
            assert.eq(winningPlanWithCursorHint, winningPlanWithoutCursorHint);
        });
    }

    /**
     * Ensure that cursor hints and query settings can be applied together, if on independent
     * pipelines.
     */
    assertQuerySettingsWithCursorHints(querySettingsQuery, mainNs, secondaryNs) {
        const query = this.qsutils.withoutDollarDB(querySettingsQuery);
        const queryWithHint = {...query, hint: this.indexA};
        const settingsOnSecondary = {indexHints: {ns: secondaryNs, allowedIndexes: [this.indexAB]}};
        const settingsOnBoth = {
            indexHints: [
                {ns: mainNs, allowedIndexes: [this.indexA]},
                {ns: secondaryNs, allowedIndexes: [this.indexAB]},
            ]
        };
        const getWinningPlansForQuery = (query, settings) => {
            let winningPlans = null;
            this.qsutils.withQuerySettings(
                {...query, $db: querySettingsQuery.$db}, settings, () => {
                    const explain = assert.commandWorked(db.runCommand({explain: query}));
                    winningPlans = getQueryPlanners(explain).map(getWinningPlan);
                });
            return winningPlans;
        };

        assert.eq(getWinningPlansForQuery(query, settingsOnBoth),
                  getWinningPlansForQuery(queryWithHint, settingsOnSecondary));
    }

    /**
     * Ensure that queries that fallback to multiplanning when the provided settings don't generate
     * any viable plans have the same winning plan as the queries that have no query settings
     * attached to them.
     */
    assertQuerySettingsFallback(querySettingsQuery, ns) {
        const query = this.qsutils.withoutDollarDB(querySettingsQuery);
        const settings = {indexHints: {ns, allowedIndexes: ["doesnotexist"]}};
        const explainWithoutQuerySettings = assert.commandWorked(db.runCommand({explain: query}));

        this.qsutils.withQuerySettings(querySettingsQuery, settings, () => {
            const explainWithQuerySettings = assert.commandWorked(db.runCommand({explain: query}));
            const winningPlansWithQuerySettings =
                getQueryPlanners(explainWithQuerySettings).map(getWinningPlan);
            const winningPlansWithoutQuerySettings =
                getQueryPlanners(explainWithoutQuerySettings).map(getWinningPlan);
            assert.eq(winningPlansWithQuerySettings, winningPlansWithoutQuerySettings);
            this.assertQuerySettingsInCacheForCommand(query, settings);
        });
    }

    /**
     * Ensure that users can not pass query settings to the commands explicitly.
     */
    assertQuerySettingsCommandValidation(querySettingsQuery, ns) {
        const query = this.qsutils.withoutDollarDB(querySettingsQuery);
        const settings = {indexHints: {ns, allowedIndexes: [this.indexAB]}};
        const expectedErrorCodes = [7746900, 7746901, 7923000, 7923001, 7708000, 7708001];
        assert.commandFailedWithCode(
            this.qsutils.db.runCommand({...query, querySettings: settings}), expectedErrorCodes);
    }

    testAggregateQuerySettingsNaturalHintEquiJoinStrategy(query, mainNs, secondaryNs) {
        // Confirm that, by default, the query can be satisfied with an IndexedLoopJoin when joining
        // against the collection.
        const queryNoDb = this.qsutils.withoutDollarDB(query);
        this.assertLookupJoinStage(queryNoDb, undefined, false, "IndexedLoopJoin");

        // Set query settings, hinting $natural for the secondary collection.
        this.qsutils.withQuerySettings(
            query, {indexHints: [{ns: secondaryNs, allowedIndexes: [{"$natural": 1}]}]}, () => {
                // Confirm the strategy has changed - the query is no longer
                // permitted to use the index on the secondary collection.
                this.assertLookupJoinStage(queryNoDb, undefined, false, "HashJoin");
            });

        // Set query settings, but hinting $natural on the "main" collection. Strategy
        this.qsutils.withQuerySettings(
            query, {indexHints: [{ns: mainNs, allowedIndexes: [{"$natural": 1}]}]}, () => {
                // Observe that strategy is unaffected in this case; the top level query was
                // already a coll scan, and the query is allowed to use the index on the
                // secondary collection.
                this.assertLookupJoinStage(queryNoDb, undefined, false, "IndexedLoopJoin");
            });
    }

    testAggregateQuerySettingsNaturalHintDirectionWhenSecondaryHinted(query, mainNs, secondaryNs) {
        // Verify main collection scan direction is not affected by hint for secondary collection.
        for (const hint
                 of [[{"$natural": 1}], [{"$natural": -1}], [{"$natural": 1}, {"$natural": -1}]]) {
            this.assertQuerySettingsNaturalApplication(
                query, mainNs, [{ns: secondaryNs, allowedIndexes: hint}]);
        }
    }
}

function* crossProductGenerator(...lists) {
    const [head, ...tail] = lists;
    if (tail.length == 0) {
        yield* head;
        return;
    }

    for (const element of head) {
        for (const rest of crossProductGenerator(...tail)) {
            yield [element].concat(rest);
        }
    }
}

function crossProduct(...lists) {
    return [...crossProductGenerator(...lists)];
}

function selfCrossProduct(list) {
    return crossProduct(list, list);
}