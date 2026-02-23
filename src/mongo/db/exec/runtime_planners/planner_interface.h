/**
 *    Copyright (C) 2024-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

#pragma once

#include "mongo/db/exec/runtime_planners/planner_types.h"
#include "mongo/db/query/canonical_query.h"
#include "mongo/db/query/plan_executor.h"
#include "mongo/util/modules.h"

namespace mongo {

/*
 *  Common interface for planner implementations.
 */
class PlannerInterface {
public:
    virtual ~PlannerInterface() = default;

    /**
     * Function that creates a PlanExecutor for the selected plan. Can be called only once, as it
     * may transfer ownership of some data to returned PlanExecutor.
     * TODO SERVER-119971 remove this function and its different implementations.
     */
    virtual std::unique_ptr<PlanExecutor, PlanExecutor::Deleter> makeExecutor(
        std::unique_ptr<CanonicalQuery> canonicalQuery) {
        MONGO_UNREACHABLE_TASSERT(11974307);
    }

    /**
     * Extracts a `PlanRankingResult` which summarizes all information from the planning phase.
     * Only called when `featureFlagGetExecutorDeferredEngineChoice` is enabled.
     * TODO SERVER-119036 when the legacy get_executor is deleted, this function can be pure
     * virtual.
     */
    virtual PlanRankingResult extractPlanRankingResult() {
        MONGO_UNREACHABLE_TASSERT(11974308);
    }
};
}  // namespace mongo
