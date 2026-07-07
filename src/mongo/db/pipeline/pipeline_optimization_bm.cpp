/**
 *    Copyright (C) 2025-present MongoDB, Inc.
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

#include "mongo/bson/bsonobj.h"
#include "mongo/db/pipeline/pipeline_factory.h"
#include "mongo/db/pipeline/pipeline_optimization_bm_fixture.h"

#include <vector>

#include <benchmark/benchmark.h>

namespace mongo {
namespace {

BENCHMARK_DEFINE_F(PipelineOptimizationBMFixture, BM_OptimizePipeline)
(benchmark::State& state) {
    auto rawPipeline = generateRawPipeline(state.range(0));
    benchmarkOptimizePipeline(state, rawPipeline, expCtx);
}
BENCHMARK_REGISTER_F(PipelineOptimizationBMFixture, BM_OptimizePipeline)
    ->Arg(10)
    ->Arg(50)
    ->Arg(100)
    ->Arg(1000)
    ->Unit(benchmark::kMicrosecond);

// Report pipeline parsing time.
BENCHMARK_DEFINE_F(PipelineOptimizationBMFixture, BM_ParsePipeline)
(benchmark::State& state) {
    auto rawPipeline = generateRawPipeline(state.range(0));
    for (auto keepRunning : state) {
        benchmark::DoNotOptimize(
            pipeline_factory::makePipeline(rawPipeline, expCtx, pipeline_factory::kOptionsMinimal));
    }
}
BENCHMARK_REGISTER_F(PipelineOptimizationBMFixture, BM_ParsePipeline)
    ->Arg(10)
    ->Arg(50)
    ->Arg(100)
    ->Arg(1000)
    ->Unit(benchmark::kMicrosecond);

}  // namespace
}  // namespace mongo
