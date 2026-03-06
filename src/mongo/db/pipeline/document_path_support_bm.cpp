/**
 *    Copyright (C) 2026-present MongoDB, Inc.
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

#include "mongo/db/pipeline/document_path_support.h"

#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/exec/document_value/document.h"
#include "mongo/db/pipeline/field_path.h"
#include "mongo/db/query/compiler/dependency_analysis/dependencies.h"

#include <benchmark/benchmark.h>

namespace mongo {
namespace {

struct TestData {
    Document doc;
    OrderedPathSet paths;
};

TestData buildTestData(int numPrefixes) {
    BSONObjBuilder bob;
    OrderedPathSet paths;
    for (int i = 0; i < numPrefixes; ++i) {
        std::string prefix = "field_" + std::to_string(i);
        bob.append(prefix, BSON("x" << i));
        if (i == 0) {
            paths.insert(prefix + ".x");
        }
        paths.insert(prefix);
    }
    return {Document{bob.obj()}, std::move(paths)};
}

void BM_DocumentToBsonWithPaths(benchmark::State& state) {
    auto [doc, paths] = buildTestData(state.range(0));
    for (auto _ : state) {
        benchmark::DoNotOptimize(
            document_path_support::documentToBsonWithPaths<BSONObj::LargeSizeTrait, false>(doc,
                                                                                           paths));
    }
}

BENCHMARK(BM_DocumentToBsonWithPaths)->Arg(3)->Arg(10)->Arg(50)->Arg(100)->Arg(200)->Arg(500);

}  // namespace
}  // namespace mongo
