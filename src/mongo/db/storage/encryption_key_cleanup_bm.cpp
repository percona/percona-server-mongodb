/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2018-present Percona and/or its affiliates. All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the Server Side Public License, version 1,
    as published by MongoDB, Inc.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Server Side Public License for more details.

    You should have received a copy of the Server Side Public License
    along with this program. If not, see
    <http://www.mongodb.com/licensing/server-side-public-license>.

    As a special exception, the copyright holders give permission to link the
    code of portions of this program with the OpenSSL library under certain
    conditions as described in each individual source file and distribute
    linked combinations including the program with the OpenSSL library. You
    must comply with the Server Side Public License in all respects for
    all of the code used other than as permitted herein. If you modify file(s)
    with this exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do so,
    delete this exception statement from your version. If you delete this
    exception statement from all source files in the program, then also delete
    it in the license file.
======= */

/**
 * Benchmark for the orphaned encryption key cleanup algorithm.
 *
 * Tests the core set-difference algorithm used by
 * StorageEngineImpl::cleanupOrphanedEncryptionKeys() to find orphaned keys.
 * The algorithm collects three sorted vectors and performs two set_difference
 * passes in O(K + I + D) time. This benchmark verifies that performance
 * scales linearly with input size.
 */

#include <algorithm>
#include <cstdio>
#include <numeric>
#include <random>
#include <string>
#include <vector>

#include <benchmark/benchmark.h>

namespace mongo {
namespace {

// Generate a vector of unique "database name" strings like "db_00000", "db_00042", etc.
// The indices are sampled from [0, universeSize) without replacement.
std::vector<std::string> generateSortedNames(int count, int universeSize, std::mt19937& gen) {
    // Generate unique indices
    std::vector<int> indices(universeSize);
    std::iota(indices.begin(), indices.end(), 0);
    std::shuffle(indices.begin(), indices.end(), gen);
    indices.resize(count);
    std::sort(indices.begin(), indices.end());

    std::vector<std::string> names;
    names.reserve(count);
    for (int idx : indices) {
        // Fixed-width format ensures lexicographic order matches numeric order
        char buf[32];
        snprintf(buf, sizeof(buf), "db_%05d", idx);
        names.emplace_back(buf);
    }
    return names;
}

// Mirrors the algorithm in StorageEngineImpl::cleanupOrphanedEncryptionKeys():
//   Pass 1: keyIds \ existingDbNames → notInCatalog
//   Pass 2: notInCatalog \ keyIdsInUse → orphaned
std::vector<std::string> findOrphanedKeys(std::vector<std::string> keyIds,
                                          const std::vector<std::string>& keyIdsInUse,
                                          const std::vector<std::string>& existingDbNames) {
    std::sort(keyIds.begin(), keyIds.end());

    std::vector<std::string> notInCatalog;
    std::set_difference(keyIds.begin(),
                        keyIds.end(),
                        existingDbNames.begin(),
                        existingDbNames.end(),
                        std::back_inserter(notInCatalog));

    std::vector<std::string> orphaned;
    std::set_difference(notInCatalog.begin(),
                        notInCatalog.end(),
                        keyIdsInUse.begin(),
                        keyIdsInUse.end(),
                        std::back_inserter(orphaned));

    return orphaned;
}

// Benchmark: scale all three vectors together.
// state.range(0) = total number of keys in the key database
// 50% of keys have a matching database (existingDbNames)
// 25% of keys are in use by idents (keyIdsInUse)
// ~25% end up orphaned
void BM_FindOrphanedKeys(benchmark::State& state) {
    const int numKeys = state.range(0);
    const int numExistingDbs = numKeys / 2;
    const int numIdentsInUse = numKeys / 4;
    const int universeSize = numKeys * 2;  // key names drawn from a larger universe

    std::mt19937 gen(42);  // fixed seed for reproducibility
    auto keyIds = generateSortedNames(numKeys, universeSize, gen);
    auto existingDbNames = generateSortedNames(numExistingDbs, universeSize, gen);
    auto keyIdsInUse = generateSortedNames(numIdentsInUse, universeSize, gen);

    for (auto _ : state) {
        auto result = findOrphanedKeys(keyIds, keyIdsInUse, existingDbNames);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) *
                            (numKeys + numExistingDbs + numIdentsInUse));
}

BENCHMARK(BM_FindOrphanedKeys)->RangeMultiplier(10)->Range(100, 100'000);

// Benchmark: many idents, few keys (typical production scenario).
// A server with 10 databases might have thousands of idents (collections + indexes).
void BM_FindOrphanedKeysFewKeysManyIdents(benchmark::State& state) {
    const int numKeys = 10;
    const int numIdents = state.range(0);
    const int numExistingDbs = 8;  // most keys still have a database
    const int universeSize = numIdents * 2;

    std::mt19937 gen(42);
    auto keyIds = generateSortedNames(numKeys, universeSize, gen);
    auto existingDbNames = generateSortedNames(numExistingDbs, universeSize, gen);
    auto keyIdsInUse = generateSortedNames(numIdents, universeSize, gen);

    for (auto _ : state) {
        auto result = findOrphanedKeys(keyIds, keyIdsInUse, existingDbNames);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) *
                            (numKeys + numExistingDbs + numIdents));
}

BENCHMARK(BM_FindOrphanedKeysFewKeysManyIdents)->RangeMultiplier(10)->Range(1'000, 100'000);

// Benchmark: no orphans (best case — both set_differences produce empty output).
// All keys have a matching database, so Pass 1 yields nothing.
void BM_FindOrphanedKeysNoOrphans(benchmark::State& state) {
    const int numKeys = state.range(0);
    const int universeSize = numKeys * 2;

    std::mt19937 gen(42);
    auto keyIds = generateSortedNames(numKeys, universeSize, gen);
    // existingDbNames is a superset of keyIds — no orphans possible
    auto existingDbNames = keyIds;
    auto keyIdsInUse = generateSortedNames(numKeys / 2, universeSize, gen);

    for (auto _ : state) {
        auto result = findOrphanedKeys(keyIds, keyIdsInUse, existingDbNames);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) *
                            (numKeys + numKeys + numKeys / 2));
}

BENCHMARK(BM_FindOrphanedKeysNoOrphans)->RangeMultiplier(10)->Range(100, 100'000);

}  // namespace
}  // namespace mongo
