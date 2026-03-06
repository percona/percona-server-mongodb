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

#include "mongo/util/hex.h"

#include <cstddef>
#include <string>

#include <benchmark/benchmark.h>

namespace mongo {
namespace {

void BM_HexEncode(benchmark::State& state) {
    std::string in(state.range(0), 'x');
    size_t outBytes = 0;
    for (auto _ : state) {
        std::string out;
        benchmark::DoNotOptimize(out = hexblob::encode(in));
        outBytes += out.size();
    }
    state.counters["outBytes"] = outBytes;
}

void BM_HexDecode(benchmark::State& state) {
    const size_t length = static_cast<size_t>(state.range(0));
    std::string in;
    for (size_t i = 0; i < length; ++i)
        in.push_back("0123456789abcdef"[i & 0xf]);
    size_t outBytes = 0;
    for (auto _ : state) {
        std::string out;
        benchmark::DoNotOptimize(out = hexblob::decode(in));
        outBytes += out.size();
    }
    state.counters["outBytes"] = outBytes;
}

void BM_HexDecodeFromValidSizedInput(benchmark::State& state) {
    const size_t length = static_cast<size_t>(state.range(0));
    std::string in;
    for (size_t i = 0; i < length; ++i)
        in.push_back("0123456789abcdef"[i & 0xf]);
    size_t outBytes = 0;
    for (auto _ : state) {
        std::string out;
        benchmark::DoNotOptimize(out = hexblob::decodeFromValidSizedInput(in));
        outBytes += out.size();
    }
    state.counters["outBytes"] = outBytes;
}

void customRanges(benchmark::internal::Benchmark* b) {
    b->Arg(0)->RangeMultiplier(2)->Range(8, 128 << 10);
}

BENCHMARK(BM_HexEncode)->Apply(customRanges);
BENCHMARK(BM_HexDecode)->Apply(customRanges);
BENCHMARK(BM_HexDecodeFromValidSizedInput)->Apply(customRanges);

}  // namespace
}  // namespace mongo
