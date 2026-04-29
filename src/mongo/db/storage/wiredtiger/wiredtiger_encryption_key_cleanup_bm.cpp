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
 * Benchmark for the WT-side work of orphaned encryption key cleanup.
 *
 * Targets the part that dominates wall time in production:
 * the WT metadata cursor scan + per-ident getMetadataCreate + keyid extraction
 * that runs inside WiredTigerKVEngine::findOrphanedEncryptionKeyIds(). The
 * keydb listing and final set_difference are O(K) and negligible by
 * comparison.
 */

#include "mongo/base/string_data.h"
#include "mongo/db/service_context_test_fixture.h"
#include "mongo/db/storage/wiredtiger/encryption_keydb.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_connection.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_error_util.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_recovery_unit.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_session.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_util.h"
#include "mongo/unittest/temp_dir.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/clock_source_mock.h"

#include <algorithm>
#include <cstdio>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <wiredtiger.h>

#include <benchmark/benchmark.h>

namespace mongo {
namespace {

// Opens a raw WT connection in a temp dir and wraps it with the same
// WiredTigerConnection/RecoveryUnit/Session machinery the production code uses,
// so we can call WiredTigerUtil helpers directly.
class WtMetadataHarness : public ScopedGlobalServiceContextForTest {
public:
    WtMetadataHarness(int numIdents, bool withEncryptionConfig) {
        std::string config = "create,log=(enabled=true,file_max=1m,prealloc=false)";
        int ret = wiredtiger_open(_tempDir.path().c_str(), nullptr, config.c_str(), &_conn);
        invariant(wtRCToStatus(ret, nullptr));

        _connection =
            std::make_unique<WiredTigerConnection>(_conn, &_clockSource, /*sessionCacheMax=*/33000);
        _ru = std::make_unique<WiredTigerRecoveryUnit>(_connection.get(), nullptr);
        _session = _ru->getSession();

        // 100 distinct keyids, each used by many idents — this mirrors the
        // typical production shape (few databases, thousands of idents).
        constexpr int kNumKeys = 100;
        for (int i = 0; i < numIdents; ++i) {
            char uri[64];
            std::snprintf(uri, sizeof(uri), "table:collection-%06d", i);

            std::ostringstream createConfig;
            createConfig << "key_format=q,value_format=u";
            if (withEncryptionConfig) {
                createConfig << ",encryption=(name=none,keyid=\"db_" << (i % kNumKeys) << "\")";
            }

            auto s = createConfig.str();
            invariant(wtRCToStatus(_session->create(uri, s.c_str()), *_session));
        }
        _ru->abandonSnapshot();
    }

    ~WtMetadataHarness() override {
        _ru.reset();
        _connection.reset();
        _conn->close(_conn, nullptr);
    }

    WiredTigerSession& session() {
        return *_session;
    }

private:
    unittest::TempDir _tempDir{"wt_encryption_key_cleanup_bm"};
    ClockSourceMock _clockSource;
    WT_CONNECTION* _conn = nullptr;
    std::unique_ptr<WiredTigerConnection> _connection;
    std::unique_ptr<WiredTigerRecoveryUnit> _ru;
    WiredTigerSession* _session = nullptr;
};

// Mirrors the body of WiredTigerKVEngineBase::_wtGetAllIdents at
// src/mongo/db/storage/wiredtiger/wiredtiger_kv_engine.cpp:1068 so the
// benchmark exercises the same cursor-scan cost as production.
std::vector<std::string> wtGetAllIdents(WiredTigerSession& session) {
    std::vector<std::string> all;
    WT_CURSOR* c = nullptr;
    auto ret = session.open_cursor("metadata:", nullptr, nullptr, &c);
    uassertStatusOK(wtRCToStatus(ret, session));
    if (!c) {
        return all;
    }
    while ((ret = c->next(c)) == 0) {
        const char* raw;
        c->get_key(c, &raw);
        StringData key(raw);
        size_t idx = key.find(':');
        if (idx == std::string::npos) {
            continue;
        }
        if (key.substr(0, idx) != "table") {
            continue;
        }
        all.emplace_back(std::string{key.substr(idx + 1)});
    }
    c->close(c);
    return all;
}

// Mirrors the cursor-scan + per-ident metadata fetch + keyid extraction
// portion of WiredTigerKVEngine::findOrphanedEncryptionKeyIds. The keydb
// listing and the final set_difference are excluded; this is the cost that
// scales with ident count.
std::vector<std::string> scanIdentsForKeyIdsInUse(WiredTigerSession& session) {
    std::vector<std::string> keyIdsInUse;
    auto idents = wtGetAllIdents(session);
    for (const auto& ident : idents) {
        auto metadata =
            WiredTigerUtil::getMetadataCreate(session, WiredTigerUtil::buildTableUri(ident));
        if (!metadata.isOK()) {
            continue;
        }
        auto keyId = WiredTigerUtil::getEncryptionKeyId(metadata.getValue());
        if (keyId && !EncryptionKeyDB::isSpecialKeyId(*keyId)) {
            keyIdsInUse.emplace_back(std::move(*keyId));
        }
    }
    std::sort(keyIdsInUse.begin(), keyIdsInUse.end());
    keyIdsInUse.erase(std::unique(keyIdsInUse.begin(), keyIdsInUse.end()), keyIdsInUse.end());
    return keyIdsInUse;
}

// WT-scan portion of findOrphanedEncryptionKeyIds: cursor scan + per-ident
// getMetadataCreate + getEncryptionKeyId extraction + sort/dedup. Excludes
// the keydb listing and final set_difference, which are O(K).
void BM_ScanIdentsForKeyIdsInUse(benchmark::State& state) {
    WtMetadataHarness harness(static_cast<int>(state.range(0)),
                              /*withEncryptionConfig=*/true);
    for (auto _ : state) {
        auto keyIds = scanIdentsForKeyIdsInUse(harness.session());
        benchmark::DoNotOptimize(keyIds);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * state.range(0));
}

BENCHMARK(BM_ScanIdentsForKeyIdsInUse)->RangeMultiplier(10)->Range(100, 10'000);

// Only the cursor scan, with no per-ident metadata fetch or keyid parsing.
// Isolates the WT metadata iteration cost from the per-ident work.
void BM_WtGetAllIdents(benchmark::State& state) {
    WtMetadataHarness harness(static_cast<int>(state.range(0)),
                              /*withEncryptionConfig=*/false);
    for (auto _ : state) {
        auto idents = wtGetAllIdents(harness.session());
        benchmark::DoNotOptimize(idents);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * state.range(0));
}

BENCHMARK(BM_WtGetAllIdents)->RangeMultiplier(10)->Range(100, 10'000);

// Only the per-ident metadata:create point lookup, iterating over a
// pre-built ident list. Isolates the getMetadataCreate cost from the
// initial cursor scan and from keyid parsing.
void BM_GetMetadataCreate(benchmark::State& state) {
    WtMetadataHarness harness(static_cast<int>(state.range(0)),
                              /*withEncryptionConfig=*/true);
    auto idents = wtGetAllIdents(harness.session());
    for (auto _ : state) {
        for (const auto& ident : idents) {
            auto metadata = WiredTigerUtil::getMetadataCreate(harness.session(),
                                                              WiredTigerUtil::buildTableUri(ident));
            benchmark::DoNotOptimize(metadata);
        }
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * state.range(0));
}

BENCHMARK(BM_GetMetadataCreate)->RangeMultiplier(10)->Range(100, 10'000);

// Only getEncryptionKeyId parsing overhead, on a synthetic config string that
// mirrors the shape WT stores for an encrypted ident. Isolates the string-
// parser cost from the WT I/O cost.
void BM_GetEncryptionKeyIdParse(benchmark::State& state) {
    std::string config =
        "key_format=q,value_format=u,encryption=(name=percona,keyid=\"db_000042\")";
    for (auto _ : state) {
        auto keyId = WiredTigerUtil::getEncryptionKeyId(config);
        benchmark::DoNotOptimize(keyId);
    }
}

BENCHMARK(BM_GetEncryptionKeyIdParse);

}  // namespace
}  // namespace mongo
