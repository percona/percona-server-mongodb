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

#include "mongo/db/storage/kv/kv_engine_test_harness.h"

#include "mongo/base/init.h"
#include "mongo/db/repl/repl_settings.h"
#include "mongo/db/repl/replication_coordinator_mock.h"
#include "mongo/db/repl/repl_set_member_in_standalone_mode.h"
#include "mongo/db/service_context.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_kv_engine.h"
#include "mongo/db/global_settings.h"
#include "mongo/unittest/temp_dir.h"
#include "mongo/util/clock_source_mock.h"

namespace mongo {
namespace {

namespace {
    const std::string kInMemoryEngineName = "inMemory";
}

class InMemoryKVHarnessHelper : public KVHarnessHelper {
public:
    InMemoryKVHarnessHelper(ServiceContext* svcCtx) : _dbpath("inmem-kv-harness") {
        if (!hasGlobalServiceContext())
            setGlobalServiceContext(ServiceContext::make());
        auto client = svcCtx->getService()->makeClient("opCtx");
        auto opCtx = client->makeOperationContext();

        WiredTigerKVEngine::WiredTigerConfig wtConfig;
        wtConfig.cacheSizeMB = 100;
        wtConfig.inMemory = true;
        wtConfig.extraOpenOptions =
            "in_memory=true,"
            "log=(enabled=false),"
            "file_manager=(close_idle_time=0),"
            "checkpoint=(wait=0,log_size=0)";
        _engine.reset(
            new WiredTigerKVEngine(kInMemoryEngineName,
                                   _dbpath.path(),
                                   _cs.get(),
                                   std::move(wtConfig),
                                   WiredTigerExtensions::get(svcCtx),
                                   false,
                                   getGlobalReplSettings().isReplSet(),
                                   repl::ReplSettings::shouldRecoverFromOplogAsStandalone(),
                                   getReplSetMemberInStandaloneMode(getGlobalServiceContext())));
        repl::ReplicationCoordinator::set(
            svcCtx,
            std::unique_ptr<repl::ReplicationCoordinator>(
                new repl::ReplicationCoordinatorMock(svcCtx, repl::ReplSettings())));
        _engine->notifyStorageStartupRecoveryComplete();
    }

    ~InMemoryKVHarnessHelper() override {
        _engine.reset(NULL);
    }

    KVEngine* restartEngine() override {
        // Don't reset the engine since it doesn't persist anything
        // and all the data will be lost.
        return _engine.get();
    }

    KVEngine* getEngine() override {
        return _engine.get();
    }

private:
    const std::unique_ptr<ClockSource> _cs = std::make_unique<ClockSourceMock>();
    unittest::TempDir _dbpath;
    std::unique_ptr<WiredTigerKVEngine> _engine;
};

std::unique_ptr<KVHarnessHelper> makeHelper(ServiceContext* svcCtx) {
    return std::make_unique<InMemoryKVHarnessHelper>(svcCtx);
}

MONGO_INITIALIZER(RegisterKVHarnessFactory)(InitializerContext*) {
    KVHarnessHelper::registerFactory(makeHelper);
}

}  // namespace
}  // namespace mongo
