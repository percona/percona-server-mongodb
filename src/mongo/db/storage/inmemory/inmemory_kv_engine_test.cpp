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
#include "mongo/db/global_settings.h"
#include "mongo/db/repl/repl_settings.h"
#include "mongo/db/repl/replication_coordinator_mock.h"
#include "mongo/db/service_context.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_kv_engine.h"
#include "mongo/db/storage/storage_engine_impl.h"
#include "mongo/unittest/temp_dir.h"
#include "mongo/util/clock_source_mock.h"

namespace mongo {
namespace {

namespace {
    const std::string kInMemoryEngineName = "inMemory";
}

class InMemoryKVHarnessHelper : public KVHarnessHelper {
public:
    InMemoryKVHarnessHelper(ServiceContext* svcCtx) : _dbpath("inmem-kv-harness"), _svcCtx(svcCtx) {
        if (!hasGlobalServiceContext())
            setGlobalServiceContext(ServiceContext::make());
        auto client = svcCtx->makeClient("opCtx");
        auto opCtx = client->makeOperationContext();
        auto kv = std::make_unique<WiredTigerKVEngine>(opCtx.get(),
                                                       kInMemoryEngineName,
                                                       _dbpath.path(),
                                                       _cs.get(),
                                                       "in_memory=true,"
                                                       "log=(enabled=false),"
                                                       "file_manager=(close_idle_time=0),"
                                                       "checkpoint=(wait=0,log_size=0)",
                                                       100,
                                                       0,
                                                       true,
                                                       false);

        // Simulate being in replica set mode for timestamping tests
        repl::ReplSettings replSettings;
        replSettings.setReplSetString("i am a replica set");
        setGlobalReplSettings(replSettings);
        repl::ReplicationCoordinator::set(
            svcCtx, std::make_unique<repl::ReplicationCoordinatorMock>(svcCtx, replSettings));

        StorageEngineOptions options;
        _svcCtx->setStorageEngine(
            std::make_unique<StorageEngineImpl>(opCtx.get(), std::move(kv), options));

        getWiredTigerKVEngine()->notifyStartupComplete();
    }

    ~InMemoryKVHarnessHelper() override {
        getWiredTigerKVEngine()->cleanShutdown(true);
        _svcCtx->clearStorageEngine();
    }

    virtual KVEngine* restartEngine() {
        // Don't reset the engine since it doesn't persist anything
        // and all the data will be lost.
        return getEngine();
    }

    KVEngine* getEngine() override {
        return _svcCtx->getStorageEngine()->getEngine();
    }

private:
    WiredTigerKVEngine* getWiredTigerKVEngine() {
        auto engine = dynamic_cast<WiredTigerKVEngine*>(_svcCtx->getStorageEngine()->getEngine());
        invariant(engine);
        return engine;
    }

    const std::unique_ptr<ClockSource> _cs = std::make_unique<ClockSourceMock>();
    unittest::TempDir _dbpath;
    ServiceContext* _svcCtx;
};

std::unique_ptr<KVHarnessHelper> makeHelper(ServiceContext* svcCtx) {
    return std::make_unique<InMemoryKVHarnessHelper>(svcCtx);
}

MONGO_INITIALIZER(RegisterKVHarnessFactory)(InitializerContext*) {
    KVHarnessHelper::registerFactory(makeHelper);
}

}  // namespace
}  // namespace mongo
