// inmemory_init.cpp

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

#include "mongo/platform/basic.h"

#include "mongo/base/init.h"
#include "mongo/db/catalog/collection_options.h"
#include "mongo/db/service_context.h"
#include "mongo/db/storage/inmemory/inmemory_global_options.h"
#include "mongo/db/storage/storage_engine_init.h"
#include "mongo/db/storage/storage_engine_impl.h"
#include "mongo/db/storage/storage_engine_lock_file.h"
#include "mongo/db/storage/storage_engine_metadata.h"
#include "mongo/db/storage/storage_options.h"
#include "mongo/db/storage/storage_parameters_gen.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_global_options.h"
#include "mongo/db/storage/wiredtiger/spill_wiredtiger_kv_engine.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_index.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_kv_engine.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_record_store.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_server_status.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_util.h"

#if __has_feature(address_sanitizer)
#include <sanitizer/lsan_interface.h>
#endif

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kStorage

namespace mongo {

namespace {
const std::string kInMemoryEngineName = "inMemory";
std::once_flag initializeServerStatusSectionFlag;

class InMemoryFactory : public StorageEngine::Factory {
public:
    virtual ~InMemoryFactory() {}
    virtual std::unique_ptr<StorageEngine> create(OperationContext* opCtx,
                                                  const StorageGlobalParams& params,
                                                  const StorageEngineLockFile*,
                                                  bool isReplSet,
                                                  bool shouldRecoverFromOplogAsStandalone,
                                                  bool inStandaloneMode) const {
        syncInMemoryAndWiredTigerOptions();

        size_t cacheMB = WiredTigerUtil::getMainCacheSizeMB(wiredTigerGlobalOptions.cacheSizeGB);
        const double memoryThresholdPercentage = 0.8;
        ProcessInfo p;
        if (p.supported()) {
            if (cacheMB > memoryThresholdPercentage * p.getMemSizeMB()) {
                LOGV2_OPTIONS(
                    29146,
                    {logv2::LogTag::kStartupWarnings},
                    "The configured WiredTiger cache size is more than 80% of available RAM");
            }
        }

        WiredTigerKVEngine::WiredTigerConfig wtConfig = getWiredTigerConfigFromStartupOptions();
        wtConfig.cacheSizeMB = cacheMB;
        wtConfig.inMemory = params.inMemory;
        if (params.inMemory) {
            wtConfig.logEnabled = false;
        }

        auto kv =
            std::make_unique<WiredTigerKVEngine>(std::string{getCanonicalName()},
                                                 params.dbpath,
                                                 getGlobalServiceContext()->getFastClockSource(),
                                                 std::move(wtConfig),
                                                 WiredTigerExtensions::get(opCtx->getServiceContext()),
                                                 params.repair,
                                                 isReplSet,
                                                 shouldRecoverFromOplogAsStandalone,
                                                 inStandaloneMode);
        kv->setRecordStoreExtraOptions(wiredTigerGlobalOptions.collectionConfig);
        kv->setSortedDataInterfaceExtraOptions(wiredTigerGlobalOptions.indexConfig);

        std::unique_ptr<SpillWiredTigerKVEngine> spillWiredTigerKVEngine;
        if (feature_flags::gFeatureFlagCreateSpillKVEngine.isEnabled()) {
            boost::system::error_code ec;
            boost::filesystem::remove_all(params.getSpillDbPath(), ec);
            if (ec) {
                LOGV2_WARNING(29145,
                              "Failed to clear dbpath of the internal WiredTiger instance",
                              "error"_attr = ec.message());
            }

            WiredTigerKVEngineBase::WiredTigerConfig wtConfig =
                getWiredTigerConfigFromStartupOptions(true /* usingSpillWiredTigerKVEngine */);
            // TODO(SERVER-103753): Compute cache size properly.
            wtConfig.cacheSizeMB = 100;
            wtConfig.inMemory = params.inMemory;
            wtConfig.logEnabled = false;
            spillWiredTigerKVEngine = std::make_unique<SpillWiredTigerKVEngine>(
                std::string{getCanonicalName()},
                params.getSpillDbPath(),
                getGlobalServiceContext()->getFastClockSource(),
                std::move(wtConfig),
                SpillWiredTigerExtensions::get(opCtx->getServiceContext()));
        }

        // Register the ServerStatusSection for the in-memory storage engine
        // and do that only once.
        std::call_once(initializeServerStatusSectionFlag, [] {
            *ServerStatusSectionBuilder<WiredTigerServerStatusSection>(
                 std::string{kInMemoryEngineName})
                 .forShard();
        });

        StorageEngineOptions options;
        options.directoryPerDB = params.directoryperdb;
        options.directoryForIndexes = wiredTigerGlobalOptions.directoryForIndexes;
        options.forRepair = params.repair;
        return std::make_unique<StorageEngineImpl>(
            opCtx, std::move(kv), std::move(spillWiredTigerKVEngine), options);
    }

    virtual StringData getCanonicalName() const {
        return kInMemoryEngineName;
    }

    virtual Status validateCollectionStorageOptions(const BSONObj& options) const {
        return WiredTigerRecordStore::parseOptionsField(options).getStatus();
    }

    virtual Status validateIndexStorageOptions(const BSONObj& options) const {
        return WiredTigerIndex::parseIndexOptions(options).getStatus();
    }

    virtual Status validateMetadata(const StorageEngineMetadata& metadata,
                                    const StorageGlobalParams& params) const {
        Status status =
            metadata.validateStorageEngineOption("directoryPerDB", params.directoryperdb);
        if (!status.isOK()) {
            return status;
        }

        status = metadata.validateStorageEngineOption("directoryForIndexes",
                                                      wiredTigerGlobalOptions.directoryForIndexes);
        if (!status.isOK()) {
            return status;
        }

        return Status::OK();
    }

    virtual BSONObj createMetadataOptions(const StorageGlobalParams& params) const {
        BSONObjBuilder builder;
        builder.appendBool("directoryPerDB", params.directoryperdb);
        builder.appendBool("directoryForIndexes", wiredTigerGlobalOptions.directoryForIndexes);
        return builder.obj();
    }

private:
    static void syncInMemoryAndWiredTigerOptions() {
        // Re-create WiredTiger options to fill it with default values
        wiredTigerGlobalOptions = WiredTigerGlobalOptions();

        wiredTigerGlobalOptions.cacheSizeGB =
            inMemoryGlobalOptions.cacheSizeGB;
        wiredTigerGlobalOptions.statisticsLogDelaySecs =
            inMemoryGlobalOptions.statisticsLogDelaySecs;
        // Set InMemory configuration as part of engineConfig string
        wiredTigerGlobalOptions.engineConfig =
            "in_memory=true,"
            "log=(enabled=false),"
            "file_manager=(close_idle_time=0),"
            "checkpoint=(wait=0,log_size=0),";
        // Don't change the order as user-defined config string should go
        // AFTER InMemory config to override it if needed
        wiredTigerGlobalOptions.engineConfig += inMemoryGlobalOptions.engineConfig;
        // Don't change the order as user-defined collection & index config strings should go
        // BEFORE InMemory configs to disable cache_resident option later
        wiredTigerGlobalOptions.collectionConfig = inMemoryGlobalOptions.collectionConfig;
        wiredTigerGlobalOptions.collectionConfig += ",cache_resident=false";
        wiredTigerGlobalOptions.indexConfig = inMemoryGlobalOptions.indexConfig;
        wiredTigerGlobalOptions.indexConfig += ",cache_resident=false";
    }
};

ServiceContext::ConstructorActionRegisterer registerInMemory(
    "InMemoryEngineInit", [](ServiceContext* service) {
        registerStorageEngine(service, std::make_unique<InMemoryFactory>());
    });
}  // namespace
}  // namespace
