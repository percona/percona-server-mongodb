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

#define MONGO_LOG_DEFAULT_COMPONENT ::mongo::logger::LogComponent::kStorage

#include "mongo/platform/basic.h"

#include "mongo/base/init.h"
#include "mongo/db/catalog/collection_options.h"
#include "mongo/db/jsobj.h"
#include "mongo/db/service_context.h"
#include "mongo/db/storage/inmemory/inmemory_global_options.h"
#include "mongo/db/storage/storage_engine_init.h"
#include "mongo/db/storage/kv/kv_storage_engine.h"
#include "mongo/db/storage/storage_engine_lock_file.h"
#include "mongo/db/storage/storage_engine_metadata.h"
#include "mongo/db/storage/storage_options.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_global_options.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_index.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_kv_engine.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_record_store.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_server_status.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_util.h"
#include "mongo/util/log.h"

namespace mongo {

namespace {
const std::string kInMemoryEngineName = "inMemory";

class InMemoryFactory : public StorageEngine::Factory {
public:
    virtual ~InMemoryFactory() {}
    virtual StorageEngine* create(const StorageGlobalParams& params,
                                  const StorageEngineLockFile*) const {
        syncInMemoryAndWiredTigerOptions();

        size_t cacheMB = WiredTigerUtil::getCacheSizeMB(wiredTigerGlobalOptions.cacheSizeGB);
        const bool durable = false;
        const bool ephemeral = true;
        const bool readOnly = false;
        WiredTigerKVEngine* kv = new WiredTigerKVEngine(getCanonicalName().toString(),
                                                        params.dbpath,
                                                        getGlobalServiceContext()->getFastClockSource(),
                                                        wiredTigerGlobalOptions.engineConfig,
                                                        cacheMB,
                                                        durable,
                                                        ephemeral,
                                                        params.repair,
                                                        readOnly);
        kv->setRecordStoreExtraOptions(wiredTigerGlobalOptions.collectionConfig);
        kv->setSortedDataInterfaceExtraOptions(wiredTigerGlobalOptions.indexConfig);
        // Intentionally leaked.
        new WiredTigerServerStatusSection(kv);

        KVStorageEngineOptions options;
        options.directoryPerDB = params.directoryperdb;
        options.directoryForIndexes = wiredTigerGlobalOptions.directoryForIndexes;
        options.forRepair = params.repair;
        return new KVStorageEngine(kv, options);
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

    // explicitly specify that inMemory does not support readOnly mode
    bool supportsReadOnly() const final {
        return false;
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
