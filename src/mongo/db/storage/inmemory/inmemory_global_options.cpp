// inmemory_global_options.cpp

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

#include "mongo/base/status.h"
#include "mongo/db/storage/inmemory/inmemory_global_options.h"
#include "mongo/util/log.h"

namespace mongo {

InMemoryGlobalOptions inMemoryGlobalOptions;

Status InMemoryGlobalOptions::add(moe::OptionSection* options) {
    moe::OptionSection inMemoryOptions("InMemory options");

    // InMemory storage engine options
    inMemoryOptions
        .addOptionChaining("storage.inMemory.engineConfig.inMemorySizeGB",
                           "inMemorySizeGB",
                           moe::Double,
                           "The maximum memory in gigabytes to use for InMemory storage. "
                           "See documentation for default.");

    // hidden options
    inMemoryOptions
        .addOptionChaining("storage.inMemory.engineConfig.statisticsLogDelaySecs",
                           "inMemoryStatisticsLogDelaySecs",
                           moe::Int,
                           "The number of seconds between writes to statistics log. "
                           "If 0 is specified then statistics will not be logged.")
        // FTDC supercedes inMemory's statistics logging.
        .hidden()
        .validRange(0, 100000)
        .setDefault(moe::Value(0));
    inMemoryOptions
        .addOptionChaining("storage.inMemory.engineConfig.configString",
                           "inMemoryEngineConfigString",
                           moe::String,
                           "InMemory storage engine custom "
                           "configuration settings")
        .hidden();
    inMemoryOptions
        .addOptionChaining("storage.inMemory.collectionConfig.configString",
                           "inMemoryCollectionConfigString",
                           moe::String,
                           "InMemory custom collection configuration settings")
        .hidden();
    inMemoryOptions
        .addOptionChaining("storage.inMemory.indexConfig.configString",
                           "inMemoryIndexConfigString",
                           moe::String,
                           "InMemory custom index configuration settings")
        .hidden();

    return options->addSection(inMemoryOptions);
}

Status InMemoryGlobalOptions::store(const moe::Environment& params,
                                    const std::vector<std::string>& args) {
    // InMemory storage engine options
    if (params.count("storage.inMemory.engineConfig.inMemorySizeGB")) {
        inMemoryGlobalOptions.cacheSizeGB =
            params["storage.inMemory.engineConfig.inMemorySizeGB"].as<double>();
    }
    if (params.count("storage.inMemory.engineConfig.statisticsLogDelaySecs")) {
        inMemoryGlobalOptions.statisticsLogDelaySecs =
            params["storage.inMemory.engineConfig.statisticsLogDelaySecs"].as<int>();
    }

    // hidden options
    if (params.count("storage.inMemory.engineConfig.configString")) {
        inMemoryGlobalOptions.engineConfig =
            params["storage.inMemory.engineConfig.configString"].as<std::string>();
        log() << "Engine custom option: " << inMemoryGlobalOptions.engineConfig;
    }
    if (params.count("storage.inMemory.collectionConfig.configString")) {
        inMemoryGlobalOptions.collectionConfig =
            params["storage.inMemory.collectionConfig.configString"].as<std::string>();
        log() << "Collection custom option: " << inMemoryGlobalOptions.collectionConfig;
    }
    if (params.count("storage.inMemory.indexConfig.configString")) {
        inMemoryGlobalOptions.indexConfig =
            params["storage.inMemory.indexConfig.configString"].as<std::string>();
        log() << "Index custom option: " << inMemoryGlobalOptions.indexConfig;
    }

    return Status::OK();
}

}  // namespace mongo
