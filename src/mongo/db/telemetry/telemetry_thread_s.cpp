/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2024-present Percona and/or its affiliates. All rights reserved.

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

#include <memory>

#include "mongo/base/status.h"
#include "mongo/base/status_with.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/bson/oid.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/repl/read_concern_level.h"
#include "mongo/db/service_context.h"
#include "mongo/db/telemetry/telemetry_thread_base.h"
#include "mongo/s/catalog/sharding_catalog_client.h"
#include "mongo/s/catalog/type_config_version.h"
#include "mongo/s/grid.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kDefault

namespace mongo {

namespace {

constexpr StringData kSourceName = "mongos"_sd;


class TelemetryThreadS final : public TelemetryThreadBase {
public:
    static std::unique_ptr<TelemetryThreadBase> create() {
        return std::make_unique<TelemetryThreadS>();
    }

private:
    StringData _sourceName() override {
        return kSourceName;
    }

    Status _initInstanceId(const OID& initialId, BSONObjBuilder* pfx) override {
        _instid = initialId;
        pfx->append(kDbInstanceId, _instid.toString());
        return Status::OK();
    }

    Status _initDbId(ServiceContext* serviceContext,
                     OperationContext* opCtx,
                     const OID& initialId,
                     BSONObjBuilder* pfx) override {
        // mongos has no internal db Id
        return Status::OK();
    }

    Status _initClusterId(ServiceContext* serviceContext,
                          OperationContext* opCtx,
                          BSONObjBuilder* pfx) override {
        OID clusterId;
        if (auto* grid = Grid::get(serviceContext)) {
            if (grid->isShardingInitialized()) {
                auto* catalogClient = grid->catalogClient();
                auto cfgVersion = catalogClient->getConfigVersion(
                    opCtx, repl::ReadConcernLevel::kMajorityReadConcern);
                if (cfgVersion.isOK()) {
                    clusterId = cfgVersion.getValue().getClusterId();
                    pfx->append(kClusterId, clusterId.toString());
                }
            }
        }
        return Status::OK();
    }

    Status _advancePersist(ServiceContext* serviceContext) override {
        // mongos cannot persist this
        return Status::OK();
    }

    Status _appendMetrics(ServiceContext* serviceContext, BSONObjBuilder* builder) override {
        return Status::OK();
    }
};

}  // namespace

void initPerconaTelemetry(ServiceContext* serviceContext) {
    TelemetryThreadBase::create = TelemetryThreadS::create;
    initPerconaTelemetryInternal(serviceContext);
}

}  // namespace mongo
