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

#include <boost/filesystem.hpp>  // IWYU pragma: keep
#include <boost/optional/optional.hpp>
#include <fmt/format.h>          // IWYU pragma: keep
#include <fstream>
#include <memory>
#include <vector>

#include "mongo/base/data_range.h"
#include "mongo/base/data_type_validated.h"
#include "mongo/base/error_codes.h"
#include "mongo/base/status.h"
#include "mongo/base/status_with.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonelement.h"
#include "mongo/bson/bsonmisc.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/bson/oid.h"
#include "mongo/bson/timestamp.h"
#include "mongo/db/catalog/collection_options.h"
#include "mongo/db/client.h"
#include "mongo/db/cluster_role.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/repl/member_state.h"
#include "mongo/db/repl/read_concern_level.h"
#include "mongo/db/repl/repl_server_parameters_gen.h"
#include "mongo/db/repl/repl_set_config.h"
#include "mongo/db/repl/replication_coordinator.h"
#include "mongo/db/repl/storage_interface.h"
#include "mongo/db/server_options.h"
#include "mongo/db/service_context.h"
#include "mongo/db/storage/storage_options.h"
#include "mongo/db/telemetry/telemetry_thread_base.h"
#include "mongo/logv2/log.h"
#include "mongo/s/catalog/sharding_catalog_client.h"
#include "mongo/s/catalog/type_config_version.h"
#include "mongo/s/grid.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/time_support.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kDefault

namespace mongo {

namespace {

constexpr StringData kSourceName = "mongod"_sd;
constexpr StringData kTelemetryFileName = "psmdb_telemetry.data"_sd;
constexpr StringData kTelemetryCollection = "percona.telemetry"_sd;
constexpr StringData kId = "_id"_sd;
constexpr StringData kScheduledAt = "scheduledAt"_sd;

constexpr StringData kEncryptionKeyStorage = "tde_key_storage"_sd;
constexpr StringData kVaultKeyFile = "keyfile"_sd;
constexpr StringData kVaultVault = "vault"_sd;
constexpr StringData kVaultKmip = "kmip"_sd;

constexpr StringData kPBMVersionField = "v"_sd;
constexpr StringData kPBMActive = "pbm_active"_sd;

constexpr StringData kInitialSyncMethod = "initial_sync_method"_sd;


StringData keyStorageType() {
    if (!encryptionGlobalParams.encryptionKeyFile.empty()) {
        return kVaultKeyFile;
    }
    if (!encryptionGlobalParams.vaultServerName.empty()) {
        return kVaultVault;
    }
    if (!encryptionGlobalParams.kmipServerName.empty()) {
        return kVaultKmip;
    }
    MONGO_UNREACHABLE;
}

class TelemetryThreadD final : public TelemetryThreadBase {
public:
    static std::unique_ptr<TelemetryThreadBase> create() {
        return std::make_unique<TelemetryThreadD>();
    }

private:
    StringData _sourceName() override {
        return kSourceName;
    }

    Status _initInstanceId(const OID& initialId) override {
        auto fileName =
            boost::filesystem::path(storageGlobalParams.dbpath) / sdPath(kTelemetryFileName);
        if (boost::filesystem::exists(fileName)) {
            // read instance id
            auto fileSize = boost::filesystem::file_size(fileName);
            std::vector<char> buffer(fileSize);
            std::ifstream dataFile(fileName, std::ios_base::in | std::ios_base::binary);
            dataFile.read(buffer.data(), buffer.size());

            ConstDataRange cdr(buffer.data(), buffer.size());
            auto swObj = cdr.readNoThrow<Validated<BSONObj>>();
            if (!swObj.isOK()) {
                LOGV2_DEBUG(29134,
                            1,
                            "Failed to load BSON from file. Will try to recreate the file",
                            "file"_attr = fileName.string(),
                            "status"_attr = swObj.getStatus());
            } else {
                try {
                    _instid = static_cast<BSONObj>(swObj.getValue())[kDbInstanceId].OID();
                } catch (const AssertionException& e) {
                    LOGV2_DEBUG(29135,
                                1,
                                "BSON loaded from file does not contain instance id field. Will "
                                "try to recreate the file with new instance id",
                                "status"_attr = e.toStatus());
                }
            }
        }
        if (!_instid.isSet()) {
            // create file with new OID
            // probably overwriting existing file which we have failed to parse
            _instid = initialId;
            auto obj = BSON(kDbInstanceId << _instid);
            std::ofstream dataFile(
                fileName, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
            dataFile.write(obj.objdata(), obj.objsize());
        }
        return Status::OK();
    }

    Status _initDbId(ServiceContext* serviceContext,
                     OperationContext* opCtx,
                     const OID& initialId) override {
        // see StorageInterfaceImpl::initializeRollbackID
        // see ReplicationConsistencyMarkersImpl::setInitialSyncIdIfNotSet
        repl::UnreplicatedWritesBlock uwb(opCtx);
        auto* storageInterface = repl::StorageInterface::get(serviceContext);
        if (storageInterface == nullptr) {
            return {ErrorCodes::InternalError, "Failed to access storage interface"};
        }
        const auto nss = NamespaceString::makeLocalCollection(kTelemetryCollection);
        auto status = storageInterface->createCollection(opCtx, nss, CollectionOptions());
        if (!status.isOK() && status.code() != ErrorCodes::NamespaceExists) {
            LOGV2_DEBUG(29124, 1, "Failed to create collection", logAttrs(nss));
            return status;
        }
        auto prev = storageInterface->findSingleton(opCtx, nss);
        if (prev.isOK()) {
            // copy scheduled time from BSONObj to nextScrape
            auto obj = prev.getValue();
            try {
                _nextScrape = obj[kScheduledAt].Date();
                _dbid = obj[kId].OID();
            } catch (AssertionException& e) {
                LOGV2_DEBUG(29125,
                            1,
                            "Failed to read internal db id or next telemetry scrape scheduled "
                            "time. Will try to recreate the document",
                            "status"_attr = e.toStatus());
            }
        } else if (prev.getStatus() != ErrorCodes::CollectionIsEmpty) {
            return prev.getStatus();
        }

        if (!_dbid.isSet()) {
            _dbid = initialId;
            auto doc = BSON(kId << _dbid << kScheduledAt << _nextScrape);
            Timestamp noTimestamp;  // This write is not replicated
            if (auto status = storageInterface->putSingleton(
                    opCtx, nss, repl::TimestampedBSONObj{doc, noTimestamp});
                !status.isOK()) {
                LOGV2_DEBUG(29127, 1, "Failed to insert document into collection", logAttrs(nss));
                return status;
            }
        }
        return Status::OK();
    }

    Status _advancePersist(ServiceContext* serviceContext) override {
        auto opCtxObj = cc().makeOperationContext();
        auto* opCtx = opCtxObj.get();
        repl::UnreplicatedWritesBlock uwb(opCtx);
        auto* storageInterface = repl::StorageInterface::get(serviceContext);
        if (storageInterface == nullptr) {
            return {ErrorCodes::InternalError, "Failed to access storage interface"};
        }
        const auto nss = NamespaceString::makeLocalCollection(kTelemetryCollection);
        auto doc = BSON(kId << _dbid << kScheduledAt << _nextScrape);
        Timestamp noTimestamp;  // This write is not replicated
        return storageInterface->putSingleton(
            opCtx, nss, repl::TimestampedBSONObj{doc, noTimestamp});
    }

    Status _appendShardingMetrics(ServiceContext* serviceContext,
                                  OperationContext* opCtx,
                                  BSONObjBuilder* builder) try {
        OID clusterId;
        if (auto* grid = Grid::get(serviceContext)) {
            if (grid->isShardingInitialized()) {
                auto* catalogClient = grid->catalogClient();
                auto cfgVersion = catalogClient->getConfigVersion(
                    opCtx, repl::ReadConcernLevel::kMajorityReadConcern);
                if (cfgVersion.isOK()) {
                    clusterId = cfgVersion.getValue().getClusterId();
                    builder->append(kClusterId, clusterId.toString());
                    builder->append(
                        kShardSvr,
                        boolName(serverGlobalParams.clusterRole.has(ClusterRole::ShardServer)));
                    builder->append(
                        kConfigSvr,
                        boolName(serverGlobalParams.clusterRole.has(ClusterRole::ConfigServer)));
                }
            }
        }
        return Status::OK();
    } catch (...) {
        return exceptionToStatus();
    }

    Status _appendBackupMetrics(ServiceContext* serviceContext,
                                OperationContext* opCtx,
                                BSONObjBuilder* builder) try {
        // check if 'admin.pbmAgents' namespace exists and try to extract PBM version
        auto* storageInterface = repl::StorageInterface::get(serviceContext);
        if (storageInterface == nullptr) {
            return {ErrorCodes::InternalError, "Failed to access storage interface"};
        }
        const auto res =
            storageInterface->findDocuments(opCtx,
                                            NamespaceString::kAdminPBMAgents,
                                            boost::none,
                                            repl::StorageInterface::ScanDirection::kForward,
                                            {},
                                            BoundInclusion::kIncludeStartKeyOnly,
                                            1U);
        if (res.isOK()) {
            // collection exists, try to get version from the document
            const auto& docs = res.getValue();
            if (!docs.empty()) {
                const BSONObj& obj = docs.front();
                try {
                    builder->append(kPBMActive, obj[kPBMVersionField].checkAndGetStringData());
                } catch (AssertionException&) {  // NOLINT(*-empty-catch)
                    // ignoring exception as there is no PBM in this case
                }
            }
        } else if (res.getStatus() != ErrorCodes::NamespaceNotFound) {
            return res.getStatus();
        }
        return Status::OK();
    } catch (...) {
        return exceptionToStatus();
    }

    void _appendMetrics(ServiceContext* serviceContext, BSONObjBuilder* builder) override {
        builder->append(kStorageEngine, storageGlobalParams.engine);
        if (auto* rs = repl::ReplicationCoordinator::get(serviceContext);
            rs->getSettings().isReplSet()) {
            builder->append(kReplicaSetId, rs->getConfig().getReplicaSetId().toString());
            builder->append(kReplMemberState, rs->getMemberState().toString());
            // is FCBIS enabled?
            builder->append(kInitialSyncMethod, repl::initialSyncMethod);
        }
        // data at rest encryption
        if (encryptionGlobalParams.enableEncryption) {
            builder->append(kEncryptionKeyStorage, keyStorageType());
        }

        // operation context is necessary for following operations
        auto opCtxObj = cc().makeOperationContext();
        auto* opCtx = opCtxObj.get();

        // sharding metrics
        if (auto status = _appendShardingMetrics(serviceContext, opCtx, builder); !status.isOK()) {
            LOGV2_DEBUG(29137, 1, "Failed to collect sharding metrics", "status"_attr = status);
        }

        // PBM activity
        if (auto status = _appendBackupMetrics(serviceContext, opCtx, builder); !status.isOK()) {
            LOGV2_DEBUG(
                29138, 1, "Failed to collect backup-related metrics", "status"_attr = status);
        }
    }
};

}  // namespace

void initPerconaTelemetry(ServiceContext* serviceContext) {
    TelemetryThreadBase::create = TelemetryThreadD::create;
    initPerconaTelemetryInternal(serviceContext);
}

}  // namespace mongo
