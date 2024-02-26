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

#include "mongo/db/telemetry/telemetry_thread.h"

#include <array>
#include <boost/filesystem.hpp>  // IWYU pragma: keep
#include <cstddef>
#include <fmt/format.h>  // IWYU pragma: keep
#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "mongo/base/data_range.h"
#include "mongo/base/data_type_validated.h"
#include "mongo/base/error_codes.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonmisc.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/bson/bsontypes.h"
#include "mongo/bson/oid.h"
#include "mongo/db/client.h"
#include "mongo/db/cluster_role.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/repl/optime.h"
#include "mongo/db/repl/replication_coordinator.h"
#include "mongo/db/repl/storage_interface.h"
#include "mongo/db/server_options.h"
#include "mongo/db/server_parameter.h"
#include "mongo/db/service_context.h"
#include "mongo/db/storage/storage_options.h"
#include "mongo/db/telemetry/telemetry_parameter_gen.h"
#include "mongo/logv2/log.h"
#include "mongo/platform/atomic_word.h"
#include "mongo/platform/mutex.h"
#include "mongo/s/catalog/type_config_version.h"
#include "mongo/s/grid.h"
#include "mongo/stdx/condition_variable.h"
#include "mongo/stdx/mutex.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/background.h"
#include "mongo/util/concurrency/idle_thread_block.h"
#include "mongo/util/duration.h"
#include "mongo/util/time_support.h"
#include "mongo/util/uuid.h"
#include "mongo/util/version.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kDefault

namespace mongo {

namespace {

constexpr StringData kParamName = "perconaTelemetry"_sd;
constexpr StringData kTelemetryPath = "/usr/local/percona/telemetry/psmdb"_sd;
constexpr StringData kTelemetryFileName = "psmdb_telemetry.data"_sd;
constexpr StringData kTelemetryNamespace = "local.percona.telemetry"_sd;

constexpr StringData kId = "_id"_sd;
constexpr StringData kScheduledAt = "scheduledAt"_sd;

constexpr StringData kFalse = "false"_sd;
constexpr StringData kTrue = "true"_sd;
constexpr StringData kShardSvr = "shardsvr"_sd;
constexpr StringData kConfigSvr = "configsvr"_sd;
constexpr StringData kNoneSvr = "none"_sd;

// names of the fields in the metric file
constexpr StringData kDbInstanceId = "dbInstanceId"_sd;
constexpr StringData kPillarVersion = "pillar_version"_sd;
constexpr StringData kStorageEngine = "storageEngine"_sd;
constexpr StringData kReplicationEnabled = "replicationEnabled"_sd;
constexpr StringData kReplicaSetId = "replicaSetId"_sd;
constexpr StringData kReplMemberState = "replMemberState"_sd;
constexpr StringData kClusterId = "clusterId"_sd;
constexpr StringData kClusterRole = "clusterRole"_sd;


// We need this flag to filter out updates from server parameter which can arrive before global
// service context is set. In other words we need to avoid asserts from getGlobalServiceContext()
bool updatesEnabled = false;

// mutex to serialize external API calls and access to updatesEnabled
Mutex mutex = MONGO_MAKE_LATCH("TelemetryThread::mutex");

// auxiliary function
auto sdPath(StringData sd) {
    return boost::filesystem::path{sd.rawData(), sd.rawData() + sd.size()};
}

// auxiliary function
constexpr StringData boolName(bool v) {
    return v ? kTrue : kFalse;
}

// auxiliary function
StringData clusterRoleName(mongo::ClusterRole v) {
    if (v.has(ClusterRole::ConfigServer))
        return kConfigSvr;
    if (v.has(ClusterRole::ShardServer))
        return kShardSvr;
    return kNoneSvr;
}

class TelemetryThread;

const auto getTelemetryThread =
    ServiceContext::declareDecoration<std::unique_ptr<TelemetryThread>>();

class TelemetryThread final : public BackgroundJob {
public:
    explicit TelemetryThread()
        : BackgroundJob(false /* selfDelete */),
          _nextScrape(Date_t::now() + Seconds(perconaTelemetryGracePeriod)) {}

    static TelemetryThread* get(ServiceContext* serviceCtx) {
        return getTelemetryThread(serviceCtx).get();
    }

    static void set(ServiceContext* serviceCtx,
                    std::unique_ptr<TelemetryThread> newTelemetryThread) {
        auto& telemetryThread = getTelemetryThread(serviceCtx);
        if (telemetryThread) {
            invariant(
                !telemetryThread->running(),
                "Tried to reset the TelemetryThread without shutting down the previous instance.");
        }

        invariant(newTelemetryThread);
        telemetryThread = std::move(newTelemetryThread);
    }

    std::string name() const final {
        return "PerconaTelemetry";
    }

    void run() final {
        const ThreadClient tc(name(), getGlobalServiceContext());
        LOGV2_DEBUG(29121, 1, "starting {name} thread", "name"_attr = name());

        // TODO: handle errors
        _initParameters(tc->getServiceContext());

        while (!_shuttingDown.load()) {
            if (Date_t::now() >= _nextScrape) {
                auto* serviceCtx = tc->getServiceContext();
                // create metrics file
                _writeMetrics(serviceCtx);
                // update nextScrape
                _advance(serviceCtx);
            }

            {
                stdx::unique_lock<Latch> lock(_mutex);
                MONGO_IDLE_THREAD_BLOCK;
                _condvar.wait_until(lock, _nextScrape.toSystemTimePoint());
            }
        }
        LOGV2_DEBUG(29122, 1, "stopping {name} thread", "name"_attr = name());
    }

    void shutdown() {
        _shuttingDown.store(true);
        {
            stdx::unique_lock<Latch> lock(_mutex);
            // Wake up the telemetry thread early, we do not want the shutdown
            // to wait for us too long.
            _condvar.notify_one();
        }
        wait();
    }

private:
    void _initParameters(ServiceContext* serviceContext) {
        // TODO: refactor all this out of constructor into dedicated functions returning Status
        // load/create instance id
        auto fileName =
            boost::filesystem::path(storageGlobalParams.dbpath) / sdPath(kTelemetryFileName);
        if (boost::filesystem::exists(fileName)) {
            // read instance uuid
            auto fileSize = boost::filesystem::file_size(fileName);
            std::vector<char> buffer(fileSize);
            std::ifstream dataFile(fileName, std::ios_base::in | std::ios_base::binary);
            dataFile.read(buffer.data(), buffer.size());

            ConstDataRange cdr(buffer.data(), buffer.size());
            auto swObj = cdr.readNoThrow<Validated<BSONObj>>();
            // if (!swObj.isOK()) {
            //     return swObj.getStatus();
            // }

            _uuid = UUID::parse(swObj.getValue());
        } else {
            // create file with new UUID
            _uuid = UUID::gen();
            auto obj = _uuid.toBSON();
            std::ofstream dataFile(fileName, std::ios_base::out | std::ios_base::binary);
            dataFile.write(obj.objdata(), obj.objsize());
        }
        LOGV2_DEBUG(29123, 1, "Initialized telemetry instance UUID: {uuid}", "uuid"_attr = _uuid);
        // load/create db id
        // see StorageInterfaceImpl::initializeRollbackID
        // see ReplicationConsistencyMarkersImpl::setInitialSyncIdIfNotSet
        auto opCtxObj = cc().makeOperationContext();
        auto* opCtx = opCtxObj.get();
        repl::UnreplicatedWritesBlock uwb(opCtx);
        auto* storageInterface = repl::StorageInterface::get(serviceContext);
        const NamespaceString nss{kTelemetryNamespace};
        auto status = storageInterface->createCollection(opCtx, nss, CollectionOptions());
        if (!status.isOK() && status.code() != ErrorCodes::NamespaceExists) {
            LOGV2_FATAL(29124, "Failed to create collection", logAttrs(nss));
            fassertFailedWithStatus(29125, status);
        }
        auto prev = storageInterface->findSingleton(opCtx, nss);
        if (prev.getStatus() == ErrorCodes::CollectionIsEmpty) {
            _dbid.init();
            auto doc = BSON(kId << _dbid << kScheduledAt << _nextScrape);
            Timestamp noTimestamp;  // This write is not replicated
            // TODO: fassert can kill server?
            fassert(29127,
                    storageInterface->insertDocument(opCtx,
                                                     nss,
                                                     repl::TimestampedBSONObj{doc, noTimestamp},
                                                     repl::OpTime::kUninitializedTerm));
        } else if (prev.isOK()) {
            // copy scheduled time from BSONObj to nextScrape
            auto obj = prev.getValue();
            auto id = obj[kId];
            if (id.type() != BSONType::jstOID) {
                // TODO: report error, stop telemetry thread
            }
            _dbid = id.OID();
            _nextScrape = obj[kScheduledAt].Date();
        } else {
            fassertFailedWithStatus(29126, prev.getStatus());
        }

        // load cluster id
        OID clusterId;
        if (auto* grid = Grid::get(serviceContext)) {
            if (grid->isShardingInitialized()) {
                auto* catalogClient = grid->catalogClient();
                auto cfgVersion = catalogClient->getConfigVersion(
                    opCtx, repl::ReadConcernLevel::kMajorityReadConcern);
                if (cfgVersion.isOK()) {
                    clusterId = cfgVersion.getValue().getClusterId();
                }
            }
        }

        // initialize prefix
        _prefix = BSON(kDbInstanceId << _uuid.toString() << kPillarVersion
                                     << VersionInfoInterface::instance().makeVersionString(
                                            "Percona Server for MongoDB")
                                     << kClusterId << clusterId.toString());
    }

    // advance nextScrape and store it into kTelemetryNamespace
    void _advance(ServiceContext* serviceContext) {
        _nextScrape = Date_t::now() + Seconds(perconaTelemetryScrapeInterval);
        auto opCtxObj = cc().makeOperationContext();
        auto* opCtx = opCtxObj.get();
        repl::UnreplicatedWritesBlock uwb(opCtx);
        auto* storageInterface = repl::StorageInterface::get(serviceContext);
        const NamespaceString nss{kTelemetryNamespace};
        auto doc = BSON(kId << _dbid << kScheduledAt << _nextScrape);
        Timestamp noTimestamp;  // This write is not replicated
        // TODO: fassert can kill server?
        fassert(
            29128,
            storageInterface->putSingleton(opCtx, nss, repl::TimestampedBSONObj{doc, noTimestamp}));
    }

    // write metrics file
    void _writeMetrics(ServiceContext* serviceContext) {
        const auto ts = Date_t::now().toMillisSinceEpoch() / 1000;
        const auto instancePath = sdPath(kTelemetryPath) / _uuid.toString();
        // TODO: only create instance dir?
        boost::filesystem::create_directories(instancePath);

        // clear outdated files
        for (auto const& dirEntry : boost::filesystem::directory_iterator{instancePath}) {
            if (boost::filesystem::is_regular_file(dirEntry.status())) {
                auto s = dirEntry.path().filename().string();
                try {
                    std::size_t pos = 0;
                    if (std::stoll(s, &pos) < ts - perconaTelemetryHistoryKeepInterval &&
                        s.substr(pos) == ".json") {
                        boost::filesystem::remove(dirEntry.path());
                    }
                } catch (std::invalid_argument const&) {
                    // possible exception from std::stoll
                    // means file name does not match pattern
                } catch (std::out_of_range const&) {
                    // possible exception from std::stoll
                    // means file name does not match pattern
                } catch (const boost::filesystem::filesystem_error& e) {
                    LOGV2_DEBUG(29130,
                                1,
                                "Error removing file {file}: {errmsg}",
                                "file"_attr = dirEntry.path().string(),
                                "errmsg"_attr = e.what());
                }
            }
        }

        // dump new metrics file
        const auto tmpName = instancePath / fmt::format("{}.tmp", ts);
        LOGV2_DEBUG(29129, 1, "writing metrics file {path}", "path"_attr = tmpName.string());
        BSONObjBuilder builder(_prefix);

        // TODO: the next part is for debugging sharding/clusterId (remove after debug)
        if constexpr (false) {
            StringData v{"no grid"};
            if (auto* grid = Grid::get(serviceContext)) {
                v = boolName(grid->isShardingInitialized());
            }
            builder.append("isShardingInitialized", v);
        }

        builder.append(kStorageEngine, storageGlobalParams.engine);
        {
            auto* rs = repl::ReplicationCoordinator::get(serviceContext);
            builder.append(
                kReplicationEnabled,
                boolName(rs->getReplicationMode() == repl::ReplicationCoordinator::modeReplSet));
            builder.append(kReplicaSetId, rs->getConfig().getReplicaSetId().toString());
            builder.append(kReplMemberState, rs->getMemberState().toString());
        }
        builder.append(kClusterRole, clusterRoleName(serverGlobalParams.clusterRole));
        // TODO: append more metrics
        auto obj = builder.done();  // obj becomes invalid when builder goes out of scope
        std::ofstream ofs(tmpName);
        ofs << obj.jsonString(ExtendedCanonicalV2_0_0, 1 /* pretty */) << "\n";
        ofs.close();
        // tweak permissions if Telemetry Agent does not run as root
        // boost::filesystem::permissions(
        //    tmpName,
        //    boost::filesystem::owner_read | boost::filesystem::owner_write |
        //        boost::filesystem::group_read | boost::filesystem::group_write |
        //        boost::filesystem::others_read | boost::filesystem::others_write);
        boost::filesystem::rename(tmpName, instancePath / fmt::format("{}.json", ts));
    }

    AtomicWord<bool> _shuttingDown{false};

    Mutex _mutex = MONGO_MAKE_LATCH("TelemetryThread::_mutex");  // protects _condvar
    // The telemetry thread idles on this condition variable for a particular time duration
    // between creating metrics files. It can be triggered early to expediate shutdown.
    stdx::condition_variable _condvar;

    // instance id stored in kTelemetryFileName
    UUID _uuid = UUID::fromCDR(std::array<unsigned char, UUID::kNumBytes>{});

    // nextScarpe is set to "now + grace" in the constructor
    // but it is overwritten if we read scheduled time from kTelemetryNamespace
    Date_t _nextScrape;

    // database id stored as kTelemetryNamespace._id
    OID _dbid;
    // constant prefix for each metrics file
    BSONObj _prefix;
};

// start telemetry thread if it is not running
void startTelemetryThread_inlock(ServiceContext* serviceContext) {
    auto* telemetryThread = TelemetryThread::get(serviceContext);
    if (telemetryThread == nullptr) {
        auto telemetryThread = std::make_unique<TelemetryThread>();
        telemetryThread->go();
        TelemetryThread::set(serviceContext, std::move(telemetryThread));
    }
}

// stop telemetry thread if it is running
void stopTelemetryThread_inlock(ServiceContext* serviceContext) {
    auto* telemetryThread = TelemetryThread::get(serviceContext);
    if (telemetryThread != nullptr) {
        telemetryThread->shutdown();
    }
}

}  // namespace


void initPerconaTelemetry(ServiceContext* serviceContext) {
    stdx::unique_lock<Latch> lock(mutex);
    //  enable updates from server parameter
    updatesEnabled = true;
    // only create if telemetry is enabled
    if (ServerParameterSet::getNodeParameterSet()
            ->get<TelemetryParameter>(kParamName)
            ->_data.load()) {
        startTelemetryThread_inlock(serviceContext);
    }
}

void shutdownPerconaTelemetry(ServiceContext* serviceContext) {
    stdx::unique_lock<Latch> lock(mutex);
    // we do not allow any updates during shutdown
    updatesEnabled = false;
    stopTelemetryThread_inlock(serviceContext);
}

void updatePerconaTelemetry(bool state) {
    stdx::unique_lock<Latch> lock(mutex);
    if (updatesEnabled) {
        if (state) {
            startTelemetryThread_inlock(getGlobalServiceContext());
        } else {
            stopTelemetryThread_inlock(getGlobalServiceContext());
        }
    }
}

}  // namespace mongo
