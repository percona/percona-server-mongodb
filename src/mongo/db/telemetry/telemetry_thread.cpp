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

#include <boost/filesystem.hpp>  // IWYU pragma: keep
#include <cstddef>
#include <fmt/format.h>  // IWYU pragma: keep
#include <fstream>
#include <memory>
#include <stdexcept>
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
#include "mongo/bson/oid.h"
#include "mongo/db/client.h"
#include "mongo/db/cluster_role.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/operation_context.h"
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

// names of the fields in the metric file
constexpr StringData kDbInstanceId = "db_instance_id"_sd;
constexpr StringData kDbInternalId = "db_internal_id"_sd;
constexpr StringData kPillarVersion = "pillar_version"_sd;
constexpr StringData kProFeatures = "pro_features"_sd;
constexpr StringData kStorageEngine = "storage_engine"_sd;
constexpr StringData kReplicaSetId = "db_replication_id"_sd;
constexpr StringData kReplMemberState = "replication_state"_sd;
constexpr StringData kClusterId = "db_cluster_id"_sd;
constexpr StringData kShardSvr = "shard_svr"_sd;
constexpr StringData kConfigSvr = "config_svr"_sd;
constexpr StringData kUptime = "uptime"_sd;
constexpr StringData kSource = "source"_sd;


// We need this flag to filter out updates from server parameter which can arrive before global
// service context is set. In other words we need to avoid asserts from getGlobalServiceContext()
bool updatesEnabled = false;

// mutex to serialize external API calls and access to updatesEnabled
Mutex mutex = MONGO_MAKE_LATCH("TelemetryThread::mutex");

// auxiliary function
boost::filesystem::path sdPath(StringData sd) {
    return {sd.rawData(), sd.rawData() + sd.size()};  // NOLINT(*-pointer-arithmetic)
}

// auxiliary function
constexpr StringData boolName(bool v) {
    return v ? kTrue : kFalse;
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

        if (auto status = _initParameters(tc->getServiceContext()); !status.isOK()) {
            LOGV2_ERROR(29133,
                        "Telemetry thread failed to initialize. Telemetry will be stopped",
                        "status"_attr = status);
            _shuttingDown.store(true);
        }

        while (!_shuttingDown.load()) {
            if (Date_t::now() >= _nextScrape) {
                // cleanup telemetry dir
                if (auto status = _cleanupTelemetryDir(); !status.isOK()) {
                    LOGV2_WARNING(29132,
                                  "Telemetry thread failed to cleanup telemetry directory ",
                                  "status"_attr = status);
                }
                auto* serviceCtx = tc->getServiceContext();
                // create metrics file
                if (auto status = _writeMetrics(serviceCtx); !status.isOK()) {
                    LOGV2_WARNING(29131,
                                  "Telemetry thread failed to write metric file",
                                  "status"_attr = status);
                }
                // update nextScrape
                if (auto status = _advance(serviceCtx); !status.isOK()) {
                    LOGV2_ERROR(29128,
                                "Telemetry thread failed to schedule the next telemetry scrape and "
                                "will be stopped",
                                "status"_attr = status);
                    _shuttingDown.store(true);
                    continue;
                }
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
    Status _initParameters(ServiceContext* serviceContext) try {
        // on first start both instance Id and internal Id are initialized to the same value
        // after some events like backup/restore, dbpath change or cleanup those two Ids may become
        // not equal --> this is intended behavior
        auto initialId = OID::gen();

        // load/create instance id
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
        LOGV2_DEBUG(29123,
                    1,
                    "Initialized telemetry instance id: {db_instance_id}",
                    "db_instance_id"_attr = _instid.toString());

        // init unique metric file suffix
        // must go after instance id initialization
        if (_metricFileSuffix.empty()) {
            _metricFileSuffix = _instid.toString();
            // TODO: for mongos we should use somethign like this:
            //     _metricFileSuffix = initialId.toString();
            // but that will be in the specialized version of _initParameters for mongos
        }

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
        {
            BSONObjBuilder bson;
            bson.append(kDbInstanceId, _instid.toString());
            bson.append(kDbInternalId, _dbid.toString());
            const auto& vii = VersionInfoInterface::instance();
            bson.append(kPillarVersion, vii.version());
            bson.append(kProFeatures, vii.psmdbProFeatures());
            bson.append(kSource, "mongod"_sd);
            if (clusterId.isSet()) {
                bson.append(kClusterId, clusterId.toString());
                bson.append(kShardSvr,
                            boolName(serverGlobalParams.clusterRole.has(ClusterRole::ShardServer)));
                bson.append(
                    kConfigSvr,
                    boolName(serverGlobalParams.clusterRole.has(ClusterRole::ConfigServer)));
            }
            _prefix = bson.obj();
        }

        return Status::OK();
    } catch (...) {
        return exceptionToStatus();
    }

    // advance nextScrape and store it into kTelemetryNamespace
    Status _advance(ServiceContext* serviceContext) try {
        _nextScrape = Date_t::now() + Seconds(perconaTelemetryScrapeInterval);
        auto opCtxObj = cc().makeOperationContext();
        auto* opCtx = opCtxObj.get();
        repl::UnreplicatedWritesBlock uwb(opCtx);
        auto* storageInterface = repl::StorageInterface::get(serviceContext);
        const NamespaceString nss{kTelemetryNamespace};
        auto doc = BSON(kId << _dbid << kScheduledAt << _nextScrape);
        Timestamp noTimestamp;  // This write is not replicated
        return storageInterface->putSingleton(
            opCtx, nss, repl::TimestampedBSONObj{doc, noTimestamp});
    } catch (...) {
        return exceptionToStatus();
    }

    // cleanup telemetry directory
    Status _cleanupTelemetryDir() try {
        const auto ts = Date_t::now().toMillisSinceEpoch() / 1000;
        const auto telePath = sdPath(kTelemetryPath);
        // We do not create any directories
        if (auto status = boost::filesystem::status(telePath);
            !boost::filesystem::exists(status) || !boost::filesystem::is_directory(status)) {
            return {ErrorCodes::NonExistentPath,
                    fmt::format("telemetry directory doesn't exist or isn't a directory: {}",
                                kTelemetryPath)};
        }

        // clear outdated files
        auto suffix = fmt::format("-{}.json", _metricFileSuffix);
        const std::string jsonExt(".json");
        constexpr int perconaTelemetryHistoryOrphan = 60 * 60 * 24 * 7;
        for (auto const& dirEntry : boost::filesystem::directory_iterator{telePath}) {
            if (boost::filesystem::is_regular_file(dirEntry.status())) {
                auto s = dirEntry.path().filename().string();
                try {
                    std::size_t pos = 0;
                    const auto filets = std::stoll(s, &pos);
                    if ((filets < ts - perconaTelemetryHistoryKeepInterval &&
                         s.substr(pos) == suffix) ||
                        (filets < ts - perconaTelemetryHistoryOrphan && s.ends_with(jsonExt))) {
                        boost::filesystem::remove(dirEntry.path());
                    }
                } catch (std::invalid_argument const&) {  // NOLINT(*-empty-catch)
                    // possible exception from std::stoll
                    // means file name does not match pattern
                } catch (std::out_of_range const&) {  // NOLINT(*-empty-catch)
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
        return Status::OK();
    } catch (...) {
        return exceptionToStatus();
    }

    // write metrics file
    Status _writeMetrics(ServiceContext* serviceContext) try {
        const auto ts = Date_t::now().toMillisSinceEpoch() / 1000;
        const auto telePath = sdPath(kTelemetryPath);

        // dump new metrics file
        const auto tmpName = telePath / fmt::format("{}-{}.tmp", ts, _metricFileSuffix);
        LOGV2_DEBUG(29129, 1, "writing metrics file {path}", "path"_attr = tmpName.string());
        BSONObjBuilder builder(_prefix);


        builder.append(kUptime, std::to_string(time(nullptr) - serverGlobalParams.started));
        builder.append(kStorageEngine, storageGlobalParams.engine);
        if (auto* rs = repl::ReplicationCoordinator::get(serviceContext);
            rs->getReplicationMode() == repl::ReplicationCoordinator::modeReplSet) {
            builder.append(kReplicaSetId, rs->getConfig().getReplicaSetId().toString());
            builder.append(kReplMemberState, rs->getMemberState().toString());
        }
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
        boost::filesystem::rename(tmpName,
                                  telePath / fmt::format("{}-{}.json", ts, _metricFileSuffix));
        return Status::OK();
    } catch (...) {
        return exceptionToStatus();
    }

    // Used as suffix in metric file names.
    // Accessed only from the telemetry thread so synchronization is not necessary
    static std::string _metricFileSuffix;

    AtomicWord<bool> _shuttingDown{false};

    Mutex _mutex = MONGO_MAKE_LATCH("TelemetryThread::_mutex");  // protects _condvar
    // The telemetry thread idles on this condition variable for a particular time duration
    // between creating metrics files. It can be triggered early to expediate shutdown.
    stdx::condition_variable _condvar;

    // instance id stored in kTelemetryFileName
    OID _instid;

    // nextScarpe is set to "now + grace" in the constructor
    // but it is overwritten if we read scheduled time from kTelemetryNamespace
    Date_t _nextScrape;

    // database id stored as kTelemetryNamespace._id
    OID _dbid;
    // constant prefix for each metrics file
    BSONObj _prefix;
};

std::string TelemetryThread::_metricFileSuffix;

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
