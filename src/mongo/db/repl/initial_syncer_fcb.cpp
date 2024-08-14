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

#include "initial_syncer_fcb.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include <fmt/format.h>

#include "mongo/base/error_codes.h"
#include "mongo/base/status.h"
#include "mongo/bson/bsonmisc.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/bson/timestamp.h"
#include "mongo/client/dbclient_cursor.h"
#include "mongo/client/fetcher.h"
#include "mongo/client/remote_command_retry_scheduler.h"
#include "mongo/db/catalog/catalog_control.h"
#include "mongo/db/client.h"
#include "mongo/db/concurrency/d_concurrency.h"
#include "mongo/db/database_name.h"
#include "mongo/db/dbdirectclient.h"
#include "mongo/db/feature_compatibility_version_parser.h"
#include "mongo/db/index_builds_coordinator.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/pipeline/aggregate_command_gen.h"
#include "mongo/db/repl/all_database_cloner.h"
#include "mongo/db/repl/drop_pending_collection_reaper.h"
#include "mongo/db/repl/fcb_file_cloner.h"
#include "mongo/db/repl/initial_sync_state.h"
#include "mongo/db/repl/initial_syncer_common_stats.h"
#include "mongo/db/repl/initial_syncer_factory.h"
#include "mongo/db/repl/initial_syncer_interface.h"
#include "mongo/db/repl/optime.h"
#include "mongo/db/repl/repl_server_parameters_gen.h"
#include "mongo/db/repl/replication_auth.h"
#include "mongo/db/repl/replication_consistency_markers.h"
#include "mongo/db/repl/replication_coordinator.h"
#include "mongo/db/repl/replication_coordinator_external_state_impl.h"
#include "mongo/db/repl/replication_process.h"
#include "mongo/db/repl/storage_interface.h"
#include "mongo/db/repl/sync_source_selector.h"
#include "mongo/db/repl/tenant_migration_access_blocker_util.h"
#include "mongo/db/repl/transaction_oplog_application.h"
#include "mongo/db/server_options.h"
#include "mongo/db/serverless/serverless_operation_lock_registry.h"
#include "mongo/db/service_context.h"
#include "mongo/db/startup_recovery.h"
#include "mongo/db/storage/storage_engine.h"
#include "mongo/db/storage/storage_engine_init.h"
#include "mongo/db/storage/storage_options.h"
#include "mongo/executor/remote_command_request.h"
#include "mongo/executor/task_executor.h"
#include "mongo/logv2/log.h"
#include "mongo/platform/compiler.h"  // IWYU pragma: keep
#include "mongo/rpc/get_status_from_command_result.h"
#include "mongo/stdx/mutex.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/destructor_guard.h"
#include "mongo/util/fail_point.h"
#include "mongo/util/scopeguard.h"
#include "mongo/util/str.h"
#include "mongo/util/time_support.h"
#include "mongo/util/timer.h"
#include "mongo/util/version/releases.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kReplicationInitialSync


namespace mongo {
namespace repl {

// Failpoint for initial sync
MONGO_FAIL_POINT_DEFINE(failInitialSyncWithBadHostFCB);

// Failpoint which causes the initial sync function to hang before creating shared data and
// splitting control flow between the oplog fetcher and the cloners.
MONGO_FAIL_POINT_DEFINE(initialSyncHangBeforeSplittingControlFlowFCB);

// Failpoint which causes the initial sync function to hang before copying databases.
MONGO_FAIL_POINT_DEFINE(initialSyncHangBeforeCopyingDatabasesFCB);

// Failpoint which causes the initial sync function to hang before finishing.
MONGO_FAIL_POINT_DEFINE(initialSyncHangBeforeFinishFCB);

// Failpoint which causes the initial sync function to hang before creating the oplog.
MONGO_FAIL_POINT_DEFINE(initialSyncHangBeforeCreatingOplogFCB);

// Failpoint which skips clearing _initialSyncState after a successful initial sync attempt.
MONGO_FAIL_POINT_DEFINE(skipClearInitialSyncStateFCB);

// Failpoint which causes the initial sync function to fail and hang before starting a new attempt.
MONGO_FAIL_POINT_DEFINE(failAndHangInitialSyncFCB);

// Failpoint which causes the initial sync function to hang before choosing a sync source.
MONGO_FAIL_POINT_DEFINE(initialSyncHangBeforeChoosingSyncSourceFCB);

// Failpoint which causes the initial sync function to hang after finishing.
MONGO_FAIL_POINT_DEFINE(initialSyncHangAfterFinishFCB);

namespace {
using namespace executor;
using CallbackArgs = executor::TaskExecutor::CallbackArgs;
using Event = executor::TaskExecutor::EventHandle;
using Handle = executor::TaskExecutor::CallbackHandle;
using QueryResponseStatus = StatusWith<Fetcher::QueryResponse>;
using UniqueLock = stdx::unique_lock<Latch>;
using LockGuard = stdx::lock_guard<Latch>;

constexpr StringData kMetadataFieldName = "metadata"_sd;
constexpr StringData kBackupIdFieldName = "backupId"_sd;
constexpr StringData kDBPathFieldName = "dbpath"_sd;
constexpr StringData kFileNameFieldName = "filename"_sd;
constexpr StringData kFileSizeFieldName = "fileSize"_sd;

// Used to reset the oldest timestamp during initial sync to a non-null timestamp.
const Timestamp kTimestampOne(0, 1);

ServiceContext::UniqueOperationContext makeOpCtx() {
    return cc().makeOperationContext();
}

/**
 * Computes a boost::filesystem::path generic-style relative path (always uses slashes)
 * from a base path and a relative path.
 */
std::string getPathRelativeTo(const std::string& path, const std::string& basePath) {
    if (basePath.empty() || path.find(basePath) != 0) {
        uasserted(6113319,
                  str::stream() << "The file " << path << " is not a subdirectory of " << basePath);
    }

    auto result = path.substr(basePath.size());
    // Skip separators at the beginning of the relative part.
    if (!result.empty() && (result[0] == '/' || result[0] == '\\')) {
        result.erase(result.begin());
    }

    std::replace(result.begin(), result.end(), '\\', '/');
    return result;
}
}  // namespace

const ServiceContext::ConstructorActionRegisterer initialSyncerRegistererFCB(
    "InitialSyncerRegistererFCB",
    {"InitialSyncerFactoryRegisterer"} /* dependency list */,
    [](ServiceContext* service) {
        InitialSyncerFactory::get(service)->registerInitialSyncer(
            "fileCopyBased",
            [](InitialSyncerInterface::Options opts,
               std::unique_ptr<DataReplicatorExternalState> dataReplicatorExternalState,
               ThreadPool* writerPool,
               StorageInterface* storage,
               ReplicationProcess* replicationProcess,
               const InitialSyncerInterface::OnCompletionFn& onCompletion) {
                return std::make_shared<InitialSyncerFCB>(opts,
                                                          std::move(dataReplicatorExternalState),
                                                          writerPool,
                                                          storage,
                                                          replicationProcess,
                                                          onCompletion);
            });
    });

InitialSyncerFCB::InitialSyncerFCB(
    InitialSyncerInterface::Options opts,
    std::unique_ptr<DataReplicatorExternalState> dataReplicatorExternalState,
    ThreadPool* writerPool,
    StorageInterface* storage,
    ReplicationProcess* replicationProcess,
    const OnCompletionFn& onCompletion)
    : _fetchCount(0),
      _opts(opts),
      _dataReplicatorExternalState(std::move(dataReplicatorExternalState)),
      _exec(_dataReplicatorExternalState->getSharedTaskExecutor()),
      _clonerExec(_exec),
      _writerPool(writerPool),
      _storage(storage),
      _replicationProcess(replicationProcess),
      _backupId(UUID::fromCDR(std::array<unsigned char, 16>{})),
      _cfgDBPath(storageGlobalParams.dbpath),
      _onCompletion(onCompletion),
      _createClientFn(
          [] { return std::make_unique<DBClientConnection>(true /* autoReconnect */); }) {
    uassert(ErrorCodes::BadValue, "task executor cannot be null", _exec);
    uassert(ErrorCodes::BadValue, "invalid storage interface", _storage);
    uassert(ErrorCodes::BadValue, "invalid replication process", _replicationProcess);
    uassert(ErrorCodes::BadValue, "invalid getMyLastOptime function", _opts.getMyLastOptime);
    uassert(ErrorCodes::BadValue, "invalid setMyLastOptime function", _opts.setMyLastOptime);
    uassert(ErrorCodes::BadValue, "invalid resetOptimes function", _opts.resetOptimes);
    uassert(ErrorCodes::BadValue, "invalid sync source selector", _opts.syncSourceSelector);
    uassert(ErrorCodes::BadValue, "callback function cannot be null", _onCompletion);
}

InitialSyncerFCB::~InitialSyncerFCB() {
    DESTRUCTOR_GUARD({
        shutdown().transitional_ignore();
        join();
    });
}

bool InitialSyncerFCB::isActive() const {
    stdx::lock_guard<Latch> lock(_mutex);
    return _isActive_inlock();
}

bool InitialSyncerFCB::_isActive_inlock() const {
    return State::kRunning == _state || State::kShuttingDown == _state;
}

std::string InitialSyncerFCB::getInitialSyncMethod() const {
    return "logical";
}

Status InitialSyncerFCB::startup(OperationContext* opCtx,
                                 std::uint32_t initialSyncMaxAttempts) noexcept {
    invariant(opCtx);
    invariant(initialSyncMaxAttempts >= 1U);

    stdx::lock_guard<Latch> lock(_mutex);
    switch (_state) {
        case State::kPreStart:
            _state = State::kRunning;
            break;
        case State::kRunning:
            return {ErrorCodes::IllegalOperation, "initial syncer already started"};
        case State::kShuttingDown:
            return {ErrorCodes::ShutdownInProgress, "initial syncer shutting down"};
        case State::kComplete:
            return {ErrorCodes::ShutdownInProgress, "initial syncer completed"};
    }

    _setUp_inlock(opCtx, initialSyncMaxAttempts);

    // Start first initial sync attempt.
    std::uint32_t initialSyncAttempt = 0;
    _attemptExec = std::make_unique<executor::ScopedTaskExecutor>(
        _exec, Status(ErrorCodes::CallbackCanceled, "Initial Sync Attempt Canceled"));
    _clonerAttemptExec = std::make_unique<executor::ScopedTaskExecutor>(
        _clonerExec, Status(ErrorCodes::CallbackCanceled, "Initial Sync Attempt Canceled"));
    auto status = _scheduleWorkAndSaveHandle_inlock(
        [=](const executor::TaskExecutor::CallbackArgs& args) {
            _startInitialSyncAttemptCallback(args, initialSyncAttempt, initialSyncMaxAttempts);
        },
        &_startInitialSyncAttemptHandle,
        str::stream() << "_startInitialSyncAttemptCallback-" << initialSyncAttempt);

    if (!status.isOK()) {
        _state = State::kComplete;
        return status;
    }

    return Status::OK();
}

Status InitialSyncerFCB::shutdown() {
    stdx::lock_guard<Latch> lock(_mutex);
    switch (_state) {
        case State::kPreStart:
            // Transition directly from PreStart to Complete if not started yet.
            _state = State::kComplete;
            return Status::OK();
        case State::kRunning:
            _state = State::kShuttingDown;
            break;
        case State::kShuttingDown:
        case State::kComplete:
            // Nothing to do if we are already in ShuttingDown or Complete state.
            return Status::OK();
    }

    _cancelRemainingWork_inlock();

    return Status::OK();
}

void InitialSyncerFCB::cancelCurrentAttempt() {
    stdx::lock_guard lk(_mutex);
    if (_isActive_inlock()) {
        LOGV2_DEBUG(128419,
                    1,
                    "Cancelling the current initial sync attempt.",
                    "currentAttempt"_attr = _stats.failedInitialSyncAttempts + 1);
        _cancelRemainingWork_inlock();
    } else {
        LOGV2_DEBUG(128420,
                    1,
                    "There is no initial sync attempt to cancel because the initial syncer is not "
                    "currently active.");
    }
}

void InitialSyncerFCB::_cancelRemainingWork_inlock() {
    _cancelHandle_inlock(_startInitialSyncAttemptHandle);
    _cancelHandle_inlock(_chooseSyncSourceHandle);
    _cancelHandle_inlock(_getBaseRollbackIdHandle);
    _cancelHandle_inlock(_fetchBackupCursorHandle);
    _cancelHandle_inlock(_transferFileHandle);
    _cancelHandle_inlock(_currentHandle);
    _cancelHandle_inlock(_getLastRollbackIdHandle);

    if (_sharedData) {
        // We actually hold the required lock, but the lock object itself is not passed through.
        _clearRetriableError(WithLock::withoutLock());
        stdx::lock_guard<InitialSyncSharedData> lock(*_sharedData);
        _sharedData->setStatusIfOK(
            lock, Status{ErrorCodes::CallbackCanceled, "Initial sync attempt canceled"});
    }
    if (_client) {
        _client->shutdownAndDisallowReconnect();
    }
    _shutdownComponent_inlock(_applier);
    _shutdownComponent_inlock(_backupCursorFetcher);
    _shutdownComponent_inlock(_fCVFetcher);
    _shutdownComponent_inlock(_beginFetchingOpTimeFetcher);
    (*_attemptExec)->shutdown();
    (*_clonerAttemptExec)->shutdown();
    _attemptCanceled = true;
}

void InitialSyncerFCB::join() {
    stdx::unique_lock<Latch> lk(_mutex);
    _stateCondition.wait(lk, [this]() { return !_isActive_inlock(); });
}

InitialSyncerFCB::State InitialSyncerFCB::getState_forTest() const {
    stdx::lock_guard<Latch> lk(_mutex);
    return _state;
}

Date_t InitialSyncerFCB::getWallClockTime_forTest() const {
    stdx::lock_guard<Latch> lk(_mutex);
    return _lastApplied.wallTime;
}

void InitialSyncerFCB::setAllowedOutageDuration_forTest(Milliseconds allowedOutageDuration) {
    stdx::lock_guard<Latch> lk(_mutex);
    _allowedOutageDuration = allowedOutageDuration;
    if (_sharedData) {
        stdx::lock_guard<InitialSyncSharedData> lk(*_sharedData);
        _sharedData->setAllowedOutageDuration_forTest(lk, allowedOutageDuration);
    }
}

bool InitialSyncerFCB::_isShuttingDown() const {
    stdx::lock_guard<Latch> lock(_mutex);
    return _isShuttingDown_inlock();
}

bool InitialSyncerFCB::_isShuttingDown_inlock() const {
    return State::kShuttingDown == _state;
}

std::string InitialSyncerFCB::getDiagnosticString() const {
    LockGuard lk(_mutex);
    str::stream out;
    out << "InitialSyncerFCB -" << " active: " << _isActive_inlock()
        << " shutting down: " << _isShuttingDown_inlock();
    if (_initialSyncState) {
        out << " opsAppied: " << _initialSyncState->appliedOps;
    }

    return out;
}

BSONObj InitialSyncerFCB::getInitialSyncProgress() const {
    LockGuard lk(_mutex);

    // We return an empty BSON object after an initial sync attempt has been successfully
    // completed. When an initial sync attempt completes successfully, initialSyncCompletes is
    // incremented and then _initialSyncState is cleared. We check that _initialSyncState has been
    // cleared because an initial sync attempt can fail even after initialSyncCompletes is
    // incremented, and we also check that initialSyncCompletes is positive because an initial sync
    // attempt can also fail before _initialSyncState is initialized.
    if (!_initialSyncState && initial_sync_common_stats::initialSyncCompletes.get() > 0) {
        return {};
    }
    return _getInitialSyncProgress_inlock();
}

void InitialSyncerFCB::_appendInitialSyncProgressMinimal_inlock(BSONObjBuilder* bob) const {
    bob->append("method", "logical");
    _stats.append(bob);
    if (!_initialSyncState) {
        return;
    }
    if (_initialSyncState->allDatabaseCloner) {
        const auto allDbClonerStats = _initialSyncState->allDatabaseCloner->getStats();
        const auto approxTotalDataSize = allDbClonerStats.dataSize;
        bob->appendNumber("approxTotalDataSize", approxTotalDataSize);
        long long approxTotalBytesCopied = 0;
        for (auto const& dbClonerStats : allDbClonerStats.databaseStats) {
            for (auto const& collClonerStats : dbClonerStats.collectionStats) {
                approxTotalBytesCopied += collClonerStats.approxBytesCopied;
            }
        }
        bob->appendNumber("approxTotalBytesCopied", approxTotalBytesCopied);
        if (approxTotalBytesCopied > 0) {
            const auto statsObj = bob->asTempObj();
            auto totalInitialSyncElapsedMillis =
                statsObj.getField("totalInitialSyncElapsedMillis").safeNumberLong();
            const auto downloadRate =
                (double)totalInitialSyncElapsedMillis / (double)approxTotalBytesCopied;
            const auto remainingInitialSyncEstimatedMillis =
                downloadRate * (double)(approxTotalDataSize - approxTotalBytesCopied);
            bob->appendNumber("remainingInitialSyncEstimatedMillis",
                              (long long)remainingInitialSyncEstimatedMillis);
        }
    }
    bob->appendNumber("appliedOps", static_cast<long long>(_initialSyncState->appliedOps));
    if (!_initialSyncState->beginApplyingTimestamp.isNull()) {
        bob->append("initialSyncOplogStart", _initialSyncState->beginApplyingTimestamp);
    }
    // Only include the beginFetchingTimestamp if it's different from the beginApplyingTimestamp.
    if (!_initialSyncState->beginFetchingTimestamp.isNull() &&
        _initialSyncState->beginFetchingTimestamp != _initialSyncState->beginApplyingTimestamp) {
        bob->append("initialSyncOplogFetchingStart", _initialSyncState->beginFetchingTimestamp);
    }
    if (!_initialSyncState->stopTimestamp.isNull()) {
        bob->append("initialSyncOplogEnd", _initialSyncState->stopTimestamp);
    }
    if (_sharedData) {
        stdx::lock_guard<InitialSyncSharedData> sdLock(*_sharedData);
        auto unreachableSince = _sharedData->getSyncSourceUnreachableSince(sdLock);
        if (unreachableSince != Date_t()) {
            bob->append("syncSourceUnreachableSince", unreachableSince);
            bob->append("currentOutageDurationMillis",
                        durationCount<Milliseconds>(_sharedData->getCurrentOutageDuration(sdLock)));
        }
        bob->append("totalTimeUnreachableMillis",
                    durationCount<Milliseconds>(_sharedData->getTotalTimeUnreachable(sdLock)));
    }
}

BSONObj InitialSyncerFCB::_getInitialSyncProgress_inlock() const {
    try {
        BSONObjBuilder bob;
        _appendInitialSyncProgressMinimal_inlock(&bob);
        if (_initialSyncState) {
            if (_initialSyncState->allDatabaseCloner) {
                BSONObjBuilder dbsBuilder(bob.subobjStart("databases"));
                _initialSyncState->allDatabaseCloner->getStats().append(&dbsBuilder);
                dbsBuilder.doneFast();
            }
        }
        return bob.obj();
    } catch (const DBException& e) {
        LOGV2(128421,
              "Error creating initial sync progress object: {error}",
              "Error creating initial sync progress object",
              "error"_attr = e.toString());
    }
    BSONObjBuilder bob;
    _appendInitialSyncProgressMinimal_inlock(&bob);
    return bob.obj();
}

void InitialSyncerFCB::_setUp_inlock(OperationContext* opCtx,
                                     std::uint32_t initialSyncMaxAttempts) {
    // 'opCtx' is passed through from startup().
    _replicationProcess->getConsistencyMarkers()->clearInitialSyncId(opCtx);

    auto* serviceCtx = opCtx->getServiceContext();
    _storage->setInitialDataTimestamp(serviceCtx, Timestamp::kAllowUnstableCheckpointsSentinel);
    _storage->setStableTimestamp(serviceCtx, Timestamp::min());

    _stats.initialSyncStart = _exec->now();
    _stats.maxFailedInitialSyncAttempts = initialSyncMaxAttempts;
    _stats.failedInitialSyncAttempts = 0;
    _stats.exec = std::weak_ptr<executor::TaskExecutor>(_exec);

    _allowedOutageDuration = Seconds(initialSyncTransientErrorRetryPeriodSeconds.load());
}

void InitialSyncerFCB::_tearDown_inlock(OperationContext* opCtx,
                                        const StatusWith<OpTimeAndWallTime>& lastApplied) {
    _stats.initialSyncEnd = _exec->now();

    if (!lastApplied.isOK()) {
        return;
    }
    const auto lastAppliedOpTime = lastApplied.getValue().opTime;
    auto initialDataTimestamp = lastAppliedOpTime.getTimestamp();

    // A node coming out of initial sync must guarantee at least one oplog document is visible
    // such that others can sync from this node. Oplog visibility is only advanced when applying
    // oplog entries during initial sync. Correct the visibility to match the initial sync time
    // before transitioning to steady state replication.
    const bool orderedCommit = true;
    _storage->oplogDiskLocRegister(opCtx, initialDataTimestamp, orderedCommit);

    tenant_migration_access_blocker::recoverTenantMigrationAccessBlockers(opCtx);
    ServerlessOperationLockRegistry::recoverLocks(opCtx);
    reconstructPreparedTransactions(opCtx, repl::OplogApplication::Mode::kInitialSync);

    _replicationProcess->getConsistencyMarkers()->setInitialSyncIdIfNotSet(opCtx);

    _storage->setInitialDataTimestamp(opCtx->getServiceContext(), initialDataTimestamp);

    auto currentLastAppliedOpTime = _opts.getMyLastOptime();
    if (currentLastAppliedOpTime.isNull()) {
        _opts.setMyLastOptime(lastApplied.getValue());
    } else {
        invariant(currentLastAppliedOpTime == lastAppliedOpTime);
    }

    LOGV2(128422,
          "initial sync done; took "
          "{duration}.",
          "Initial sync done",
          "duration"_attr =
              duration_cast<Seconds>(_stats.initialSyncEnd - _stats.initialSyncStart));
    initial_sync_common_stats::initialSyncCompletes.increment();
}

void InitialSyncerFCB::_startInitialSyncAttemptCallback(
    const executor::TaskExecutor::CallbackArgs& callbackArgs,
    std::uint32_t initialSyncAttempt,
    std::uint32_t initialSyncMaxAttempts) noexcept {
    auto status = [&] {
        stdx::lock_guard<Latch> lock(_mutex);
        return _checkForShutdownAndConvertStatus_inlock(
            callbackArgs,
            str::stream() << "error while starting initial sync attempt "
                          << (initialSyncAttempt + 1) << " of " << initialSyncMaxAttempts);
    }();

    if (!status.isOK()) {
        _finishInitialSyncAttempt(status);
        return;
    }

    LOGV2(128423,
          "Starting initial sync (attempt {initialSyncAttempt} of {initialSyncMaxAttempts})",
          "Starting initial sync attempt",
          "initialSyncAttempt"_attr = (initialSyncAttempt + 1),
          "initialSyncMaxAttempts"_attr = initialSyncMaxAttempts);

    // This completion guard invokes _finishInitialSyncAttempt on destruction.
    auto cancelRemainingWorkInLock = [this]() {
        _cancelRemainingWork_inlock();
    };
    auto finishInitialSyncAttemptFn = [this](const StatusWith<OpTimeAndWallTime>& lastApplied) {
        _finishInitialSyncAttempt(lastApplied);
    };
    auto onCompletionGuard =
        std::make_shared<OnCompletionGuard>(cancelRemainingWorkInLock, finishInitialSyncAttemptFn);

    // Lock guard must be declared after completion guard because completion guard destructor
    // has to run outside lock.
    stdx::lock_guard<Latch> lock(_mutex);

    LOGV2_DEBUG(128424,
                2,
                "Resetting sync source so a new one can be chosen for this initial sync attempt");
    _syncSource = HostAndPort();

    LOGV2_DEBUG(128425, 2, "Resetting all optimes before starting this initial sync attempt");
    _opts.resetOptimes();
    _lastApplied = {OpTime(), Date_t()};
    _lastFetched = {};
    _backupCursorInfo.reset();

    LOGV2_DEBUG(
        128426, 2, "Resetting the oldest timestamp before starting this initial sync attempt");
    auto* storageEngine = getGlobalServiceContext()->getStorageEngine();
    if (storageEngine) {
        // Set the oldestTimestamp to one because WiredTiger does not allow us to set it to zero
        // since that would also set the all_durable point to zero. We specifically don't set
        // the stable timestamp here because that will trigger taking a first stable checkpoint even
        // though the initialDataTimestamp is still set to kAllowUnstableCheckpointsSentinel.
        storageEngine->setOldestTimestamp(kTimestampOne, true /*force*/);
    }

    LOGV2_DEBUG(128427,
                2,
                "Resetting feature compatibility version to last-lts. If the sync source is in "
                "latest feature compatibility version, we will find out when we clone the "
                "server configuration collection (admin.system.version)");
    serverGlobalParams.mutableFCV.reset();

    // Get sync source.
    std::uint32_t chooseSyncSourceAttempt = 0;
    std::uint32_t chooseSyncSourceMaxAttempts =
        static_cast<std::uint32_t>(numInitialSyncConnectAttempts.load());

    // _scheduleWorkAndSaveHandle_inlock() is shutdown-aware.
    status = _scheduleWorkAndSaveHandle_inlock(
        [=](const executor::TaskExecutor::CallbackArgs& args) {
            _chooseSyncSourceCallback(
                args, chooseSyncSourceAttempt, chooseSyncSourceMaxAttempts, onCompletionGuard);
        },
        &_chooseSyncSourceHandle,
        str::stream() << "_chooseSyncSourceCallback-" << chooseSyncSourceAttempt);
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }
}

void InitialSyncerFCB::_chooseSyncSourceCallback(
    const executor::TaskExecutor::CallbackArgs& callbackArgs,
    std::uint32_t chooseSyncSourceAttempt,
    std::uint32_t chooseSyncSourceMaxAttempts,
    std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept try {
    if (MONGO_unlikely(initialSyncHangBeforeChoosingSyncSourceFCB.shouldFail())) {
        LOGV2(128428, "initialSyncHangBeforeChoosingSyncSourceFCB fail point enabled");
        initialSyncHangBeforeChoosingSyncSourceFCB.pauseWhileSet();
    }

    stdx::unique_lock<Latch> lock(_mutex);
    // Cancellation should be treated the same as other errors. In this case, the most likely cause
    // of a failed _chooseSyncSourceCallback() task is a cancellation triggered by
    // InitialSyncerFCB::shutdown() or the task executor shutting down.
    auto status =
        _checkForShutdownAndConvertStatus_inlock(callbackArgs, "error while choosing sync source");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    if (MONGO_unlikely(failInitialSyncWithBadHostFCB.shouldFail())) {
        status = Status(ErrorCodes::InvalidSyncSource,
                        "initial sync failed - failInitialSyncWithBadHostFCB failpoint is set.");
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    auto syncSource = _chooseSyncSource_inlock();
    if (!syncSource.isOK()) {
        if (chooseSyncSourceAttempt + 1 >= chooseSyncSourceMaxAttempts) {
            onCompletionGuard->setResultAndCancelRemainingWork_inlock(
                lock,
                Status(ErrorCodes::InitialSyncOplogSourceMissing,
                       "No valid sync source found in current replica set to do an initial sync."));
            return;
        }

        auto when = (*_attemptExec)->now() + _opts.syncSourceRetryWait;
        LOGV2_DEBUG(128429,
                    1,
                    "Error getting sync source: '{error}', trying again in "
                    "{syncSourceRetryWait} at {retryTime}. Attempt {chooseSyncSourceAttempt} of "
                    "{numInitialSyncConnectAttempts}",
                    "Error getting sync source. Waiting to retry",
                    "error"_attr = syncSource.getStatus(),
                    "syncSourceRetryWait"_attr = _opts.syncSourceRetryWait,
                    "retryTime"_attr = when.toString(),
                    "chooseSyncSourceAttempt"_attr = (chooseSyncSourceAttempt + 1),
                    "numInitialSyncConnectAttempts"_attr = numInitialSyncConnectAttempts.load());
        auto status = _scheduleWorkAtAndSaveHandle_inlock(
            when,
            [=](const executor::TaskExecutor::CallbackArgs& args) {
                _chooseSyncSourceCallback(args,
                                          chooseSyncSourceAttempt + 1,
                                          chooseSyncSourceMaxAttempts,
                                          onCompletionGuard);
            },
            &_chooseSyncSourceHandle,
            str::stream() << "_chooseSyncSourceCallback-" << (chooseSyncSourceAttempt + 1));
        if (!status.isOK()) {
            onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
            return;
        }
        return;
    }

    if (MONGO_unlikely(initialSyncHangBeforeCreatingOplogFCB.shouldFail())) {
        // This log output is used in js tests so please leave it.
        LOGV2(128430,
              "initial sync - initialSyncHangBeforeCreatingOplogFCB fail point "
              "enabled. Blocking until fail point is disabled.");
        lock.unlock();
        while (MONGO_unlikely(initialSyncHangBeforeCreatingOplogFCB.shouldFail()) &&
               !_isShuttingDown()) {
            mongo::sleepsecs(1);
        }
        lock.lock();
    }

    // There is no need to schedule separate task to create oplog collection since we are already in
    // a callback and we are certain there's no existing operation context (required for creating
    // collections and dropping user databases) attached to the current thread.
    status = _truncateOplogAndDropReplicatedDatabases();
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    _syncSource = syncSource.getValue();

    // Schedule rollback ID checker.
    _rollbackChecker = std::make_unique<RollbackChecker>(*_attemptExec, _syncSource);
    auto scheduleResult = _rollbackChecker->reset([=](const RollbackChecker::Result& result) {
        return _rollbackCheckerResetCallback(result, onCompletionGuard);
    });
    status = scheduleResult.getStatus();
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }
    _getBaseRollbackIdHandle = scheduleResult.getValue();
} catch (const DBException&) {
    // Report exception as an initial syncer failure.
    stdx::unique_lock<Latch> lock(_mutex);
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
}

// TODO: we probably don't need this in FCBIS
Status InitialSyncerFCB::_truncateOplogAndDropReplicatedDatabases() {
    // truncate oplog; drop user databases.
    LOGV2_DEBUG(128431,
                1,
                "About to truncate the oplog, if it exists, ns:{namespace}, and drop all "
                "user databases (so that we can clone them).",
                "About to truncate the oplog, if it exists, and drop all user databases (so that "
                "we can clone them)",
                logAttrs(NamespaceString::kRsOplogNamespace));

    auto opCtx = makeOpCtx();
    // This code can make untimestamped writes (deletes) to the _mdb_catalog on top of existing
    // timestamped updates.
    opCtx->recoveryUnit()->allowAllUntimestampedWrites();

    // We are not replicating nor validating these writes.
    UnreplicatedWritesBlock unreplicatedWritesBlock(opCtx.get());

    // 1.) Truncate the oplog.
    LOGV2_DEBUG(128432,
                2,
                "Truncating the existing oplog: {namespace}",
                "Truncating the existing oplog",
                logAttrs(NamespaceString::kRsOplogNamespace));
    Timer timer;
    auto status = _storage->truncateCollection(opCtx.get(), NamespaceString::kRsOplogNamespace);
    LOGV2(128433,
          "Initial syncer oplog truncation finished in: {durationMillis}ms",
          "Initial syncer oplog truncation finished",
          "durationMillis"_attr = timer.millis());
    if (!status.isOK()) {
        // 1a.) Create the oplog.
        LOGV2_DEBUG(128434,
                    2,
                    "Creating the oplog: {namespace}",
                    "Creating the oplog",
                    logAttrs(NamespaceString::kRsOplogNamespace));
        status = _storage->createOplog(opCtx.get(), NamespaceString::kRsOplogNamespace);
        if (!status.isOK()) {
            return status;
        }
    }

    // 2a.) Abort any index builds started during initial sync.
    IndexBuildsCoordinator::get(opCtx.get())
        ->abortAllIndexBuildsForInitialSync(opCtx.get(), "Aborting index builds for initial sync");

    // 2b.) Drop user databases.
    LOGV2_DEBUG(128435, 2, "Dropping user databases");
    return _storage->dropReplicatedDatabases(opCtx.get());
}

void InitialSyncerFCB::_rollbackCheckerResetCallback(
    const RollbackChecker::Result& result, std::shared_ptr<OnCompletionGuard> onCompletionGuard) {
    stdx::lock_guard<Latch> lock(_mutex);
    auto status = _checkForShutdownAndConvertStatus_inlock(result.getStatus(),
                                                           "error while getting base rollback ID");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    // we will need shared data to clone files from sync source
    _sharedData =
        std::make_unique<InitialSyncSharedData>(_rollbackChecker->getBaseRBID(),
                                                _allowedOutageDuration,
                                                getGlobalServiceContext()->getFastClockSource());
    _client = _createClientFn();

    // schedule $backupCursor on the sync source
    status = _scheduleWorkAndSaveHandle_inlock(
        [this, onCompletionGuard](const executor::TaskExecutor::CallbackArgs& args) {
            _fetchBackupCursorCallback(args, onCompletionGuard);
        },
        &_fetchBackupCursorHandle,
        "_fetchBackupCursorCallback");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }
}

void InitialSyncerFCB::_fcvFetcherCallback(const StatusWith<Fetcher::QueryResponse>& result,
                                           std::shared_ptr<OnCompletionGuard> onCompletionGuard,
                                           const OpTime& lastOpTime,
                                           OpTime& beginFetchingOpTime) {
    stdx::unique_lock<Latch> lock(_mutex);
    auto status = _checkForShutdownAndConvertStatus_inlock(
        result.getStatus(), "error while getting the remote feature compatibility version");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    const auto docs = result.getValue().documents;
    if (docs.size() > 1) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(
            lock,
            Status(ErrorCodes::TooManyMatchingDocuments,
                   str::stream() << "Expected to receive one feature compatibility version "
                                    "document, but received: "
                                 << docs.size() << ". First: " << redact(docs.front())
                                 << ". Last: " << redact(docs.back())));
        return;
    }
    const auto hasDoc = docs.begin() != docs.end();
    if (!hasDoc) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(
            lock,
            Status(ErrorCodes::IncompatibleServerVersion,
                   "Sync source had no feature compatibility version document"));
        return;
    }

    auto fCVParseSW = FeatureCompatibilityVersionParser::parse(docs.front());
    if (!fCVParseSW.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, fCVParseSW.getStatus());
        return;
    }

    auto version = fCVParseSW.getValue();

    // Changing the featureCompatibilityVersion during initial sync is unsafe.
    // (Generic FCV reference): This FCV check should exist across LTS binary versions.
    if (serverGlobalParams.featureCompatibility.acquireFCVSnapshot().isUpgradingOrDowngrading(
            version)) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(
            lock,
            Status(ErrorCodes::IncompatibleServerVersion,
                   str::stream() << "Sync source had unsafe feature compatibility version: "
                                 << multiversion::toString(version)));
        return;
    } else {
        // Since we don't guarantee that we always clone the "admin.system.version" collection first
        // and collection/index creation can depend on FCV, we set the in-memory FCV value to match
        // the version on the sync source. We won't persist the FCV on disk nor will we update our
        // minWireVersion until we clone the actual document.
        serverGlobalParams.mutableFCV.setVersion(version);
    }

    if (MONGO_unlikely(initialSyncHangBeforeSplittingControlFlowFCB.shouldFail())) {
        lock.unlock();
        LOGV2(128436,
              "initial sync - initialSyncHangBeforeSplittingControlFlowFCB fail point "
              "enabled. Blocking until fail point is disabled.");
        while (MONGO_unlikely(initialSyncHangBeforeSplittingControlFlowFCB.shouldFail()) &&
               !_isShuttingDown()) {
            mongo::sleepsecs(1);
        }
        lock.lock();
    }

    // This is where the flow of control starts to split into two parallel tracks:
    // - oplog fetcher
    // - data cloning and applier
    _sharedData =
        std::make_unique<InitialSyncSharedData>(_rollbackChecker->getBaseRBID(),
                                                _allowedOutageDuration,
                                                getGlobalServiceContext()->getFastClockSource());
    _client = _createClientFn();
    _initialSyncState = std::make_unique<InitialSyncState>(std::make_unique<AllDatabaseCloner>(
        _sharedData.get(), _syncSource, _client.get(), _storage, _writerPool));

    _initialSyncState->beginApplyingTimestamp = lastOpTime.getTimestamp();
    _initialSyncState->beginFetchingTimestamp = beginFetchingOpTime.getTimestamp();

    invariant(_initialSyncState->beginApplyingTimestamp >=
                  _initialSyncState->beginFetchingTimestamp,
              str::stream() << "beginApplyingTimestamp was less than beginFetchingTimestamp. "
                               "beginApplyingTimestamp: "
                            << _initialSyncState->beginApplyingTimestamp.toBSON()
                            << " beginFetchingTimestamp: "
                            << _initialSyncState->beginFetchingTimestamp.toBSON());

    invariant(!result.getValue().documents.empty());
    LOGV2_DEBUG(128437,
                2,
                "Setting begin applying timestamp to {beginApplyingTimestamp}, ns: "
                "{namespace} and the begin fetching timestamp to {beginFetchingTimestamp}",
                "Setting begin applying timestamp and begin fetching timestamp",
                "beginApplyingTimestamp"_attr = _initialSyncState->beginApplyingTimestamp,
                logAttrs(NamespaceString::kRsOplogNamespace),
                "beginFetchingTimestamp"_attr = _initialSyncState->beginFetchingTimestamp);

    const auto configResult = _dataReplicatorExternalState->getCurrentConfig();
    status = configResult.getStatus();
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        _initialSyncState.reset();
        return;
    }

    if (MONGO_unlikely(initialSyncHangBeforeCopyingDatabasesFCB.shouldFail())) {
        lock.unlock();
        // This could have been done with a scheduleWorkAt but this is used only by JS tests where
        // we run with multiple threads so it's fine to spin on this thread.
        // This log output is used in js tests so please leave it.
        LOGV2(128438,
              "initial sync - initialSyncHangBeforeCopyingDatabasesFCB fail point "
              "enabled. Blocking until fail point is disabled.");
        while (MONGO_unlikely(initialSyncHangBeforeCopyingDatabasesFCB.shouldFail()) &&
               !_isShuttingDown()) {
            mongo::sleepsecs(1);
        }
        lock.lock();
    }

    lock.unlock();
}

void InitialSyncerFCB::_finishInitialSyncAttempt(const StatusWith<OpTimeAndWallTime>& lastApplied) {
    // Since _finishInitialSyncAttempt can be called from any component's callback function or
    // scheduled task, it is possible that we may not be in a TaskExecutor-managed thread when this
    // function is invoked.
    // For example, if CollectionCloner fails while inserting documents into the
    // CollectionBulkLoader, we will get here via one of CollectionCloner's TaskRunner callbacks
    // which has an active OperationContext bound to the current Client. This would lead to an
    // invariant when we attempt to create a new OperationContext for _tearDown(opCtx).
    // To avoid this, we schedule _finishCallback against the TaskExecutor rather than calling it
    // here synchronously.

    // Unless dismissed, a scope guard will schedule _finishCallback() upon exiting this function.
    // Since it is a requirement that _finishCallback be called outside the lock (which is possible
    // if the task scheduling fails and we have to invoke _finishCallback() synchronously), we
    // declare the scope guard before the lock guard.
    auto result = lastApplied;
    ScopeGuard finishCallbackGuard([this, &result] {
        auto scheduleResult = _exec->scheduleWork(
            [=](const mongo::executor::TaskExecutor::CallbackArgs&) { _finishCallback(result); });
        if (!scheduleResult.isOK()) {
            LOGV2_WARNING(128439,
                          "Unable to schedule initial syncer completion task due to "
                          "{error}. Running callback on current thread.",
                          "Unable to schedule initial syncer completion task. Running callback on "
                          "current thread",
                          "error"_attr = redact(scheduleResult.getStatus()));
            _finishCallback(result);
        }
    });

    LOGV2(128440, "Initial sync attempt finishing up");

    stdx::lock_guard<Latch> lock(_mutex);

    auto runTime = _initialSyncState ? _initialSyncState->timer.millis() : 0;
    int rollBackId = -1;
    int operationsRetried = 0;
    int totalTimeUnreachableMillis = 0;
    if (_sharedData) {
        stdx::lock_guard<InitialSyncSharedData> sdLock(*_sharedData);
        rollBackId = _sharedData->getRollBackId();
        operationsRetried = _sharedData->getTotalRetries(sdLock);
        totalTimeUnreachableMillis =
            durationCount<Milliseconds>(_sharedData->getTotalTimeUnreachable(sdLock));
    }

    if (MONGO_unlikely(failAndHangInitialSyncFCB.shouldFail())) {
        LOGV2(128441, "failAndHangInitialSyncFCB fail point enabled");
        failAndHangInitialSyncFCB.pauseWhileSet();
        result = Status(ErrorCodes::InternalError, "failAndHangInitialSyncFCB fail point enabled");
    }

    _stats.initialSyncAttemptInfos.emplace_back(
        InitialSyncerFCB::InitialSyncAttemptInfo{runTime,
                                                 result.getStatus(),
                                                 _syncSource,
                                                 rollBackId,
                                                 operationsRetried,
                                                 totalTimeUnreachableMillis});

    if (!result.isOK()) {
        // This increments the number of failed attempts for the current initial sync request.
        ++_stats.failedInitialSyncAttempts;
        // This increments the number of failed attempts across all initial sync attempts since
        // process startup.
        initial_sync_common_stats::initialSyncFailedAttempts.increment();
    }

    bool hasRetries = _stats.failedInitialSyncAttempts < _stats.maxFailedInitialSyncAttempts;

    initial_sync_common_stats::LogInitialSyncAttemptStats(
        result, hasRetries, _getInitialSyncProgress_inlock());

    if (result.isOK()) {
        // Scope guard will invoke _finishCallback().
        return;
    }

    LOGV2_ERROR(128442,
                "Initial sync attempt failed -- attempts left: "
                "{attemptsLeft} cause: "
                "{error}",
                "Initial sync attempt failed",
                "attemptsLeft"_attr =
                    (_stats.maxFailedInitialSyncAttempts - _stats.failedInitialSyncAttempts),
                "error"_attr = redact(result.getStatus()));

    // Check if need to do more retries.
    if (!hasRetries) {
        LOGV2_FATAL_CONTINUE(128443,
                             "The maximum number of retries have been exhausted for initial sync");

        initial_sync_common_stats::initialSyncFailures.increment();

        // Scope guard will invoke _finishCallback().
        return;
    }

    _attemptExec = std::make_unique<executor::ScopedTaskExecutor>(
        _exec, Status(ErrorCodes::CallbackCanceled, "Initial Sync Attempt Canceled"));
    _clonerAttemptExec = std::make_unique<executor::ScopedTaskExecutor>(
        _clonerExec, Status(ErrorCodes::CallbackCanceled, "Initial Sync Attempt Canceled"));
    _attemptCanceled = false;
    auto when = (*_attemptExec)->now() + _opts.initialSyncRetryWait;
    auto status = _scheduleWorkAtAndSaveHandle_inlock(
        when,
        [=](const executor::TaskExecutor::CallbackArgs& args) {
            _startInitialSyncAttemptCallback(
                args, _stats.failedInitialSyncAttempts, _stats.maxFailedInitialSyncAttempts);
        },
        &_startInitialSyncAttemptHandle,
        str::stream() << "_startInitialSyncAttemptCallback-" << _stats.failedInitialSyncAttempts);

    if (!status.isOK()) {
        result = status;
        // Scope guard will invoke _finishCallback().
        return;
    }

    // Next initial sync attempt scheduled successfully and we do not need to call _finishCallback()
    // until the next initial sync attempt finishes.
    finishCallbackGuard.dismiss();
}

void InitialSyncerFCB::_finishCallback(StatusWith<OpTimeAndWallTime> lastApplied) {
    // After running callback function, clear '_onCompletion' to release any resources that might be
    // held by this function object.
    // '_onCompletion' must be moved to a temporary copy and destroyed outside the lock in case
    // there is any logic that's invoked at the function object's destruction that might call into
    // this InitialSyncerFCB. 'onCompletion' must be destroyed outside the lock and this should
    // happen before we transition the state to Complete.
    decltype(_onCompletion) onCompletion;
    {
        stdx::lock_guard<Latch> lock(_mutex);
        auto opCtx = makeOpCtx();
        _tearDown_inlock(opCtx.get(), lastApplied);
        invariant(_onCompletion);
        std::swap(_onCompletion, onCompletion);
    }

    if (MONGO_unlikely(initialSyncHangBeforeFinishFCB.shouldFail())) {
        // This log output is used in js tests so please leave it.
        LOGV2(128444,
              "initial sync - initialSyncHangBeforeFinishFCB fail point "
              "enabled. Blocking until fail point is disabled.");
        while (MONGO_unlikely(initialSyncHangBeforeFinishFCB.shouldFail()) && !_isShuttingDown()) {
            mongo::sleepsecs(1);
        }
    }

    // Any _retryingOperation is no longer active.  This must be done before signalling state
    // Complete.
    _retryingOperation = boost::none;

    // Completion callback must be invoked outside mutex.
    try {
        onCompletion(lastApplied);
    } catch (...) {
        LOGV2_WARNING(128445,
                      "initial syncer finish callback threw exception: {error}",
                      "Initial syncer finish callback threw exception",
                      "error"_attr = redact(exceptionToStatus()));
    }

    // Destroy the remaining reference to the completion callback before we transition the state to
    // Complete so that callers can expect any resources bound to '_onCompletion' to be released
    // before InitialSyncerFCB::join() returns.
    onCompletion = {};

    {
        stdx::lock_guard<Latch> lock(_mutex);
        invariant(_state != State::kComplete);
        _state = State::kComplete;
        _stateCondition.notify_all();

        // Clear the initial sync progress after an initial sync attempt has been successfully
        // completed.
        if (lastApplied.isOK() && !MONGO_unlikely(skipClearInitialSyncStateFCB.shouldFail())) {
            _initialSyncState.reset();
        }

        // Destroy shared references to executors.
        _attemptExec = nullptr;
        _clonerAttemptExec = nullptr;
        _clonerExec = nullptr;
        _exec = nullptr;
    }

    if (MONGO_unlikely(initialSyncHangAfterFinishFCB.shouldFail())) {
        LOGV2(128446,
              "initial sync finished - initialSyncHangAfterFinishFCB fail point "
              "enabled. Blocking until fail point is disabled.");
        while (MONGO_unlikely(initialSyncHangAfterFinishFCB.shouldFail()) && !_isShuttingDown()) {
            mongo::sleepsecs(1);
        }
    }
}

bool InitialSyncerFCB::_shouldRetryError(WithLock lk, Status status) {
    if (ErrorCodes::isRetriableError(status)) {
        stdx::lock_guard<InitialSyncSharedData> sharedDataLock(*_sharedData);
        return _sharedData->shouldRetryOperation(sharedDataLock, &_retryingOperation);
    }
    // The status was OK or some error other than a retriable error, so clear the retriable error
    // state and indicate that we should not retry.
    _clearRetriableError(lk);
    return false;
}

void InitialSyncerFCB::_clearRetriableError(WithLock lk) {
    _retryingOperation = boost::none;
}

Status InitialSyncerFCB::_checkForShutdownAndConvertStatus_inlock(
    const executor::TaskExecutor::CallbackArgs& callbackArgs, const std::string& message) {
    return _checkForShutdownAndConvertStatus_inlock(callbackArgs.status, message);
}

Status InitialSyncerFCB::_checkForShutdownAndConvertStatus_inlock(const Status& status,
                                                                  const std::string& message) {

    if (_isShuttingDown_inlock()) {
        return {ErrorCodes::CallbackCanceled, message + ": initial syncer is shutting down"};
    }

    return status.withContext(message);
}

Status InitialSyncerFCB::_scheduleWorkAndSaveHandle_inlock(
    executor::TaskExecutor::CallbackFn work,
    executor::TaskExecutor::CallbackHandle* handle,
    const std::string& name) {
    invariant(handle);
    if (_isShuttingDown_inlock()) {
        return {ErrorCodes::CallbackCanceled,
                str::stream() << "failed to schedule work " << name
                              << ": initial syncer is shutting down"};
    }
    auto result = (*_attemptExec)->scheduleWork(std::move(work));
    if (!result.isOK()) {
        return result.getStatus().withContext(str::stream() << "failed to schedule work " << name);
    }
    *handle = result.getValue();
    return Status::OK();
}

Status InitialSyncerFCB::_scheduleWorkAtAndSaveHandle_inlock(
    Date_t when,
    executor::TaskExecutor::CallbackFn work,
    executor::TaskExecutor::CallbackHandle* handle,
    const std::string& name) {
    invariant(handle);
    if (_isShuttingDown_inlock()) {
        return {ErrorCodes::CallbackCanceled,
                str::stream() << "failed to schedule work " << name << " at " << when.toString()
                              << ": initial syncer is shutting down"};
    }
    auto result = (*_attemptExec)->scheduleWorkAt(when, std::move(work));
    if (!result.isOK()) {
        return result.getStatus().withContext(str::stream() << "failed to schedule work " << name
                                                            << " at " << when.toString());
    }
    *handle = result.getValue();
    return Status::OK();
}

void InitialSyncerFCB::_cancelHandle_inlock(executor::TaskExecutor::CallbackHandle handle) {
    if (!handle) {
        return;
    }
    (*_attemptExec)->cancel(handle);
}

template <typename Component>
Status InitialSyncerFCB::_startupComponent_inlock(Component& component) {
    // It is necessary to check if shutdown or attempt cancelling happens before starting a
    // component; otherwise the component may call a callback function in line which will
    // cause a deadlock when the callback attempts to obtain the initial syncer mutex.
    if (_isShuttingDown_inlock() || _attemptCanceled) {
        component.reset();
        if (_isShuttingDown_inlock()) {
            return {ErrorCodes::CallbackCanceled,
                    "initial syncer shutdown while trying to call startup() on component"};
        } else {
            return {ErrorCodes::CallbackCanceled,
                    "initial sync attempt canceled while trying to call startup() on component"};
        }
    }
    auto status = component->startup();
    if (!status.isOK()) {
        component.reset();
    }
    return status;
}

template <typename Component>
void InitialSyncerFCB::_shutdownComponent_inlock(Component& component) {
    if (!component) {
        return;
    }
    component->shutdown();
}

StatusWith<HostAndPort> InitialSyncerFCB::_chooseSyncSource_inlock() {
    auto syncSource = _opts.syncSourceSelector->chooseNewSyncSource(_lastFetched);
    if (syncSource.empty()) {
        return Status{ErrorCodes::InvalidSyncSource,
                      str::stream() << "No valid sync source available. Our last fetched optime: "
                                    << _lastFetched.toString()};
    }
    return syncSource;
}

namespace {

constexpr int kBackupCursorFileFetcherRetryAttempts = 10;

BSONObj makeBackupCursorCmd() {
    BSONArrayBuilder pipelineBuilder;
    pipelineBuilder << BSON("$backupCursor" << BSONObj());
    return BSON("aggregate" << 1 << "pipeline" << pipelineBuilder.arr() << "cursor" << BSONObj());
}

AggregateCommandRequest makeBackupCursorRequest() {
    return {NamespaceString::makeCollectionlessAggregateNSS(DatabaseName::kAdmin),
            {BSON("$backupCursor" << BSONObj())}};
}

}  // namespace

// clean local files in the dbpath
Status InitialSyncerFCB::_deleteLocalFiles() {
    // list of files is in the _localFiles vector of std::string
    for (const auto& path : _localFiles) {
        boost::system::error_code ec;
        boost::filesystem::remove(path, ec);
        if (ec) {
            return {ErrorCodes::InternalError,
                    "Error deleting file '{}': {}"_format(path, ec.message())};
        }
    }
    return Status::OK();
}

// function to move files from one directory to another
// excluding .dummy subdirectory
Status InitialSyncerFCB::_moveFiles(const boost::filesystem::path& sourceDir,
                                    const boost::filesystem::path& destDir) {
    namespace fs = boost::filesystem;

    const fs::path excluded{".dummy"};
    try {
        std::vector<fs::path> files;
        // populate files list and create directory structure under destDir
        for (auto it = fs::recursive_directory_iterator(sourceDir);
             it != fs::recursive_directory_iterator();
             ++it) {
            if (fs::is_regular_file(it->status())) {
                // TODO: filter some files
                // push into the list
                files.push_back(it->path());
            } else if (fs::is_directory(it->status())) {
                auto relPath = fs::relative(it->path(), sourceDir);
                if (excluded == relPath) {
                    it.disable_recursion_pending();
                } else {
                    fs::create_directories(destDir / relPath);
                }
            }
        }
        // move files from the list
        for (const auto& sourcePath : files) {
            auto destPath = destDir / fs::relative(sourcePath, sourceDir);
            fs::rename(sourcePath, destPath);
        }

        return Status::OK();
    } catch (const fs::filesystem_error& e) {
        return Status(ErrorCodes::UnknownError, e.what());
    }
}

// Open a local backup cursor and obtain a list of files from that.
StatusWith<std::vector<std::string>> InitialSyncerFCB::_getBackupFiles() {
    std::vector<std::string> files;
    try {
        // Open a local backup cursor and obtain a list of files from that.

        // Try to use DBDirectClient
        auto opCtx = makeOpCtx();
        DBDirectClient client(opCtx.get());
        auto cursor = uassertStatusOK(DBClientCursor::fromAggregationRequest(
            &client, makeBackupCursorRequest(), true /* secondaryOk */, false /* useExhaust */));
        if (cursor->more()) {
            auto metadata = cursor->next();
            files.reserve(cursor->objsLeftInBatch());
        }
        while (cursor->more()) {
            auto rec = cursor->next();
            files.emplace_back(rec[kFileNameFieldName].String());
        }

        // Close cursor
        cursor->kill();
    } catch (const DBException& e) {
        return e.toStatus();
    }
    return files;
}

// Switch storage location
Status InitialSyncerFCB::_switchStorageLocation(OperationContext* opCtx,
                                                const std::string& newLocation) {
    boost::system::error_code ec;
    boost::filesystem::create_directories(newLocation, ec);
    if (ec) {
        return {ErrorCodes::InternalError,
                str::stream() << "Failed to create directory " << newLocation
                              << " Error: " << ec.message()};
    }

    auto previousCatalogState = catalog::closeCatalog(opCtx);

    auto lastShutdownState =
        reinitializeStorageEngine(opCtx, StorageEngineInitFlags{}, [&newLocation] {
            storageGlobalParams.dbpath = newLocation;
        });
    if (StorageEngine::LastShutdownState::kClean != lastShutdownState) {
        return {ErrorCodes::InternalError,
                str::stream() << "Failed to switch storage location to " << newLocation};
    }


    try {
        startup_recovery::repairAndRecoverDatabases(opCtx, lastShutdownState);
    } catch (const ExceptionFor<ErrorCodes::MustDowngrade>& error) {
        // versions incompatibility (we actually should check this when we select sync source)
        return error.toStatus();
    }

    catalog::openCatalogAfterStorageChange(opCtx);

    LOGV2_DEBUG(128415, 1, "Switched storage location", "newLocation"_attr = newLocation);
    return Status::OK();
}

Status InitialSyncerFCB::_killBackupCursor_inlock() {
    const auto* info = _backupCursorInfo.get();
    invariant(info);
    executor::RemoteCommandRequest killCursorsRequest(
        _syncSource,
        info->nss.db().toString(),
        BSON("killCursors" << info->nss.coll().toString() << "cursors"
                           << BSON_ARRAY(info->cursorId)),
        nullptr);

    auto scheduleResult = _exec->scheduleRemoteCommand(
        killCursorsRequest, [](const executor::TaskExecutor::RemoteCommandCallbackArgs& args) {
            if (!args.response.isOK()) {
                LOGV2_WARNING(128416,
                              "killCursors command task failed",
                              "error"_attr = redact(args.response.status));
                return;
            }
            auto status = getStatusFromCommandResult(args.response.data);
            if (status.isOK()) {
                LOGV2_INFO(128417, "Killed backup cursor");
            } else {
                LOGV2_WARNING(128418, "killCursors command failed", "error"_attr = redact(status));
            }
        });
    return scheduleResult.getStatus();
}

// TenantMigrationRecipientService::Instance::_openBackupCursor
// ShardMergeRecipientService::Instance::_openBackupCursor
void InitialSyncerFCB::_fetchBackupCursorCallback(
    const executor::TaskExecutor::CallbackArgs& callbackArgs,
    // NOLINTNEXTLINE(*-unnecessary-value-param)
    std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept try {
    stdx::lock_guard<Latch> lock(_mutex);
    auto status = _checkForShutdownAndConvertStatus_inlock(
        callbackArgs, "error executing backup cusrsor on the sync source");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    const auto aggregateCommandRequestObj = [] {
        AggregateCommandRequest aggRequest(
            NamespaceString::makeCollectionlessAggregateNSS(DatabaseName::kAdmin),
            {BSON("$backupCursor" << BSONObj())});
        // We must set a writeConcern on internal commands.
        aggRequest.setWriteConcern(WriteConcernOptions());
        return aggRequest.toBSON(BSONObj());
    }();

    LOGV2_DEBUG(128407, 1, "Opening backup cursor on sync source");

    auto fetchStatus = std::make_shared<boost::optional<Status>>();
    const auto fetcherCallback = [this, fetchStatus](const Fetcher::QueryResponseStatus& dataStatus,
                                                     Fetcher::NextAction* nextAction,
                                                     BSONObjBuilder* getMoreBob) noexcept {
        try {
            uassertStatusOK(dataStatus);

            const auto& data = dataStatus.getValue();
            for (const BSONObj& doc : data.documents) {
                if (doc[kMetadataFieldName]) {
                    // First batch must contain the metadata.
                    const auto& metadata = doc[kMetadataFieldName].Obj();
                    auto checkpointTimestamp = metadata["checkpointTimestamp"].timestamp();
                    _backupId = UUID(uassertStatusOK(UUID::parse(metadata[kBackupIdFieldName])));
                    _remoteDBPath = metadata[kDBPathFieldName].String();
                    auto status = OpTime::parseFromOplogEntry(metadata["oplogEnd"].Obj());
                    invariant(status.isOK());
                    _oplogEnd = status.getValue();
                    _backupCursorInfo = std::make_unique<BackupCursorInfo>(
                        data.cursorId, data.nss, checkpointTimestamp);

                    LOGV2_INFO(128409,
                               "Opened backup cursor on sync source",
                               "backupCursorId"_attr = data.cursorId,
                               "remoteDBPath"_attr = _remoteDBPath,
                               "backupCursorCheckpointTimestamp"_attr = checkpointTimestamp);
                    // empty _remoteFiles on new sync attempt start
                    _remoteFiles.clear();
                } else {
                    auto fileName = doc[kFileNameFieldName].String();
                    auto fileSize = doc[kFileSizeFieldName].numberLong();
                    LOGV2_DEBUG(128410,
                                1,
                                "Backup cursor entry",
                                "filename"_attr = fileName,
                                "fileSize"_attr = fileSize,
                                "backupCursorId"_attr = data.cursorId);
                    _remoteFiles.emplace_back(fileName, fileSize);
                }
            }

            *fetchStatus = Status::OK();
            if (!getMoreBob || data.documents.empty()) {
                // Exit fetcher but keep the backupCursor alive to prevent WT on sync source
                // from modifying file bytes. backupCursor can be closed after all files are
                // copied
                *nextAction = Fetcher::NextAction::kExitAndKeepCursorAlive;
                return;
            }

            getMoreBob->append("getMore", data.cursorId);
            getMoreBob->append("collection", data.nss.coll());
        } catch (DBException& ex) {
            LOGV2_ERROR(
                128408, "Error fetching backup cursor entries", "error"_attr = ex.toString());
            *fetchStatus = ex.toStatus();
            // In case of following error:
            // "Location50886: The existing backup cursor must be closed before $backupCursor can
            // succeed." replace error code with InvalidSyncSource to ensure fallback to logical
            if (fetchStatus->get().code() == 50886) {
                *fetchStatus = Status{ErrorCodes::InvalidSyncSource, ex.reason()};
            }
        }
    };

    _backupCursorFetcher = std::make_unique<Fetcher>(
        *_attemptExec,
        _syncSource,
        DatabaseName::kAdmin.toString(),
        aggregateCommandRequestObj,
        fetcherCallback,
        // ReadPreferenceSetting::secondaryPreferredMetadata(),
        ReadPreferenceSetting(ReadPreference::PrimaryPreferred).toContainingBSON(),
        executor::RemoteCommandRequest::kNoTimeout,
        executor::RemoteCommandRequest::kNoTimeout,
        RemoteCommandRetryScheduler::makeRetryPolicy<ErrorCategory::RetriableError>(
            kBackupCursorFileFetcherRetryAttempts, executor::RemoteCommandRequest::kNoTimeout));

    Status scheduleStatus = _backupCursorFetcher->schedule();
    if (!scheduleStatus.isOK()) {
        _backupCursorFetcher.reset();
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, scheduleStatus);
        return;
    }

    _backupCursorFetcher->onCompletion()
        .thenRunOn(**_attemptExec)
        .then([this, fetchStatus, onCompletionGuard, &lock] {
            if (!*fetchStatus) {
                // the callback was never invoked
                uasserted(128411, "Internal error running cursor callback in command");
            }
            auto status = fetchStatus->get();
            if (!status.isOK()) {
                onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
                return;
            }

            uassert(128414,
                    "Internal error: no file names collected from sync source",
                    !_remoteFiles.empty());

            // schedule file transfer callback
            status = _scheduleWorkAndSaveHandle_inlock(
                [this, onCompletionGuard](const executor::TaskExecutor::CallbackArgs& args) {
                    _transferFileCallback(args, 0lu, onCompletionGuard);
                },
                &_transferFileHandle,
                str::stream() << "_transferFileCallback-" << 0);
            if (!status.isOK()) {
                onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
                return;
            }
        })
        .wait();

} catch (const DBException&) {
    // Report exception as an initial syncer failure.
    stdx::unique_lock<Latch> lock(_mutex);
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
}

// tenant_migration_shard_merge_util.cpp : cloneFile
void InitialSyncerFCB::_transferFileCallback(
    const executor::TaskExecutor::CallbackArgs& callbackArgs,
    std::size_t fileIdx,
    // NOLINTNEXTLINE(*-unnecessary-value-param)
    std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept try {
    stdx::lock_guard<Latch> lock(_mutex);
    auto status = _checkForShutdownAndConvertStatus_inlock(
        callbackArgs, "error transferring file from sync source");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    // create connection to the sync source
    DBClientConnection syncSourceConn{true /* autoReconnect */};
    status = syncSourceConn.connect(_syncSource, "File copy-based initial sync", boost::none);
    if (status.isOK()) {
        status = replAuthenticate(&syncSourceConn)
                     .withContext(str::stream() << "Failed to authenticate to " << _syncSource);
    }
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    // execute remote request
    std::string remoteFileName = _remoteFiles[fileIdx].name;
    size_t remoteFileSize = _remoteFiles[fileIdx].size;
    auto currentBackupFileCloner =
        std::make_unique<FCBFileCloner>(_backupId,
                                        remoteFileName,
                                        remoteFileSize,
                                        getPathRelativeTo(remoteFileName, _remoteDBPath),
                                        _sharedData.get(),
                                        _syncSource,
                                        &syncSourceConn,
                                        _storage,
                                        _writerPool);
    auto cloneStatus = currentBackupFileCloner->run();
    if (!cloneStatus.isOK()) {
        LOGV2_WARNING(128412,
                      "Failed to clone file",
                      "fileName"_attr = remoteFileName,
                      "error"_attr = cloneStatus);
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, cloneStatus);
    } else {
        LOGV2_DEBUG(128413, 1, "Cloned file", "fileName"_attr = remoteFileName);
        auto nextFileIdx = fileIdx + 1;
        if (nextFileIdx < _remoteFiles.size()) {
            // schedule next file cloning
            auto status = _scheduleWorkAndSaveHandle_inlock(
                [this, nextFileIdx, onCompletionGuard](
                    const executor::TaskExecutor::CallbackArgs& args) {
                    _transferFileCallback(args, nextFileIdx, onCompletionGuard);
                },
                &_transferFileHandle,
                str::stream() << "_transferFileCallback-" << nextFileIdx);
            if (!status.isOK()) {
                onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
                return;
            }
        } else {
            // all files are cloned - close backup cursor
            auto status = _killBackupCursor_inlock();
            if (!status.isOK()) {
                onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
                return;
            }
            // schedule next task
            status = _scheduleWorkAndSaveHandle_inlock(
                [this, onCompletionGuard](const executor::TaskExecutor::CallbackArgs& args) {
                    _switchToDownloadedCallback(args, onCompletionGuard);
                },
                &_currentHandle,
                "_switchToDownloadedCallback");
            if (!status.isOK()) {
                onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
                return;
            }
        }
    }
} catch (const DBException&) {
    // Report exception as an initial syncer failure.
    stdx::unique_lock<Latch> lock(_mutex);
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
}

void InitialSyncerFCB::_switchToDownloadedCallback(
    const executor::TaskExecutor::CallbackArgs& callbackArgs,
    // NOLINTNEXTLINE(*-unnecessary-value-param)
    std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept try {
    stdx::lock_guard<Latch> lock(_mutex);
    auto status = _checkForShutdownAndConvertStatus_inlock(callbackArgs,
                                                           "_switchToDownloadedCallback cancelled");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    // Save list of files existing in dbpath. We will delete them later
    LOGV2_DEBUG(128404, 2, "Reading the list of local files via $backupCursor");
    auto bfiles = _getBackupFiles();
    if (!bfiles.isOK()) {
        LOGV2_DEBUG(
            128405, 2, "Failed to get the list of local files", "status"_attr = bfiles.getStatus());
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, bfiles.getStatus());
        return;
    }
    LOGV2_DEBUG(
        128406, 2, "Retrieved names of local files", "number"_attr = bfiles.getValue().size());
    _localFiles = bfiles.getValue();

    auto opCtx = makeOpCtx();
    Lock::GlobalLock lk(opCtx.get(), MODE_X);
    // retrieve the current on-disk replica set configuration
    auto* rs = repl::ReplicationCoordinator::get(opCtx->getServiceContext());
    invariant(rs);
    BSONObj savedRSConfig = rs->getConfigBSON();

    // Switch storage to be pointing to the set of downloaded files
    status = _switchStorageLocation(opCtx.get(), _cfgDBPath + "/.initialsync");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    // do some cleanup
    auto* consistencyMarkers = _replicationProcess->getConsistencyMarkers();
    // TODO: when extend backup cursor is implemented use the last opTime retrieved from the sync
    // source
    consistencyMarkers->setOplogTruncateAfterPoint(opCtx.get(), _oplogEnd.getTimestamp());
    // clear and reset the initalSyncId
    consistencyMarkers->clearInitialSyncId(opCtx.get());
    consistencyMarkers->setInitialSyncIdIfNotSet(opCtx.get());

    ReplicationCoordinatorExternalStateImpl externalState(
        opCtx->getServiceContext(),
        DropPendingCollectionReaper::get(opCtx.get()),
        StorageInterface::get(opCtx.get()),
        ReplicationProcess::get(opCtx.get()));
    // replace the lastVote document with a default one
    status = StorageInterface::get(opCtx.get())
                 ->dropCollection(opCtx.get(), NamespaceString::kLastVoteNamespace);
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }
    status = externalState.createLocalLastVoteCollection(opCtx.get());
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }
    // replace the config with savedRSConfig
    status = externalState.replaceLocalConfigDocument(opCtx.get(), savedRSConfig);
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    // schedule next task
    status = _scheduleWorkAndSaveHandle_inlock(
        [this, onCompletionGuard](const executor::TaskExecutor::CallbackArgs& args) {
            _switchToDummyCallback(args, onCompletionGuard);
        },
        &_currentHandle,
        "_switchToDummyCallback");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }
} catch (const DBException&) {
    // Report exception as an initial syncer failure.
    stdx::unique_lock<Latch> lock(_mutex);
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
}

void InitialSyncerFCB::_switchToDummyCallback(
    const executor::TaskExecutor::CallbackArgs& callbackArgs,
    // NOLINTNEXTLINE(*-unnecessary-value-param)
    std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept try {
    stdx::lock_guard<Latch> lock(_mutex);
    auto status =
        _checkForShutdownAndConvertStatus_inlock(callbackArgs, "_switchToDummyCallback cancelled");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    auto opCtx = makeOpCtx();
    Lock::GlobalLock lk(opCtx.get(), MODE_X);
    // Switch storage to a dummy location
    status = _switchStorageLocation(opCtx.get(), _cfgDBPath + "/.initialsync/.dummy");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    // Delete the list of files obtained from the local backup cursor
    status = _deleteLocalFiles();
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    // Move the files from the download location to the normal dbpath
    boost::filesystem::path cfgDBPath(_cfgDBPath);
    status = _moveFiles(cfgDBPath / ".initialsync", cfgDBPath);
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    // schedule next task
    status = _scheduleWorkAndSaveHandle_inlock(
        [this, onCompletionGuard](const executor::TaskExecutor::CallbackArgs& args) {
            _switchToDBPathCallback(args, onCompletionGuard);
        },
        &_currentHandle,
        "_switchToDBPathCallback");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }
} catch (const DBException&) {
    // Report exception as an initial syncer failure.
    stdx::unique_lock<Latch> lock(_mutex);
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
}

void InitialSyncerFCB::_switchToDBPathCallback(
    const executor::TaskExecutor::CallbackArgs& callbackArgs,
    // NOLINTNEXTLINE(*-unnecessary-value-param)
    std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept try {
    stdx::lock_guard<Latch> lock(_mutex);
    auto status =
        _checkForShutdownAndConvertStatus_inlock(callbackArgs, "_switchToDBPathCallback cancelled");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    // TODO: should it be the same lock from the previious stage?
    auto opCtx = makeOpCtx();
    Lock::GlobalLock lk(opCtx.get(), MODE_X);
    // Switch storage back to the normal dbpath
    status = _switchStorageLocation(opCtx.get(), _cfgDBPath);
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    // TODO: set value of _lastApplied or provide another instance of OpTimeAndWallTime
    // TODO: fix this temporary solution
    _lastApplied.opTime = _oplogEnd;
    _lastApplied.wallTime = Date_t::fromMillisSinceEpoch(_oplogEnd.getSecs() * 1000);
    // Successfully complete initial sync
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, _lastApplied);
} catch (const DBException&) {
    // Report exception as an initial syncer failure.
    stdx::unique_lock<Latch> lock(_mutex);
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
}

// template
// void InitialSyncerFCB::_(const executor::TaskExecutor::CallbackArgs& callbackArgs,
//                         // NOLINTNEXTLINE(*-unnecessary-value-param)
//                         std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept try {
//    stdx::lock_guard<Latch> lock(_mutex);
//    auto status = _checkForShutdownAndConvertStatus_inlock(callbackArgs, "error message");
//    if (!status.isOK()) {
//        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
//        return;
//    }
//
//    // schedule next task
//    status = _scheduleWorkAndSaveHandle_inlock(
//        [this, onCompletionGuard](const executor::TaskExecutor::CallbackArgs& args) {
//            _nextTaskCallback(args, onCompletionGuard);
//        },
//        &_currentHandle,
//        "task name");
//    if (!status.isOK()) {
//        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
//        return;
//    }
//} catch (const DBException&) {
//    // Report exception as an initial syncer failure.
//    stdx::unique_lock<Latch> lock(_mutex);
//    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
//}

// debugging template
//            onCompletionGuard->setResultAndCancelRemainingWork_inlock(
//                lock,
//                {ErrorCodes::NotImplemented,
//                 "All files cloned; cancel FCBIS for debugging reason"});


std::string InitialSyncerFCB::Stats::toString() const {
    return toBSON().toString();
}

BSONObj InitialSyncerFCB::Stats::toBSON() const {
    BSONObjBuilder bob;
    append(&bob);
    return bob.obj();
}

void InitialSyncerFCB::Stats::append(BSONObjBuilder* builder) const {
    builder->appendNumber("failedInitialSyncAttempts",
                          static_cast<long long>(failedInitialSyncAttempts));
    builder->appendNumber("maxFailedInitialSyncAttempts",
                          static_cast<long long>(maxFailedInitialSyncAttempts));

    auto e = exec.lock();
    if (initialSyncStart != Date_t()) {
        builder->appendDate("initialSyncStart", initialSyncStart);
        auto elapsedDurationEnd = e ? e->now() : Date_t::now();
        if (initialSyncEnd != Date_t()) {
            builder->appendDate("initialSyncEnd", initialSyncEnd);
            elapsedDurationEnd = initialSyncEnd;
        }
        long long elapsedMillis =
            duration_cast<Milliseconds>(elapsedDurationEnd - initialSyncStart).count();
        builder->appendNumber("totalInitialSyncElapsedMillis", elapsedMillis);
    }

    BSONArrayBuilder arrBuilder(builder->subarrayStart("initialSyncAttempts"));
    for (auto const& attemptInfo : initialSyncAttemptInfos) {
        arrBuilder.append(attemptInfo.toBSON());
    }
    arrBuilder.doneFast();
}

std::string InitialSyncerFCB::InitialSyncAttemptInfo::toString() const {
    return toBSON().toString();
}

BSONObj InitialSyncerFCB::InitialSyncAttemptInfo::toBSON() const {
    BSONObjBuilder bob;
    append(&bob);
    return bob.obj();
}

void InitialSyncerFCB::InitialSyncAttemptInfo::append(BSONObjBuilder* builder) const {
    builder->appendNumber("durationMillis", durationMillis);
    builder->append("status", status.toString());
    builder->append("syncSource", syncSource.toString());
    if (rollBackId >= 0) {
        builder->append("rollBackId", rollBackId);
    }
    builder->append("operationsRetried", operationsRetried);
    builder->append("totalTimeUnreachableMillis", totalTimeUnreachableMillis);
}

}  // namespace repl
}  // namespace mongo
