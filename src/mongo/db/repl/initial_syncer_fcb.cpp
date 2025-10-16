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

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <type_traits>
#include <utility>

#include "initial_syncer_fcb.h"

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include <fmt/format.h>

#include "mongo/base/error_codes.h"
#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonelement.h"
#include "mongo/bson/bsonmisc.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/bson/timestamp.h"
#include "mongo/client/dbclient_cursor.h"
#include "mongo/client/fetcher.h"
#include "mongo/client/read_preference.h"
#include "mongo/client/remote_command_retry_scheduler.h"
#include "mongo/db/catalog/catalog_control.h"
#include "mongo/db/client.h"
#include "mongo/db/commands/server_status_metric.h"
#include "mongo/db/concurrency/d_concurrency.h"
#include "mongo/db/database_name.h"
#include "mongo/db/dbdirectclient.h"
#include "mongo/db/dbhelpers.h"
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
#include "mongo/db/repl/read_concern_args.h"
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
#include "mongo/db/server_recovery.h"
#include "mongo/db/serverless/serverless_operation_lock_registry.h"
#include "mongo/db/service_context.h"
#include "mongo/db/startup_recovery.h"
#include "mongo/db/storage/storage_engine.h"
#include "mongo/db/storage/storage_engine_init.h"
#include "mongo/db/storage/storage_options.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_global_options.h"
#include "mongo/db/transaction/transaction_participant.h"
#include "mongo/db/transaction_resources.h"
#include "mongo/executor/remote_command_request.h"
#include "mongo/executor/task_executor.h"
#include "mongo/idl/idl_parser.h"
#include "mongo/logv2/log.h"
#include "mongo/logv2/log_attr.h"
#include "mongo/logv2/log_component.h"
#include "mongo/logv2/redaction.h"
#include "mongo/platform/compiler.h"  // IWYU pragma: keep
#include "mongo/rpc/get_status_from_command_result.h"
#include "mongo/stdx/mutex.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/destructor_guard.h"
#include "mongo/util/fail_point.h"
#include "mongo/util/future.h"
#include "mongo/util/interruptible.h"
#include "mongo/util/scopeguard.h"
#include "mongo/util/str.h"
#include "mongo/util/time_support.h"
#include "mongo/util/timer.h"
#include "mongo/util/version/releases.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kReplicationInitialSync


namespace mongo {
namespace repl {

// Failpoint for initial sync
extern FailPoint failInitialSyncWithBadHost;

// Failpoint which causes the initial sync function to hang before creating shared data and
// splitting control flow between the oplog fetcher and the cloners.
extern FailPoint initialSyncHangBeforeSplittingControlFlow;

// Failpoint which causes the initial sync function to hang before copying databases.
extern FailPoint initialSyncHangBeforeCopyingDatabases;

// Failpoint which causes the initial sync function to hang before finishing.
extern FailPoint initialSyncHangBeforeFinish;

// Failpoint which causes the initial sync function to hang before creating the oplog.
extern FailPoint initialSyncHangBeforeCreatingOplog;

// Failpoint which skips clearing _initialSyncState after a successful initial sync attempt.
extern FailPoint skipClearInitialSyncState;

// Failpoint which causes the initial sync function to fail and hang before starting a new attempt.
extern FailPoint failAndHangInitialSync;

// Failpoint which causes the initial sync function to hang before choosing a sync source.
extern FailPoint initialSyncHangBeforeChoosingSyncSource;

// Failpoint which causes the initial sync function to hang after finishing.
extern FailPoint initialSyncHangAfterFinish;

// Failpoint which causes the initial sync function to hang after resetting the in-memory FCV.
extern FailPoint initialSyncHangAfterResettingFCV;

// Failpoint which causes the initial sync function to hang after cloning files.
MONGO_FAIL_POINT_DEFINE(initialSyncHangAfterCloningFiles);

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

// denylist duration for temporary issues
constexpr Seconds kDenylistTemporary{5};
// denylist duration for persistent issues
constexpr Seconds kDenylistPersistent{60};

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

/**
 * Parse OpTime from BSONObj cotaining 'ts' and 't' fields.
 */
OpTime parseOpTimeFromBSON(const BSONObj& obj) {
    auto status = OpTime::parseFromOplogEntry(obj);
    uassertStatusOKWithContext(status, "Failed to parse OpTime from BSON");
    return status.getValue();
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
               ThreadPool* workerPool,
               StorageInterface* storage,
               ReplicationProcess* replicationProcess,
               const InitialSyncerInterface::OnCompletionFn& onCompletion) {
                return std::make_shared<InitialSyncerFCB>(opts,
                                                          std::move(dataReplicatorExternalState),
                                                          workerPool,
                                                          storage,
                                                          replicationProcess,
                                                          onCompletion);
            });
    });

InitialSyncerFCB::InitialSyncerFCB(
    InitialSyncerInterface::Options opts,
    std::unique_ptr<DataReplicatorExternalState> dataReplicatorExternalState,
    ThreadPool* workerPool,
    StorageInterface* storage,
    ReplicationProcess* replicationProcess,
    const OnCompletionFn& onCompletion)
    : _fetchCount(0),
      _opts(opts),
      _dataReplicatorExternalState(std::move(dataReplicatorExternalState)),
      _exec(_dataReplicatorExternalState->getSharedTaskExecutor()),
      _clonerExec(_exec),
      _workerPool(workerPool),
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
    return "fileCopyBased";
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

    if (storageGlobalParams.engine != "wiredTiger") {
        static constexpr char msg[] =
            "wiredTiger storage engine required on the syncing node for file copy-based initial "
            "sync";
        LOGV2_ERROR(128466, msg, "currentEngine"_attr = storageGlobalParams.engine);
        // Schedule _finishCallback to terminate initial sync with error.
        auto scheduleResult =
            _exec->scheduleWork([this](const mongo::executor::TaskExecutor::CallbackArgs&) {
                _finishCallback(Status(ErrorCodes::InitialSyncFailure, msg));
            });
        return scheduleResult.getStatus();
    }

    // Start first initial sync attempt.
    std::uint32_t initialSyncAttempt = 0;
    _attemptExec = std::make_unique<executor::ScopedTaskExecutor>(
        _exec, Status(ErrorCodes::CallbackCanceled, "Initial Sync Attempt Canceled"));
    _clonerAttemptExec = std::make_unique<executor::ScopedTaskExecutor>(
        _clonerExec, Status(ErrorCodes::CallbackCanceled, "Initial Sync Attempt Canceled"));
    auto status = _scheduleWorkAndSaveHandle_inlock(
        [=, this](const executor::TaskExecutor::CallbackArgs& args) {
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
    stdx::unique_lock<Latch> lock(_mutex);
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

    // Ensure that storage change will not be blocked by shutdown's opCtx (first call to
    // InitialSyncerFCB::shutdown comes from ReplicationCoordinatorImpl::enterTerminalShutdown
    // at the moment when there is no opCtx in the shutdown thread yet).
    // Wait for finish of tasks that change storage location if any is running.
    _inStorageChangeCondition.wait(lock, [this] { return !_inStorageChange; });

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
    _cancelHandle_inlock(_keepAliveHandle);
    _cancelHandle_inlock(_currentHandle);

    // Close backup cursor if it is still open.
    if (_backupCursorInfo) {
        Status status = _killBackupCursor_inlock();
        if (!status.isOK()) {
            LOGV2_FATAL(128468,
                        "Failed to kill backup cursor on the sync source",
                        "syncSource"_attr = _syncSource,
                        "cursorId"_attr = _backupCursorInfo->cursorId,
                        "error"_attr = status);
        }
    }

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
    bob->append("method", getInitialSyncMethod());
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

    if (ReplicationCoordinator::get(opCtx)->getSettings().isServerless()) {
        tenant_migration_access_blocker::recoverTenantMigrationAccessBlockers(opCtx);
    }
    ServerlessOperationLockRegistry::recoverLocks(opCtx);
    reconstructPreparedTransactions(opCtx, repl::OplogApplication::Mode::kInitialSync);

    // The storage engine is created with dummy callback for oldest active timestamp, so we need
    // to set it here (on server startup it is set in _initAndListen)
    // Without this callback, the oplog is never truncated
    opCtx->getServiceContext()->getStorageEngine()->setOldestActiveTransactionTimestampCallback(
        TransactionParticipant::getOldestActiveTimestamp);

    _replicationProcess->getConsistencyMarkers()->setInitialSyncIdIfNotSet(opCtx);

    _storage->setInitialDataTimestamp(opCtx->getServiceContext(), initialDataTimestamp);

    auto currentLastAppliedOpTime = _opts.getMyLastOptime();
    if (currentLastAppliedOpTime.isNull()) {
        _opts.setMyLastOptime(lastApplied.getValue());
    } else {
        invariant(currentLastAppliedOpTime == lastAppliedOpTime);
    }

    LOGV2(128422,
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
        // We need to use force in case we are resetting the oldest timestamp backwards after a
        // failed initial sync attempt.
        storageEngine->setOldestTimestamp(kTimestampOne, true /*force*/);
    }

    LOGV2_DEBUG(128427,
                2,
                "Resetting feature compatibility version to last-lts. If the sync source is in "
                "latest feature compatibility version, we will find out when we clone the "
                "server configuration collection (admin.system.version)");
    serverGlobalParams.mutableFCV.reset();

    if (MONGO_unlikely(initialSyncHangAfterResettingFCV.shouldFail())) {
        LOGV2(8206400, "initialSyncHangAfterResettingFCV fail point enabled");
        initialSyncHangAfterResettingFCV.pauseWhileSet();
    }

    // Get sync source.
    std::uint32_t chooseSyncSourceAttempt = 0;
    std::uint32_t chooseSyncSourceMaxAttempts =
        static_cast<std::uint32_t>(numInitialSyncConnectAttempts.load());

    // _scheduleWorkAndSaveHandle_inlock() is shutdown-aware.
    status = _scheduleWorkAndSaveHandle_inlock(
        [=, this](const executor::TaskExecutor::CallbackArgs& args) {
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
    if (MONGO_unlikely(initialSyncHangBeforeChoosingSyncSource.shouldFail())) {
        LOGV2(128428, "initialSyncHangBeforeChoosingSyncSource fail point enabled");
        initialSyncHangBeforeChoosingSyncSource.pauseWhileSet();
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

    if (MONGO_unlikely(failInitialSyncWithBadHost.shouldFail())) {
        status = Status(ErrorCodes::InvalidSyncSource,
                        "initial sync failed - failInitialSyncWithBadHost failpoint is set.");
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    auto syncSource = _chooseSyncSource_inlock();
    if (!syncSource.isOK()) {
        if (chooseSyncSourceAttempt + 1 >= chooseSyncSourceMaxAttempts) {
            onCompletionGuard->setResultAndCancelRemainingWork_inlock(
                lock,
                syncSource.getStatus().withContext("Finishing file copy based initial sync "
                                                   "attempt: could not choose valid sync source"));
            return;
        }

        auto when = (*_attemptExec)->now() + _opts.syncSourceRetryWait;
        LOGV2_DEBUG(128429,
                    1,
                    "Error getting sync source. Waiting to retry",
                    "error"_attr = syncSource.getStatus(),
                    "syncSourceRetryWait"_attr = _opts.syncSourceRetryWait,
                    "retryTime"_attr = when.toString(),
                    "chooseSyncSourceAttempt"_attr = (chooseSyncSourceAttempt + 1),
                    "numInitialSyncConnectAttempts"_attr = numInitialSyncConnectAttempts.load());
        auto status = _scheduleWorkAtAndSaveHandle_inlock(
            when,
            [=, this](const executor::TaskExecutor::CallbackArgs& args) {
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

    if (MONGO_unlikely(initialSyncHangBeforeCreatingOplog.shouldFail())) {
        // This log output is used in js tests so please leave it.
        LOGV2(128430,
              "initial sync - initialSyncHangBeforeCreatingOplog fail point "
              "enabled. Blocking until fail point is disabled.");
        lock.unlock();
        while (MONGO_unlikely(initialSyncHangBeforeCreatingOplog.shouldFail()) &&
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
    auto scheduleResult = _rollbackChecker->reset([=, this](const RollbackChecker::Result& result) {
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
                "About to truncate the oplog, if it exists, and drop all user databases (so that "
                "we can clone them)",
                logAttrs(NamespaceString::kRsOplogNamespace));

    auto opCtx = makeOpCtx();
    // This code can make untimestamped writes (deletes) to the _mdb_catalog on top of existing
    // timestamped updates.
    shard_role_details::getRecoveryUnit(opCtx.get())->allowAllUntimestampedWrites();

    // We are not replicating nor validating these writes.
    UnreplicatedWritesBlock unreplicatedWritesBlock(opCtx.get());

    // 1.) Truncate the oplog.
    LOGV2_DEBUG(128432,
                2,
                "Truncating the existing oplog",
                logAttrs(NamespaceString::kRsOplogNamespace));
    Timer timer;
    auto status = _storage->truncateCollection(opCtx.get(), NamespaceString::kRsOplogNamespace);
    LOGV2(128433,
          "Initial syncer oplog truncation finished",
          "durationMillis"_attr = timer.millis());
    if (!status.isOK()) {
        // 1a.) Create the oplog.
        LOGV2_DEBUG(128434,
                    2,
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
            const int extensionsUsed = 0;
            _fetchBackupCursorCallback(args, extensionsUsed, onCompletionGuard, [] {
                AggregateCommandRequest aggRequest(
                    NamespaceString::makeCollectionlessAggregateNSS(DatabaseName::kAdmin),
                    {BSON("$backupCursor" << BSONObj())});
                // We must set a writeConcern on internal commands.
                aggRequest.setWriteConcern(WriteConcernOptions());
                return aggRequest.toBSON(BSONObj());
            });
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

    if (MONGO_unlikely(initialSyncHangBeforeSplittingControlFlow.shouldFail())) {
        lock.unlock();
        LOGV2(128436,
              "initial sync - initialSyncHangBeforeSplittingControlFlow fail point "
              "enabled. Blocking until fail point is disabled.");
        while (MONGO_unlikely(initialSyncHangBeforeSplittingControlFlow.shouldFail()) &&
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
        _sharedData.get(), _syncSource, _client.get(), _storage, _workerPool));

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

    if (MONGO_unlikely(initialSyncHangBeforeCopyingDatabases.shouldFail())) {
        lock.unlock();
        // This could have been done with a scheduleWorkAt but this is used only by JS tests where
        // we run with multiple threads so it's fine to spin on this thread.
        // This log output is used in js tests so please leave it.
        LOGV2(128438,
              "initial sync - initialSyncHangBeforeCopyingDatabases fail point "
              "enabled. Blocking until fail point is disabled.");
        while (MONGO_unlikely(initialSyncHangBeforeCopyingDatabases.shouldFail()) &&
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
        auto scheduleResult =
            _exec->scheduleWork([=, this](const mongo::executor::TaskExecutor::CallbackArgs&) {
                _finishCallback(result);
            });
        if (!scheduleResult.isOK()) {
            LOGV2_WARNING(128439,
                          "Unable to schedule initial syncer completion task. Running callback on "
                          "current thread",
                          "error"_attr = redact(scheduleResult.getStatus()));
            _finishCallback(result);
        }
    });

    LOGV2(128440, "Initial sync attempt finishing up");

    stdx::unique_lock<Latch> lock(_mutex);

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

    // Remove temporary directories created by the initial syncer.
    {
        boost::filesystem::path cfgDBPath(_cfgDBPath);
        boost::system::error_code ec;
        boost::filesystem::remove_all(cfgDBPath / ".initialsync", ec);
    }

    if (MONGO_unlikely(failAndHangInitialSync.shouldFail())) {
        LOGV2(128441, "failAndHangInitialSync fail point enabled");
        failAndHangInitialSync.pauseWhileSet();
        result = Status(ErrorCodes::InternalError, "failAndHangInitialSync fail point enabled");
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
        [=, this](const executor::TaskExecutor::CallbackArgs& args) {
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

    if (MONGO_unlikely(initialSyncHangBeforeFinish.shouldFail())) {
        // This log output is used in js tests so please leave it.
        LOGV2(128444,
              "initial sync - initialSyncHangBeforeFinish fail point "
              "enabled. Blocking until fail point is disabled.");
        while (MONGO_unlikely(initialSyncHangBeforeFinish.shouldFail()) && !_isShuttingDown()) {
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
        if (lastApplied.isOK() && !MONGO_unlikely(skipClearInitialSyncState.shouldFail())) {
            _initialSyncState.reset();
        }

        // Destroy shared references to executors.
        _attemptExec = nullptr;
        _clonerAttemptExec = nullptr;
        _clonerExec = nullptr;
        _exec = nullptr;
    }

    if (MONGO_unlikely(initialSyncHangAfterFinish.shouldFail())) {
        LOGV2(128446,
              "initial sync finished - initialSyncHangAfterFinish fail point "
              "enabled. Blocking until fail point is disabled.");
        while (MONGO_unlikely(initialSyncHangAfterFinish.shouldFail()) && !_isShuttingDown()) {
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

    StatusWith<HostAndPort> result = syncSource;

    // Check if sync source supports FCBIS.
    executor::RemoteCommandRequest buildInfoRequest(
        syncSource, DatabaseName::kAdmin, BSON("buildInfo" << 1), nullptr);
    auto scheduleResult =
        (*_attemptExec)
            ->scheduleRemoteCommand(
                buildInfoRequest,
                [this, &syncSource, &result](
                    const executor::TaskExecutor::RemoteCommandCallbackArgs& args) {
                    if (!args.response.isOK()) {
                        LOGV2_WARNING(128459,
                                      "buildInfo command task failed",
                                      "error"_attr = redact(args.response.status));
                        result = Status(ErrorCodes::InvalidSyncSource,
                                        str::stream()
                                            << "buildInfo command failed on sync source, error: "
                                            << args.response.status.toString());
                        return;
                    }
                    // check build info
                    bool fcbisSupported = false;
                    if (args.response.data.hasField("psmdbVersion")) {
                        if (auto proFeatures = args.response.data.getField("proFeatures");
                            !proFeatures.eoo()) {
                            for (auto&& feature : proFeatures.Obj()) {
                                if (feature.String() == "FCBIS") {
                                    fcbisSupported = true;
                                    break;
                                }
                            }
                        }
                    }
                    if (!fcbisSupported) {
                        LOGV2_WARNING(
                            128460,
                            "Invalid sync source",
                            "error"_attr =
                                "sync source does not support file copy-based initial sync");
                        result = _invalidSyncSource_inlock(
                            syncSource,
                            kDenylistPersistent,
                            "sync source does not support file copy-based initial sync");
                        return;
                    }
                });
    if (!scheduleResult.isOK()) {
        return scheduleResult.getStatus().withContext(
            str::stream() << "Failed to schedule buildInfo command to sync source: "
                          << syncSource.toString());
    }
    // Block until the command is executed.
    (*_attemptExec)->wait(scheduleResult.getValue());

    if (!result.isOK()) {
        return result;
    }

    // Check if storage engine on the sync source is wiredTiger.
    executor::RemoteCommandRequest serverStatusRequest(
        syncSource, DatabaseName::kAdmin, BSON("serverStatus" << 1), nullptr);
    scheduleResult =
        (*_attemptExec)
            ->scheduleRemoteCommand(
                serverStatusRequest,
                [this, &syncSource, &result](
                    const executor::TaskExecutor::RemoteCommandCallbackArgs& args) {
                    if (!args.response.isOK()) {
                        LOGV2_WARNING(128457,
                                      "serverStatus command task failed",
                                      "error"_attr = redact(args.response.status));
                        result = Status(ErrorCodes::InvalidSyncSource,
                                        str::stream()
                                            << "serverStatus command failed on sync source, error: "
                                            << args.response.status.toString());
                        return;
                    }
                    // validate storage engine
                    auto storageEngineName =
                        args.response.data["storageEngine"].Obj().getStringField("name");
                    if (storageEngineName != "wiredTiger") {
                        LOGV2_WARNING(128458,
                                      "Invalid sync source",
                                      "error"_attr = "storage engine mismatch");
                        result = _invalidSyncSource_inlock(
                            syncSource, kDenylistPersistent, "storage engine mismatch");
                        return;
                    }
                });
    if (!scheduleResult.isOK()) {
        return scheduleResult.getStatus().withContext(
            str::stream() << "Failed to schedule serverStatus command to sync source: "
                          << syncSource.toString());
    }
    // Block until the command is executed.
    (*_attemptExec)->wait(scheduleResult.getValue());

    if (!result.isOK()) {
        return result;
    }

    // Check directoryperdb and wiredTigerDirectoryForIndexes via getParameter command.
    executor::RemoteCommandRequest getParameterRequest(
        syncSource, DatabaseName::kAdmin, BSON("getParameter" << "*"), nullptr);
    scheduleResult =
        (*_attemptExec)
            ->scheduleRemoteCommand(
                getParameterRequest,
                [this, &syncSource, &result](
                    const executor::TaskExecutor::RemoteCommandCallbackArgs& args) {
                    if (!args.response.isOK()) {
                        LOGV2_WARNING(128448,
                                      "getParameter command task failed",
                                      "error"_attr = redact(args.response.status));
                        result = Status(ErrorCodes::InvalidSyncSource,
                                        str::stream()
                                            << "getParameter command failed on sync source, error: "
                                            << args.response.status.toString());
                        return;
                    }
                    // validate critical parameters
                    bool dirPerDB =
                        args.response.data.getBoolField("storageGlobalParams.directoryperdb");
                    if (dirPerDB != storageGlobalParams.directoryperdb) {
                        LOGV2_WARNING(128449,
                                      "Invalid sync source",
                                      "error"_attr = "directoryperdb mismatch");
                        result = _invalidSyncSource_inlock(
                            syncSource, kDenylistPersistent, "directoryperdb mismatch");
                        return;
                    }
                    bool dirForIndexes =
                        args.response.data.getBoolField("wiredTigerDirectoryForIndexes");
                    if (dirForIndexes != wiredTigerGlobalOptions.directoryForIndexes) {
                        LOGV2_WARNING(128450,
                                      "Invalid sync source",
                                      "error"_attr = "wiredTigerDirectoryForIndexes mismatch");
                        result =
                            _invalidSyncSource_inlock(syncSource,
                                                      kDenylistPersistent,
                                                      "wiredTigerDirectoryForIndexes mismatch");
                        return;
                    }
                    // And BTW, get cursorTimeoutMillis, to fine tune the backup cursor's keep alive
                    // code
                    _keepAliveInterval =
                        Milliseconds{args.response.data.getIntField("cursorTimeoutMillis") / 2};
                });
    if (!scheduleResult.isOK()) {
        return scheduleResult.getStatus().withContext(
            str::stream() << "Failed to schedule getParameter command to sync source: "
                          << syncSource.toString());
    }
    // Block until the command is executed.
    (*_attemptExec)->wait(scheduleResult.getValue());

    if (!result.isOK()) {
        return result;
    }

    // Check FCV on the sync source.
    BSONObjBuilder queryBob;
    queryBob.append("find", NamespaceString::kServerConfigurationNamespace.coll());
    auto filterBob = BSONObjBuilder(queryBob.subobjStart("filter"));
    filterBob.append("_id", multiversion::kParameterName);
    filterBob.done();
    // readConcern is mandatory for commands on internalClient connections.
    auto readConcernBob = BSONObjBuilder(queryBob.subobjStart("readConcern"));
    readConcernBob.append("level", "local");
    readConcernBob.done();

    Fetcher fcvFetcher{
        *_attemptExec,
        syncSource,
        NamespaceString::kServerConfigurationNamespace.dbName(),
        queryBob.obj(),
        [this, &syncSource, &result](const StatusWith<mongo::Fetcher::QueryResponse>& response,
                                     mongo::Fetcher::NextAction*,
                                     mongo::BSONObjBuilder*) {
            auto status = _checkForShutdownAndConvertStatus_inlock(
                response.getStatus(),
                "error while fetching the remote feature compatibility version");
            if (!status.isOK()) {
                LOGV2_WARNING(
                    128461, "FCV fetcher task failed", "error"_attr = redact(response.getStatus()));
                result = status;
                return;
            }

            const auto docs = response.getValue().documents;
            if (docs.size() > 1) {
                result = Status(ErrorCodes::TooManyMatchingDocuments,
                                str::stream() << "Expected to receive one feature compatibility "
                                                 "version document, but received: "
                                              << docs.size() << ". First: " << redact(docs.front())
                                              << ". Last: " << redact(docs.back()));
                return;
            }
            const auto hasDoc = docs.begin() != docs.end();
            if (!hasDoc) {
                result = Status(ErrorCodes::IncompatibleServerVersion,
                                "Sync source had no feature compatibility version document");
                return;
            }

            auto fcvParseSW = FeatureCompatibilityVersionParser::parse(docs.front());
            if (!fcvParseSW.isOK()) {
                result = fcvParseSW.getStatus();
                return;
            }

            auto version = fcvParseSW.getValue();
            if (serverGlobalParams.featureCompatibility.acquireFCVSnapshot()
                    .isUpgradingOrDowngrading(version)) {
                result = _invalidSyncSource_inlock(
                    syncSource,
                    kDenylistPersistent,
                    str::stream() << "Sync source had unsafe feature compatibility version: "
                                  << multiversion::toString(version));
                return;
            }
        },
        ReadPreferenceSetting::secondaryPreferredMetadata(),
        RemoteCommandRequest::kNoTimeout,
        RemoteCommandRequest::kNoTimeout,
        RemoteCommandRetryScheduler::makeRetryPolicy<ErrorCategory::RetriableError>(
            numInitialSyncOplogFindAttempts.load(), executor::RemoteCommandRequest::kNoTimeout)};
    if (auto scheduleStatus = fcvFetcher.schedule(); !scheduleStatus.isOK()) {
        return scheduleStatus.withContext(
            str::stream()
            << "Failed to schedule feature compatibility version fetcher to sync source: "
            << syncSource.toString());
    }
    if (auto joinStatus = fcvFetcher.join(Interruptible::notInterruptible()); !joinStatus.isOK()) {
        return joinStatus.withContext(
            str::stream() << "Failed to join feature compatibility version fetcher to sync source: "
                          << syncSource.toString());
    }

    return result;
}

Status InitialSyncerFCB::_invalidSyncSource_inlock(const HostAndPort& syncSource,
                                                   Seconds denylistDuration,
                                                   const std::string& context) {
    // If the sync source is invalid, we should denylist it for a while.
    const auto until = (*_attemptExec)->now() + denylistDuration;
    _opts.syncSourceSelector->denylistSyncSource(syncSource, until);
    return Status{ErrorCodes::InvalidSyncSource,
                  str::stream() << "Invalid sync source: " << syncSource.toString()}
        .withContext(context);
}

namespace {

using namespace fmt::literals;
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
        return {ErrorCodes::UnknownError, e.what()};
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
Status InitialSyncerFCB::_switchStorageLocation(
    OperationContext* opCtx,
    const std::string& newLocation,
    const boost::optional<startup_recovery::StartupRecoveryMode> recoveryMode) {
    invariant(shard_role_details::getLocker(opCtx)->isW());

    boost::system::error_code ec;
    boost::filesystem::create_directories(newLocation, ec);
    if (ec) {
        return {ErrorCodes::InternalError,
                str::stream() << "Failed to create directory " << newLocation
                              << " Error: " << ec.message()};
    }

    auto previousCatalogState = catalog::closeCatalog(opCtx);

    auto lastShutdownState =
        reinitializeStorageEngine(opCtx, StorageEngineInitFlags{}, [&newLocation, opCtx] {
            storageGlobalParams.dbpath = newLocation;
            repl::clearLocalOplogPtr(opCtx->getServiceContext());
        });
    opCtx->getServiceContext()->getStorageEngine()->notifyStorageStartupRecoveryComplete();
    if (StorageEngine::LastShutdownState::kClean != lastShutdownState) {
        return {ErrorCodes::InternalError,
                str::stream() << "Failed to switch storage location to " << newLocation};
    }


    if (recoveryMode) {
        // We need to run startup recovery in the specified mode.
        // This is necessary to ensure that the storage engine is in a consistent state.
        try {
            startup_recovery::runStartupRecoveryInMode(opCtx, lastShutdownState, *recoveryMode);
        } catch (const ExceptionFor<ErrorCodes::MustDowngrade>& error) {
            // versions incompatibility (we actually should check this when we select sync source)
            return error.toStatus();
        }
    }

    catalog::openCatalogAfterStorageChange(opCtx);

    LOGV2_DEBUG(128415, 1, "Switched storage location", "newLocation"_attr = newLocation);
    return Status::OK();
}

void InitialSyncerFCB::_restoreStorageLocation(stdx::unique_lock<Latch>& lock,
                                               OperationContext* opCtx) {
    if (!_needToSwitchBackToOriginalDBPath) {
        return;
    }
    invariant(shard_role_details::getLocker(opCtx)->isW());
    lock.unlock();
    auto status = _switchStorageLocation(
        opCtx, _cfgDBPath, startup_recovery::StartupRecoveryMode::kReplicaSetMember);
    lock.lock();
    if (!status.isOK()) {
        // We failed to switch back to original db path. This is a serious error because we cannot
        // proceed with retry or shutdown. We should crash to avoid running in a bad state.
        LOGV2_FATAL(128467, "Failed to switch back to original db path", "error"_attr = status);
    }
    _needToSwitchBackToOriginalDBPath = false;
}

Status InitialSyncerFCB::_killBackupCursor_inlock() {
    // Cancel scheduled keep alive call
    _cancelHandle_inlock(_keepAliveHandle);

    // Kill the backup cursor by sending a killCursors command to the sync source.
    decltype(_backupCursorInfo) backupCursorInfo;
    std::swap(_backupCursorInfo, backupCursorInfo);
    const auto* info = backupCursorInfo.get();
    invariant(info);
    executor::RemoteCommandRequest killCursorsRequest(
        _syncSource,
        info->nss.dbName(),
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
    const int extensionsUsed,
    // NOLINTNEXTLINE(*-unnecessary-value-param)
    std::shared_ptr<OnCompletionGuard> onCompletionGuard,
    std::function<BSONObj()> createRequestObj) noexcept try {
    stdx::lock_guard<Latch> lock(_mutex);
    auto status = _checkForShutdownAndConvertStatus_inlock(
        callbackArgs, "error executing backup cusrsor on the sync source");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    // empty _remoteFiles before each batch received from $backupCursor/$backupCursorExtend
    _remoteFiles.clear();

    LOGV2_DEBUG(128407, 1, "Opening backup cursor on sync source", "syncSource"_attr = _syncSource);

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
                    _oplogEnd = parseOpTimeFromBSON(metadata["oplogEnd"].Obj());
                    _backupCursorInfo = std::make_unique<BackupCursorInfo>(
                        data.cursorId, data.nss, checkpointTimestamp);

                    LOGV2_INFO(128409,
                               "Opened backup cursor on sync source",
                               "backupCursorId"_attr = data.cursorId,
                               "remoteDBPath"_attr = _remoteDBPath,
                               "backupCursorCheckpointTimestamp"_attr = checkpointTimestamp);
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
                *fetchStatus = _invalidSyncSource_inlock(
                    _syncSource,
                    kDenylistTemporary,
                    str::stream() << "Error fetching backup cursor entries: " << ex.reason());
            }
        } catch (...) {
            LOGV2_ERROR(128451, "Exception while fetching backup cursor entries");
            *fetchStatus = exceptionToStatus();
        }
    };

    _backupCursorFetcher = std::make_unique<Fetcher>(
        *_attemptExec,
        _syncSource,
        DatabaseName::kAdmin,
        createRequestObj(),
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
        .then([this, fetchStatus, extensionsUsed, onCompletionGuard, &lock] {
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

            // Start keep alive loop for the backup cursor
            auto when = (*_attemptExec)->now() + _keepAliveInterval;
            status = _scheduleWorkAtAndSaveHandle_inlock(
                when,
                [this, onCompletionGuard](const executor::TaskExecutor::CallbackArgs& args) {
                    _keepAliveCallback(args, onCompletionGuard);
                },
                &_keepAliveHandle,
                "_keepAliveCallback");
            if (!status.isOK()) {
                onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
                return;
            }

            // schedule file transfer callback
            status = _scheduleWorkAndSaveHandle_inlock(
                [this, extensionsUsed, onCompletionGuard](
                    const executor::TaskExecutor::CallbackArgs& args) {
                    _transferFileCallback(args, 0LU, extensionsUsed, onCompletionGuard);
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

void InitialSyncerFCB::_keepAliveCallback(
    const executor::TaskExecutor::CallbackArgs& callbackArgs,
    // NOLINTNEXTLINE(*-unnecessary-value-param)
    std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept try {
    stdx::lock_guard<Latch> lock(_mutex);
    auto status =
        _checkForShutdownAndConvertStatus_inlock(callbackArgs, "error keeping backup cursor alive");
    if (status.code() == ErrorCodes::CallbackCanceled) {
        // If the initial syncer is shutting down or keep alive handle was cancelled, we should stop
        // keeping the backup cursor alive. Just return.
        LOGV2_DEBUG(128462, 1, "Stop keeping backup cursor alive because it was cancelled");
        return;
    }
    if (!status.isOK()) {
        LOGV2_WARNING(128463, "Unexpected error in _keepAliveCallback", "error"_attr = status);
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    const auto* info = _backupCursorInfo.get();
    if (!info) {
        LOGV2_DEBUG(128465, 1, "Stop keeping backup cursor alive because it was killed");
        return;
    }
    executor::RemoteCommandRequest getMoreRequest(
        _syncSource,
        info->nss.dbName(),
        BSON("getMore" << info->cursorId << "collection" << info->nss.coll().toString()),
        nullptr);
    getMoreRequest.options.fireAndForget = true;

    auto scheduleResult =
        (*_attemptExec)
            ->scheduleRemoteCommand(
                getMoreRequest,
                [this,
                 onCompletionGuard](const executor::TaskExecutor::RemoteCommandCallbackArgs& args) {
                    stdx::lock_guard<Latch> lock(_mutex);
                    // If backup cursor was killed in the meantime then there is no need to check
                    // getMore's result nor reschedule it
                    if (!_backupCursorInfo) {
                        LOGV2_DEBUG(
                            128464, 1, "Stop keeping backup cursor alive because it was killed");
                        return;
                    }

                    if (!args.response.isOK()) {
                        onCompletionGuard->setResultAndCancelRemainingWork_inlock(
                            lock,
                            args.response.status.withContext(
                                "error executing getMore to keep backup cursor alive"));
                        return;
                    }

                    // If the command was successful, reschedule the keep alive.
                    auto when = (*_attemptExec)->now() + _keepAliveInterval;
                    auto status = _scheduleWorkAtAndSaveHandle_inlock(
                        when,
                        [this,
                         onCompletionGuard](const executor::TaskExecutor::CallbackArgs& args) {
                            _keepAliveCallback(args, onCompletionGuard);
                        },
                        &_keepAliveHandle,
                        "_keepAliveCallback");
                    if (!status.isOK()) {
                        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
                        return;
                    }
                });
    if (!scheduleResult.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(
            lock,
            scheduleResult.getStatus().withContext(
                "Failed to schedule getMore to keep backup cursor alive"));
        return;
    }
} catch (const DBException&) {
    // Report exception as an initial syncer failure.
    stdx::lock_guard<Latch> lock(_mutex);
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
}

// tenant_migration_shard_merge_util.cpp : cloneFile
void InitialSyncerFCB::_transferFileCallback(
    const executor::TaskExecutor::CallbackArgs& callbackArgs,
    std::size_t fileIdx,
    const int extensionsUsed,
    // NOLINTNEXTLINE(*-unnecessary-value-param)
    std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept try {
    // stdx::lock_guard<Latch> lock(_mutex);
    stdx::unique_lock<Latch> lock(_mutex);
    auto status = _checkForShutdownAndConvertStatus_inlock(
        callbackArgs, "error transferring file from sync source");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    // create connection to the sync source
    DBClientConnection syncSourceConn{true /* autoReconnect */};
    syncSourceConn.connect(_syncSource, "File copy-based initial sync", boost::none);
    status = replAuthenticate(&syncSourceConn)
                 .withContext(str::stream() << "Failed to authenticate to " << _syncSource);
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
                                        _workerPool);
    lock.unlock();
    auto cloneStatus = currentBackupFileCloner->run();
    lock.lock();
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
            status = _scheduleWorkAndSaveHandle_inlock(
                [this, nextFileIdx, extensionsUsed, onCompletionGuard](
                    const executor::TaskExecutor::CallbackArgs& args) {
                    _transferFileCallback(args, nextFileIdx, extensionsUsed, onCompletionGuard);
                },
                &_transferFileHandle,
                str::stream() << "_transferFileCallback-" << nextFileIdx << "-" << extensionsUsed);
            if (!status.isOK()) {
                onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
                return;
            }
        } else {
            if (MONGO_unlikely(initialSyncHangAfterCloningFiles.shouldFail())) {
                // This could have been done with a scheduleWorkAt but this is used only by JS tests
                // where we run with multiple threads so it's fine to spin on this thread. This log
                // output is used in js tests so please leave it.
                LOGV2(128447,
                      "initial sync - initialSyncHangAfterCloningFiles fail point "
                      "enabled. Blocking until fail point is disabled.");
                lock.unlock();
                while (MONGO_unlikely(initialSyncHangAfterCloningFiles.shouldFail()) &&
                       !_isShuttingDown()) {
                    mongo::sleepsecs(1);
                }
                lock.lock();
            }
            LOGV2_DEBUG(128452, 1, "Finished cloning files from backup cursor");
            // finished cloning files from the current batch returned by
            // $backupCursor/$backupCursorExtend
            // update _lastApplied to match current on disk state
            _lastApplied.opTime = _oplogEnd;
            _lastApplied.wallTime = Date_t::fromDurationSinceEpoch(Seconds{_oplogEnd.getSecs()});
            // at this point we need to check if last applied is in correct range to decide if
            // we need to extend backup cursor. But before that we need to retrieve current last
            // applied optime from the sync source. To do that we schedule replSetGetStatus command
            executor::RemoteCommandRequest replSetGetStatusRequest(
                _syncSource, DatabaseName::kAdmin, BSON("replSetGetStatus" << 1), nullptr);
            auto scheduleResult =
                (*_attemptExec)
                    ->scheduleRemoteCommand(
                        replSetGetStatusRequest,
                        [this, extensionsUsed, onCompletionGuard](
                            const executor::TaskExecutor::RemoteCommandCallbackArgs& args) {
                            _compareLastAppliedCallback(args, extensionsUsed, onCompletionGuard);
                        });
            status = scheduleResult.getStatus();
            if (!status.isOK()) {
                onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
                return;
            }
            _currentHandle = scheduleResult.getValue();
        }
    }
} catch (const DBException&) {
    // Report exception as an initial syncer failure.
    stdx::unique_lock<Latch> lock(_mutex);
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
}

void InitialSyncerFCB::_compareLastAppliedCallback(
    const executor::TaskExecutor::RemoteCommandCallbackArgs& callbackArgs,
    const int extensionsUsed,
    // NOLINTNEXTLINE(*-unnecessary-value-param)
    std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept try {
    stdx::unique_lock<Latch> lock(_mutex);
    auto status = _checkForShutdownAndConvertStatus_inlock(
        callbackArgs.response.status, "error executing replSetGetStatus on the sync source");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    auto appliedOpTime =
        parseOpTimeFromBSON(callbackArgs.response.data["optimes"]["appliedOpTime"].Obj());
    auto lastAppliedTS = appliedOpTime.getTimestamp();
    LOGV2_DEBUG(128456,
                1,
                "Comparing last applied timestamps",
                "local"_attr = _lastApplied.opTime.getSecs(),
                "remote"_attr = lastAppliedTS.getSecs());
    if (_lastApplied.opTime.getSecs() + fileBasedInitialSyncMaxLagSec >= lastAppliedTS.getSecs()) {
        // The lag is OK, we can conclude the backup cursor loop
        // file cloning is completed - close backup cursor
        LOGV2_DEBUG(128453, 1, "The lag is acceptable. Switching to downloaded files");
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
        }
        return;
    }
    // The lag is too big, we need to extend the backup cursor
    if (!(extensionsUsed < fileBasedInitialSyncMaxCyclesWithoutProgress)) {
        LOGV2_DEBUG(128454, 1, "The lag is too big and no backup cursor extensions left");
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(
            lock,
            _invalidSyncSource_inlock(_syncSource,
                                      kDenylistTemporary,
                                      str::stream()
                                          << "No backup cursor extensions left. Node is still "
                                             "behind sync source more than the allowed lag: "
                                          << _lastApplied.opTime.getSecs() << " + "
                                          << fileBasedInitialSyncMaxLagSec << " < "
                                          << lastAppliedTS.getSecs()));
        return;
    }

    LOGV2_DEBUG(128455, 1, "The lag is too big, extending backup cursor");
    // appliedOpTime is the new _oplogEnd value. We set it here manually because $backupCursorExtend
    // does not return metadata
    _oplogEnd = appliedOpTime;
    // execute $backupCursorExtend to the lastAppliedTS moment
    status = _scheduleWorkAndSaveHandle_inlock(
        [this, extensionsUsed, onCompletionGuard, lastAppliedTS](
            const executor::TaskExecutor::CallbackArgs& args) {
            _fetchBackupCursorCallback(
                args,
                extensionsUsed + 1,
                onCompletionGuard,
                [backupId = _backupId, ts = lastAppliedTS] {
                    AggregateCommandRequest aggRequest(
                        NamespaceString::makeCollectionlessAggregateNSS(DatabaseName::kAdmin),
                        {BSON("$backupCursorExtend" << BSON(
                                  "backupId"
                                  << backupId << "timestamp"
                                  << ts))});  // We must set a writeConcern on internal commands.
                    aggRequest.setWriteConcern(WriteConcernOptions());
                    return aggRequest.toBSON(BSONObj());
                });
        },
        &_fetchBackupCursorHandle,
        "_fetchBackupCursorCallback(extend)");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
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
    ChangeStorageGuard changeStorageGuard(this);
    stdx::unique_lock<Latch> lock(_mutex);

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
    ScopeGuard storageGuard([this, &lock, opCtx = opCtx.get()] {
        // Restore storage location back to original dbpath in case of any failure
        _restoreStorageLocation(lock, opCtx);
    });
    // retrieve the current on-disk replica set configuration
    auto* rs = repl::ReplicationCoordinator::get(opCtx->getServiceContext());
    invariant(rs);
    BSONObj savedRSConfig = rs->getConfigBSON();

    // Switch storage to be pointing to the set of downloaded files
    lock.unlock();
    status = _switchStorageLocation(opCtx.get(),
                                    _cfgDBPath + "/.initialsync",
                                    startup_recovery::StartupRecoveryMode::kReplicaSetMember);
    lock.lock();
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }
    _needToSwitchBackToOriginalDBPath = true;

    // do some cleanup
    auto* consistencyMarkers = _replicationProcess->getConsistencyMarkers();
    consistencyMarkers->setMinValid(opCtx.get(),
                                    OpTime{kTimestampOne, repl::OpTime::kUninitializedTerm});
    // _oplogEnd gets its first value from the metadata returned by $backupCursor
    // The code around $backupCursorExtend sets _oplogEnd to the appliedOpTime value returned by
    // replSetGetStatus
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
            _executeRecovery(args, onCompletionGuard);
        },
        &_currentHandle,
        "_executeRecovery");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    storageGuard.dismiss();
} catch (const DBException&) {
    // Report exception as an initial syncer failure.
    stdx::unique_lock<Latch> lock(_mutex);
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
}

void InitialSyncerFCB::_executeRecovery(
    const executor::TaskExecutor::CallbackArgs& callbackArgs,
    // NOLINTNEXTLINE(*-unnecessary-value-param)
    std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept try {
    stdx::unique_lock<Latch> lock(_mutex);

    auto opCtx = makeOpCtx();
    ScopeGuard storageGuard([this, &lock, opCtx = opCtx.get()] {
        Lock::GlobalLock lk(opCtx, MODE_X);
        // Restore storage location back to original dbpath in case of any failure
        _restoreStorageLocation(lock, opCtx);
    });

    auto status =
        _checkForShutdownAndConvertStatus_inlock(callbackArgs, "_executeRecovery cancelled");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    auto* serviceCtx = opCtx->getServiceContext();
    inReplicationRecovery(serviceCtx).store(true);
    ON_BLOCK_EXIT([serviceCtx] { inReplicationRecovery(serviceCtx).store(false); });

    _replicationProcess->getReplicationRecovery()->recoverFromOplogAsStandalone(opCtx.get(), true);

    // Aborts all active, two-phase index builds.
    [[maybe_unused]] auto stoppedIndexBuilds =
        IndexBuildsCoordinator::get(serviceCtx)->stopIndexBuildsForRollback(opCtx.get());

    if (!stoppedIndexBuilds.empty()) {
        LOGV2_WARNING(128498,
                      "Aborted active index builds during initial sync recovery",
                      "numIndexBuilds"_attr = stoppedIndexBuilds.size());
    }

    // Set stable timestamp
    if (BSONObj lastEntry;
        Helpers::getLast(opCtx.get(), NamespaceString::kRsOplogNamespace, lastEntry)) {
        auto lastTime = repl::OpTimeAndWallTime::parse(lastEntry);
        _storage->setStableTimestamp(serviceCtx, lastTime.opTime.getTimestamp());
    }

    // schedule next task
    status = _scheduleWorkAndSaveHandle_inlock(
        [this, onCompletionGuard](const executor::TaskExecutor::CallbackArgs& args) {
            _switchToDummyToDBPathCallback(args, onCompletionGuard);
        },
        &_currentHandle,
        "_switchToDummyToDBPathCallback");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    storageGuard.dismiss();
} catch (const DBException&) {
    // Report exception as an initial syncer failure.
    stdx::unique_lock<Latch> lock(_mutex);
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
}

void InitialSyncerFCB::_switchToDummyToDBPathCallback(
    const executor::TaskExecutor::CallbackArgs& callbackArgs,
    // NOLINTNEXTLINE(*-unnecessary-value-param)
    std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept try {
    ChangeStorageGuard changeStorageGuard(this);
    stdx::unique_lock<Latch> lock(_mutex);

    {
        auto opCtx = makeOpCtx();
        Lock::GlobalLock lk(opCtx.get(), MODE_X);
        ScopeGuard storageGuard([this, &lock, opCtx = opCtx.get()] {
            // Restore storage location back to original dbpath in case of any failure
            _restoreStorageLocation(lock, opCtx);
        });

        auto status = _checkForShutdownAndConvertStatus_inlock(
            callbackArgs, "_switchToDummyToDBPathCallback cancelled");
        if (!status.isOK()) {
            onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
            return;
        }

        // Switch storage to a dummy location
        lock.unlock();
        status = _switchStorageLocation(opCtx.get(), _cfgDBPath + "/.initialsync/.dummy");
        lock.lock();
        if (!status.isOK()) {
            onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
            return;
        }
        _needToSwitchBackToOriginalDBPath = true;

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

        // Here the storage is switched back to the original location by the storageGuard
        // Do not dismiss storageGuard because it should work in both cases of success and failure
    }

    // schedule next task
    auto status = _scheduleWorkAndSaveHandle_inlock(
        [this, onCompletionGuard](const executor::TaskExecutor::CallbackArgs& args) {
            _finalizeAndCompleteCallback(args, onCompletionGuard);
        },
        &_currentHandle,
        "_finalizeAndCompleteCallback");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }
} catch (const DBException&) {
    // Report exception as an initial syncer failure.
    stdx::unique_lock<Latch> lock(_mutex);
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
}

void InitialSyncerFCB::_finalizeAndCompleteCallback(
    const executor::TaskExecutor::CallbackArgs& callbackArgs,
    // NOLINTNEXTLINE(*-unnecessary-value-param)
    std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept try {
    stdx::lock_guard<Latch> lock(_mutex);
    auto status = _checkForShutdownAndConvertStatus_inlock(
        callbackArgs, "_finalizeAndCompleteCallback cancelled");
    if (!status.isOK()) {
        onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, status);
        return;
    }

    {
        auto opCtx = makeOpCtx();
        // Attach JournalListener to the new instance of storage engine
        auto* journalListener = _dataReplicatorExternalState->getReplicationJournalListener();
        opCtx->getServiceContext()->getStorageEngine()->setJournalListener(journalListener);
    }

    // Successfully complete initial sync
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, _lastApplied);
} catch (const DBException&) {
    // Report exception as an initial syncer failure.
    stdx::unique_lock<Latch> lock(_mutex);
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
}


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
