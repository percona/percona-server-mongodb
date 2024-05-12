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

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "mongo/base/error_codes.h"
#include "mongo/base/status.h"
#include "mongo/bson/bsonmisc.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/bson/timestamp.h"
#include "mongo/client/fetcher.h"
#include "mongo/db/client.h"
#include "mongo/db/feature_compatibility_version_parser.h"
#include "mongo/db/index_builds_coordinator.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/repl/all_database_cloner.h"
#include "mongo/db/repl/initial_sync_state.h"
#include "mongo/db/repl/initial_syncer_common_stats.h"
#include "mongo/db/repl/initial_syncer_factory.h"
#include "mongo/db/repl/initial_syncer_interface.h"
#include "mongo/db/repl/optime.h"
#include "mongo/db/repl/repl_server_parameters_gen.h"
#include "mongo/db/repl/replication_consistency_markers.h"
#include "mongo/db/repl/replication_process.h"
#include "mongo/db/repl/storage_interface.h"
#include "mongo/db/repl/sync_source_selector.h"
#include "mongo/db/repl/tenant_migration_access_blocker_util.h"
#include "mongo/db/repl/transaction_oplog_application.h"
#include "mongo/db/serverless/serverless_operation_lock_registry.h"
#include "mongo/executor/task_executor.h"
#include "mongo/logv2/log.h"
#include "mongo/platform/compiler.h"  // IWYU pragma: keep
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

// Used to reset the oldest timestamp during initial sync to a non-null timestamp.
const Timestamp kTimestampOne(0, 1);

ServiceContext::UniqueOperationContext makeOpCtx() {
    return cc().makeOperationContext();
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
        LOGV2_DEBUG(4427201,
                    1,
                    "Cancelling the current initial sync attempt.",
                    "currentAttempt"_attr = _stats.failedInitialSyncAttempts + 1);
        _cancelRemainingWork_inlock();
    } else {
        LOGV2_DEBUG(4427202,
                    1,
                    "There is no initial sync attempt to cancel because the initial syncer is not "
                    "currently active.");
    }
}

void InitialSyncerFCB::_cancelRemainingWork_inlock() {
    _cancelHandle_inlock(_startInitialSyncAttemptHandle);
    _cancelHandle_inlock(_chooseSyncSourceHandle);
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
        LOGV2(21161,
              "Error creating initial sync progress object: {error}",
              "Error creating initial sync progress object",
              "error"_attr = e.toString());
    }
    BSONObjBuilder bob;
    _appendInitialSyncProgressMinimal_inlock(&bob);
    return bob.obj();
}

void InitialSyncerFCB::setCreateClientFn_forTest(const CreateClientFn& createClientFn) {
    LockGuard lk(_mutex);
    _createClientFn = createClientFn;
}

void InitialSyncerFCB::setClonerExecutor_forTest(
    std::shared_ptr<executor::TaskExecutor> clonerExec) {
    _clonerExec = std::move(clonerExec);
}

void InitialSyncerFCB::waitForCloner_forTest() {
    _initialSyncState->allDatabaseClonerFuture.wait();
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

    LOGV2(21163,
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

    LOGV2(21164,
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

    LOGV2_DEBUG(
        21165, 2, "Resetting sync source so a new one can be chosen for this initial sync attempt");
    _syncSource = HostAndPort();

    LOGV2_DEBUG(21166, 2, "Resetting all optimes before starting this initial sync attempt");
    _opts.resetOptimes();
    _lastApplied = {OpTime(), Date_t()};
    _lastFetched = {};

    LOGV2_DEBUG(
        21167, 2, "Resetting the oldest timestamp before starting this initial sync attempt");
    auto* storageEngine = getGlobalServiceContext()->getStorageEngine();
    if (storageEngine) {
        // Set the oldestTimestamp to one because WiredTiger does not allow us to set it to zero
        // since that would also set the all_durable point to zero. We specifically don't set
        // the stable timestamp here because that will trigger taking a first stable checkpoint even
        // though the initialDataTimestamp is still set to kAllowUnstableCheckpointsSentinel.
        storageEngine->setOldestTimestamp(kTimestampOne, true /*force*/);
    }

    LOGV2_DEBUG(21168,
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
        LOGV2(5284800, "initialSyncHangBeforeChoosingSyncSourceFCB fail point enabled");
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
        LOGV2_DEBUG(21169,
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
        LOGV2(21170,
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

} catch (const DBException&) {
    // Report exception as an initial syncer failure.
    stdx::unique_lock<Latch> lock(_mutex);
    onCompletionGuard->setResultAndCancelRemainingWork_inlock(lock, exceptionToStatus());
}

Status InitialSyncerFCB::_truncateOplogAndDropReplicatedDatabases() {
    // truncate oplog; drop user databases.
    LOGV2_DEBUG(4540700,
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
    LOGV2_DEBUG(4540701,
                2,
                "Truncating the existing oplog: {namespace}",
                "Truncating the existing oplog",
                logAttrs(NamespaceString::kRsOplogNamespace));
    Timer timer;
    auto status = _storage->truncateCollection(opCtx.get(), NamespaceString::kRsOplogNamespace);
    LOGV2(21173,
          "Initial syncer oplog truncation finished in: {durationMillis}ms",
          "Initial syncer oplog truncation finished",
          "durationMillis"_attr = timer.millis());
    if (!status.isOK()) {
        // 1a.) Create the oplog.
        LOGV2_DEBUG(4540702,
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
    LOGV2_DEBUG(21175, 2, "Dropping user databases");
    return _storage->dropReplicatedDatabases(opCtx.get());
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
        LOGV2(5032000,
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
    LOGV2_DEBUG(4431600,
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
        LOGV2(21179,
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
            LOGV2_WARNING(21197,
                          "Unable to schedule initial syncer completion task due to "
                          "{error}. Running callback on current thread.",
                          "Unable to schedule initial syncer completion task. Running callback on "
                          "current thread",
                          "error"_attr = redact(scheduleResult.getStatus()));
            _finishCallback(result);
        }
    });

    LOGV2(21191, "Initial sync attempt finishing up");

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
        LOGV2(21193, "failAndHangInitialSyncFCB fail point enabled");
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

    LOGV2_ERROR(21200,
                "Initial sync attempt failed -- attempts left: "
                "{attemptsLeft} cause: "
                "{error}",
                "Initial sync attempt failed",
                "attemptsLeft"_attr =
                    (_stats.maxFailedInitialSyncAttempts - _stats.failedInitialSyncAttempts),
                "error"_attr = redact(result.getStatus()));

    // Check if need to do more retries.
    if (!hasRetries) {
        LOGV2_FATAL_CONTINUE(21202,
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
        LOGV2(21194,
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
        LOGV2_WARNING(21198,
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
        LOGV2(5825800,
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
