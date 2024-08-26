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


#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <boost/filesystem.hpp>

#include "mongo/base/status.h"
#include "mongo/base/status_with.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/client/dbclient_connection.h"
#include "mongo/client/fetcher.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/repl/callback_completion_guard.h"
#include "mongo/db/repl/data_replicator_external_state.h"
#include "mongo/db/repl/initial_sync_shared_data.h"
#include "mongo/db/repl/initial_syncer_interface.h"
#include "mongo/db/repl/multiapplier.h"
#include "mongo/db/repl/optime.h"
#include "mongo/db/repl/rollback_checker.h"
#include "mongo/db/repl/tenant_migration_shared_data.h"
#include "mongo/executor/scoped_task_executor.h"
#include "mongo/executor/task_executor.h"
#include "mongo/platform/atomic_word.h"
#include "mongo/platform/mutex.h"
#include "mongo/stdx/condition_variable.h"
#include "mongo/util/concurrency/thread_pool.h"
#include "mongo/util/concurrency/with_lock.h"
#include "mongo/util/duration.h"
#include "mongo/util/net/hostandport.h"
#include "mongo/util/time_support.h"
#include "mongo/util/uuid.h"

namespace mongo {
namespace repl {

struct InitialSyncState;
class ReplicationProcess;
class StorageInterface;

/**
 * The initial syncer provides services to keep collection in sync by replicating
 * changes via an oplog source to the local system storage.
 *
 * This class will use existing machinery like the Executor to schedule work and
 * network tasks, as well as provide serial access and synchronization of state.
 *
 *
 * Entry Points:
 *      -- startup: Start initial sync.
 */
class InitialSyncerFCB : public InitialSyncerInterface {
public:
    InitialSyncerFCB(const InitialSyncerFCB&) = delete;
    InitialSyncerFCB& operator=(const InitialSyncerFCB&) = delete;
    InitialSyncerFCB(InitialSyncerFCB&&) = delete;
    InitialSyncerFCB& operator=(InitialSyncerFCB&&) = delete;

    /**
     * Callback completion guard for initial syncer.
     */
    using OnCompletionGuard = CallbackCompletionGuard<StatusWith<OpTimeAndWallTime>>;

    struct InitialSyncAttemptInfo {
        int durationMillis;
        Status status;
        HostAndPort syncSource;
        int rollBackId;
        int operationsRetried;
        int totalTimeUnreachableMillis;

        std::string toString() const;
        BSONObj toBSON() const;
        void append(BSONObjBuilder* builder) const;
    };

    struct Stats {
        std::uint32_t failedInitialSyncAttempts{0};
        std::uint32_t maxFailedInitialSyncAttempts{0};
        Date_t initialSyncStart;
        Date_t initialSyncEnd;
        std::vector<InitialSyncerFCB::InitialSyncAttemptInfo> initialSyncAttemptInfos;
        std::weak_ptr<executor::TaskExecutor> exec;

        std::string toString() const;
        BSONObj toBSON() const;
        void append(BSONObjBuilder* builder) const;
    };

    InitialSyncerFCB(InitialSyncerInterface::Options opts,
                     std::unique_ptr<DataReplicatorExternalState> dataReplicatorExternalState,
                     ThreadPool* writerPool,
                     StorageInterface* storage,
                     ReplicationProcess* replicationProcess,
                     const OnCompletionFn& onCompletion);

    ~InitialSyncerFCB() override;

    /**
     * Returns true if an initial sync is currently running or in the process of shutting down.
     */
    bool isActive() const;

    std::string getInitialSyncMethod() const final;

    bool allowLocalDbAccess() const final {
        return true;
    }

    Status startup(OperationContext* opCtx, std::uint32_t maxAttempts) noexcept final;

    Status shutdown() final;

    void join() final;

    /**
     * Returns internal state in a loggable format.
     */
    std::string getDiagnosticString() const;

    BSONObj getInitialSyncProgress() const final;

    void cancelCurrentAttempt() final;

    // State transitions:
    // PreStart --> Running --> ShuttingDown --> Complete
    // It is possible to skip intermediate states. For example, calling shutdown() when the data
    // replicator has not started will transition from PreStart directly to Complete.
    enum class State { kPreStart, kRunning, kShuttingDown, kComplete };

    /**
     * Returns current initial syncer state.
     * For testing only.
     */
    State getState_forTest() const;

    /**
     * Returns the wall clock time component of _lastApplied.
     * For testing only.
     */
    Date_t getWallClockTime_forTest() const;

    /**
     * Sets the allowed outage duration in _sharedData.
     * For testing only.
     */
    void setAllowedOutageDuration_forTest(Milliseconds allowedOutageDuration);

private:
    /**
     * Attributes of remote file received from $backupCursor
     */
    struct BackupFile {
        std::string name;
        size_t size;
    };

    /**
     * Returns true if we are still processing initial sync tasks (_state is either Running or
     * Shutdown).
     */
    bool _isActive_inlock() const;

    /**
     * Cancels all outstanding work.
     * Used by shutdown() and CompletionGuard::setResultAndCancelRemainingWork().
     */
    void _cancelRemainingWork_inlock();

    /**
     * Returns true if the initial syncer has received a shutdown request (_state is ShuttingDown).
     */
    bool _isShuttingDown() const;
    bool _isShuttingDown_inlock() const;

    /**
     * Initial sync flowchart:
     *
     *     startup()
     *         |
     *         |
     *         V
     *     _setUp_inlock()
     *         |
     *         |
     *         V
     *    _startInitialSyncAttemptCallback()
     *         |
     *         |
     *         |<-------+
     *         |        |
     *         |        | (bad sync source)
     *         |        |
     *         V        |
     *    _chooseSyncSourceCallback()
     *         |
     *         |
     *         | (good sync source found)
     *         |
     *         |
     *         V
     *    _truncateOplogAndDropReplicatedDatabases()
     *         |
     *         |
     *         V
     *    _rollbackCheckerResetCallback()
     *         |
     *         |
     *         V
     *   _lastOplogEntryFetcherCallbackForDefaultBeginFetchingOpTime() [removed]
     *         |
     *         |
     *         V
     *   _getBeginFetchingOpTimeCallback() [removed]
     *         |
     *         |
     *         V
     *    _lastOplogEntryFetcherCallbackForBeginApplyingTimestamp() [removed]
     *         |
     *         |
     *         V
     *    _fcvFetcherCallback()
     *         |
     *         |
     *         +------------------------------+
     *         |                              |
     *         |                              |
     *         V                              V
     *    _oplogFetcherCallback[removed]  _allDatabaseClonerCallback [removed]
     *         |                              |
     *         |                              |
     *         |                              V
     *         |                          _lastOplogEntryFetcherCallbackForStopTimestamp() [removed]
     *         |                              |       |
     *         |                              |       |
     *         |            (no ops to apply) |       | (have ops to apply)
     *         |                              |       |
     *         |                              |       V
     *         |                              |   _getNextApplierBatchCallback() [removed]
     *         |                              |       |                       ^
     *         |                              |       |                       |
     *         |                              |       |             (end ts not reached)
     *         |                              |       |                       |
     *         |                              |       V                       |
     *         |                              |   _multiApplierCallback()-----+ [removed]
     *         |                              |       |
     *         |                              |       |
     *         |                        (reached end timestamp)
     *         |                              |       |
     *         |                              V       V
     *         |                _rollbackCheckerCheckForRollbackCallback() [removed]
     *         |                              |
     *         |                              |
     *         +------------------------------+
     *         |
     *         |
     *         V
     *    _finishInitialSyncAttempt()
     *         |
     *         |
     *         V
     *    _finishCallback()
     */

    /**
     * Sets up internal state to begin initial sync.
     */
    void _setUp_inlock(OperationContext* opCtx, std::uint32_t initialSyncMaxAttempts);

    /**
     * Tears down internal state before reporting final status to caller.
     */
    void _tearDown_inlock(OperationContext* opCtx,
                          const StatusWith<OpTimeAndWallTime>& lastApplied);

    /**
     * Callback to start a single initial sync attempt.
     */
    void _startInitialSyncAttemptCallback(const executor::TaskExecutor::CallbackArgs& callbackArgs,
                                          std::uint32_t initialSyncAttempt,
                                          std::uint32_t initialSyncMaxAttempts) noexcept;

    /**
     * Callback to obtain sync source from sync source selector.
     * For every initial sync attempt, we will try up to 'numInitialSyncConnectAttempts' times (at
     * an interval of '_opts.syncSourceRetryWait' ms) to obtain a valid sync source before giving up
     * and returning ErrorCodes::InitialSyncOplogSourceMissing.
     */
    void _chooseSyncSourceCallback(const executor::TaskExecutor::CallbackArgs& callbackArgs,
                                   std::uint32_t chooseSyncSourceAttempt,
                                   std::uint32_t chooseSyncSourceMaxAttempts,
                                   std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept;

    /**
     * Callback to execute backup cursor on the sync source
     */
    void _fetchBackupCursorCallback(const executor::TaskExecutor::CallbackArgs& callbackArgs,
                                    std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept;

    /**
     * Callback to transfer file from the sync source
     */
    void _transferFileCallback(const executor::TaskExecutor::CallbackArgs& callbackArgs,
                               std::size_t fileIdx,
                               std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept;

    /**
     * Switch to downloaded files and do some cleanup of the 'local' db
     */
    void _switchToDownloadedCallback(const executor::TaskExecutor::CallbackArgs& callbackArgs,
                                     std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept;

    /**
     * Switch to dummy location, remove local files from dbpath, move downloaded files to the dbpath
     * Switch back to dbpath
     */
    void _switchToDummyToDBPathCallback(
        const executor::TaskExecutor::CallbackArgs& callbackArgs,
        std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept;

    /**
     * Finalize and complete inital sync
     */
    void _finalizeAndCompleteCallback(
        const executor::TaskExecutor::CallbackArgs& callbackArgs,
        std::shared_ptr<OnCompletionGuard> onCompletionGuard) noexcept;

    /**
     * This function does the following:
     *      1.) Truncate oplog.
     *      2.) Drop user databases (replicated dbs).
     */
    Status _truncateOplogAndDropReplicatedDatabases();

    /**
     * Callback for rollback checker's first replSetGetRBID command before starting data cloning.
     */
    void _rollbackCheckerResetCallback(const RollbackChecker::Result& result,
                                       std::shared_ptr<OnCompletionGuard> onCompletionGuard);

    /**
     * Callback for the '_fCVFetcher'. A successful response lets us check if the remote node
     * is in a currently acceptable fCV and if it has a 'targetVersion' set.
     */
    void _fcvFetcherCallback(const StatusWith<Fetcher::QueryResponse>& result,
                             std::shared_ptr<OnCompletionGuard> onCompletionGuard,
                             const OpTime& lastOpTime,
                             OpTime& beginFetchingOpTime);

    /**
     * Reports result of current initial sync attempt. May schedule another initial sync attempt
     * depending on shutdown state and whether we've exhausted all initial sync retries.
     */
    void _finishInitialSyncAttempt(const StatusWith<OpTimeAndWallTime>& lastApplied);

    /**
     * Invokes completion callback and transitions state to State::kComplete.
     */
    void _finishCallback(StatusWith<OpTimeAndWallTime> lastApplied);

    // Obtains a valid sync source from the sync source selector.
    // Returns error if a sync source cannot be found.
    StatusWith<HostAndPort> _chooseSyncSource_inlock();

    void _appendInitialSyncProgressMinimal_inlock(BSONObjBuilder* bob) const;
    BSONObj _getInitialSyncProgress_inlock() const;

    /**
     * Check if a status is one which means there's a retriable error and we should retry the
     * current operation, and records whether an operation is currently being retried.  Note this
     * can only handle one operation at a time (i.e. it should not be used in both parts of the
     * "split" section of Initial Sync)
     */
    bool _shouldRetryError(WithLock lk, Status status);

    /**
     * Indicates we are no longer handling a retriable error.
     */
    void _clearRetriableError(WithLock lk);

    /**
     * Checks the given status (or embedded status inside the callback args) and current data
     * replicator shutdown state. If the given status is not OK or if we are shutting down, returns
     * a new error status that should be passed to _finishCallback. The reason in the new error
     * status will include 'message'.
     * Otherwise, returns Status::OK().
     */
    Status _checkForShutdownAndConvertStatus_inlock(
        const executor::TaskExecutor::CallbackArgs& callbackArgs, const std::string& message);
    Status _checkForShutdownAndConvertStatus_inlock(const Status& status,
                                                    const std::string& message);

    /**
     * Schedules work to be run by the task executor.
     * Saves handle if work was successfully scheduled.
     * Returns scheduleWork status (without the handle).
     */
    Status _scheduleWorkAndSaveHandle_inlock(executor::TaskExecutor::CallbackFn work,
                                             executor::TaskExecutor::CallbackHandle* handle,
                                             const std::string& name);
    Status _scheduleWorkAtAndSaveHandle_inlock(Date_t when,
                                               executor::TaskExecutor::CallbackFn work,
                                               executor::TaskExecutor::CallbackHandle* handle,
                                               const std::string& name);

    /**
     * Cancels task executor callback handle if not null.
     */
    void _cancelHandle_inlock(executor::TaskExecutor::CallbackHandle handle);

    /**
     * Starts up component and checks initial syncer's shutdown state at the same time.
     * If component's startup() fails, resets 'component' (which is assumed to be a unique_ptr
     * to the component type).
     */
    template <typename Component>
    Status _startupComponent_inlock(Component& component);

    /**
     * Shuts down component if not null.
     */
    template <typename Component>
    void _shutdownComponent_inlock(Component& component);

    /**
     * Temporary location to declare all FCB-related private methods
     * TODO: reorganize
     */
    Status _deleteLocalFiles();

    Status _moveFiles(const boost::filesystem::path& sourceDir,
                      const boost::filesystem::path& destDir);

    StatusWith<std::vector<std::string>> _getBackupFiles();

    Status _switchStorageLocation(OperationContext* opCtx, const std::string& newLocation);

    Status _killBackupCursor_inlock();

    // Counts how many documents have been refetched from the source in the current batch.
    AtomicWord<unsigned> _fetchCount;

    //
    // All member variables are labeled with one of the following codes indicating the
    // synchronization rules for accessing them.
    //
    // (R)  Read-only in concurrent operation; no synchronization required.
    // (S)  Self-synchronizing; access in any way from any context.
    // (M)  Reads and writes guarded by _mutex
    // (X)  Reads and writes must be performed in a callback in _exec
    // (MX) Must hold _mutex and be in a callback in _exec to write; must either hold
    //      _mutex or be in a callback in _exec to read.

    mutable Mutex _mutex = MONGO_MAKE_LATCH("InitialSyncerFCB::_mutex");        // (S)
    const InitialSyncerInterface::Options _opts;                                // (R)
    std::unique_ptr<DataReplicatorExternalState> _dataReplicatorExternalState;  // (R)
    std::shared_ptr<executor::TaskExecutor> _exec;                              // (R)
    std::unique_ptr<executor::ScopedTaskExecutor> _attemptExec;                 // (X)
    // The executor that the Cloner thread runs on.  In production code this is the same as _exec,
    // but for unit testing, _exec is single-threaded and our NetworkInterfaceMock runs it in
    // lockstep with the unit test code.  If we pause the cloners using failpoints
    // NetworkInterfaceMock is unaware of this and this causes our unit tests to deadlock.
    std::shared_ptr<executor::TaskExecutor> _clonerExec;               // (R)
    std::unique_ptr<executor::ScopedTaskExecutor> _clonerAttemptExec;  // (X)
    ThreadPool* _writerPool;                                           // (R)
    StorageInterface* _storage;                                        // (R)
    ReplicationProcess* _replicationProcess;                           // (S)
    std::vector<std::string> _localFiles;                              // TODO:
    std::vector<BackupFile> _remoteFiles;                              // TODO:
    UUID _backupId;                                                    // TODO:
    std::string _remoteDBPath;                                         // TODO:
    OpTime _oplogEnd;                                                  // TODO:
    const std::string _cfgDBPath;                                      // TODO:
    std::unique_ptr<BackupCursorInfo> _backupCursorInfo;               // TODO:

    // This is invoked with the final status of the initial sync. If startup() fails, this callback
    // is never invoked. The caller gets the last applied optime when the initial sync completes
    // successfully or an error status.
    // '_onCompletion' is cleared on completion (in _finishCallback()) in order to release any
    // resources that might be held by the callback function object.
    OnCompletionFn _onCompletion;  // (M)

    // Handle to currently scheduled _startInitialSyncAttemptCallback() task.
    executor::TaskExecutor::CallbackHandle _startInitialSyncAttemptHandle;  // (M)

    // Handle to currently scheduled _chooseSyncSourceCallback() task.
    executor::TaskExecutor::CallbackHandle _chooseSyncSourceHandle;  // (M)

    // Handle to currently scheduled _fetchBackupCursorCallback() task.
    executor::TaskExecutor::CallbackHandle _fetchBackupCursorHandle;  // (M)

    // Handle to currently scheduled _transferFileCallback() task.
    executor::TaskExecutor::CallbackHandle _transferFileHandle;  // (M)

    // Handle to currently scheduled  task (one of several tasks in the file move/dbpath change
    // sequence).
    executor::TaskExecutor::CallbackHandle _currentHandle;  // (M)

    // RollbackChecker to get rollback ID before and after each initial sync attempt.
    std::unique_ptr<RollbackChecker> _rollbackChecker;  // (M)

    // Handle returned from RollbackChecker::reset().
    RollbackChecker::CallbackHandle _getBaseRollbackIdHandle;  // (M)

    // Handle returned from RollbackChecker::checkForRollback().
    RollbackChecker::CallbackHandle _getLastRollbackIdHandle;  // (M)

    // The operation, if any, currently being retried because of a network error.
    InitialSyncSharedData::RetryableOperation _retryingOperation;  // (M)

    std::unique_ptr<InitialSyncState> _initialSyncState;   // (M)
    std::unique_ptr<Fetcher> _beginFetchingOpTimeFetcher;  // (S)
    std::unique_ptr<Fetcher> _fCVFetcher;                  // (S)
    std::unique_ptr<Fetcher> _backupCursorFetcher;         // (S)
    std::unique_ptr<MultiApplier> _applier;                // (M)
    HostAndPort _syncSource;                               // (M)
    std::unique_ptr<DBClientConnection> _client;           // (M)
    OpTime _lastFetched;                                   // (MX)
    OpTimeAndWallTime _lastApplied;                        // (MX)

    // Used to signal changes in _state.
    mutable stdx::condition_variable _stateCondition;

    // Current initial syncer state. See comments for State enum class for details.
    State _state = State::kPreStart;  // (M)

    // Used to create the DBClientConnection for the cloners
    CreateClientFn _createClientFn;

    // Contains stats on the current initial sync request (includes all attempts).
    // To access these stats in a user-readable format, use getInitialSyncProgress().
    Stats _stats;  // (M)

    // Data shared by cloners and fetcher.  Follow InitialSyncSharedData synchronization rules.
    std::unique_ptr<InitialSyncSharedData> _sharedData;  // (S)

    // Amount of time an outage is allowed to continue before the initial sync attempt is marked
    // as failed.
    Milliseconds _allowedOutageDuration;  // (M)

    // The initial sync attempt has been canceled
    bool _attemptCanceled = false;  // (X)
};

}  // namespace repl
}  // namespace mongo
