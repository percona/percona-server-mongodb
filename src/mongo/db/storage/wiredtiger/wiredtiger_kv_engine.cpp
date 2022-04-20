/**
 *    Copyright (C) 2018-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kStorage

#define LOGV2_FOR_RECOVERY(ID, DLEVEL, MESSAGE, ...) \
    LOGV2_DEBUG_OPTIONS(ID, DLEVEL, {logv2::LogComponent::kStorageRecovery}, MESSAGE, ##__VA_ARGS__)
#define LOGV2_FOR_ROLLBACK(ID, DLEVEL, MESSAGE, ...) \
    LOGV2_DEBUG_OPTIONS(                             \
        ID, DLEVEL, {logv2::LogComponent::kReplicationRollback}, MESSAGE, ##__VA_ARGS__)

#include "mongo/platform/basic.h"

#ifdef _WIN32
#define NVALGRIND
#endif

#include <fmt/format.h>
#include <iomanip>
#include <memory>
#include <regex>

#include "mongo/db/storage/wiredtiger/wiredtiger_kv_engine.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/system/error_code.hpp>
#include <fmt/format.h>
#include <libarchive/archive.h>
#include <libarchive/archive_entry.h>
#include <valgrind/valgrind.h>


#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/utils/logging/AWSLogging.h>
#include <aws/core/utils/logging/FormattedLogSystem.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/AbortMultipartUploadRequest.h>
#include <aws/s3/model/CreateBucketRequest.h>
#include <aws/s3/model/CreateMultipartUploadRequest.h>
#include <aws/s3/model/ListObjectsRequest.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <aws/transfer/TransferManager.h>

#include "mongo/base/error_codes.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/bson/dotted_path_support.h"
#include "mongo/db/catalog/collection.h"
#include "mongo/db/client.h"
#include "mongo/db/commands/server_status_metric.h"
#include "mongo/db/concurrency/locker.h"
#include "mongo/db/concurrency/write_conflict_exception.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/global_settings.h"
#include "mongo/db/index/index_descriptor.h"
#include "mongo/db/mongod_options_storage_gen.h"
#include "mongo/db/repl/repl_settings.h"
#include "mongo/db/repl/replication_coordinator.h"
#include "mongo/db/server_options.h"
#include "mongo/db/server_recovery.h"
#include "mongo/db/service_context.h"
#include "mongo/db/snapshot_window_options.h"
#include "mongo/db/storage/journal_listener.h"
#include "mongo/db/storage/storage_file_util.h"
#include "mongo/db/storage/storage_options.h"
#include "mongo/db/storage/storage_parameters_gen.h"
#include "mongo/db/storage/storage_repair_observer.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_backup_cursor_hooks.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_cursor.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_customization_hooks.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_encryption_hooks.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_extensions.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_global_options.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_index.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_parameters_gen.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_record_store.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_recovery_unit.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_session_cache.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_size_storer.h"
#include "mongo/logv2/log.h"
#include "mongo/platform/atomic_word.h"
#include "mongo/util/background.h"
#include "mongo/util/concurrency/idle_thread_block.h"
#include "mongo/util/concurrency/ticketholder.h"
#include "mongo/util/debug_util.h"
#include "mongo/util/exit.h"
#include "mongo/util/processinfo.h"
#include "mongo/util/quick_exit.h"
#include "mongo/util/scopeguard.h"
#include "mongo/util/testing_proctor.h"
#include "mongo/util/time_support.h"

#if !defined(__has_feature)
#define __has_feature(x) 0
#endif

#if __has_feature(address_sanitizer)
const bool kAddressSanitizerEnabled = true;
#else
const bool kAddressSanitizerEnabled = false;
#endif

using namespace fmt::literals;

namespace mongo {

namespace {

MONGO_FAIL_POINT_DEFINE(WTPreserveSnapshotHistoryIndefinitely);
MONGO_FAIL_POINT_DEFINE(WTSetOldestTSToStableTS);

MONGO_FAIL_POINT_DEFINE(pauseCheckpointThread);

}  // namespace

bool WiredTigerFileVersion::shouldDowngrade(bool readOnly,
                                            bool repairMode,
                                            bool hasRecoveryTimestamp) {
    if (readOnly) {
        // A read-only state must not have upgraded. Nor could it downgrade.
        return false;
    }

    const auto replCoord = repl::ReplicationCoordinator::get(getGlobalServiceContext());
    const auto memberState = replCoord->getMemberState();
    if (memberState.arbiter()) {
        // SERVER-35361: Arbiters will no longer downgrade their data files. To downgrade
        // binaries, the user must delete the dbpath. It's not particularly expensive for a
        // replica set to re-initialize an arbiter that comes online.
        return false;
    }

    if (!serverGlobalParams.featureCompatibility.isVersionInitialized()) {
        // If the FCV document hasn't been read, trust the WT compatibility. MongoD will
        // downgrade to the same compatibility it discovered on startup.
        return _startupVersion == StartupVersion::IS_44_FCV_42 ||
            _startupVersion == StartupVersion::IS_42;
    }

    if (serverGlobalParams.featureCompatibility.getVersion() !=
        ServerGlobalParams::FeatureCompatibility::Version::kFullyDowngradedTo42) {
        // Only consider downgrading when FCV is set to 4.2
        return false;
    }

    if (getGlobalReplSettings().usingReplSets()) {
        // If this process is run with `--replSet`, it must have run any startup replication
        // recovery and downgrading at this point is safe.
        return true;
    }

    if (hasRecoveryTimestamp) {
        // If we're not running with `--replSet`, don't allow downgrades if the node needed to run
        // replication recovery. Having a recovery timestamp implies recovery must be run, but it
        // was not.
        return false;
    }

    // If there is no `recoveryTimestamp`, then the data should be consistent with the top of
    // oplog and downgrading can proceed. This is expected for standalone datasets that use FCV.
    return true;
}

std::string WiredTigerFileVersion::getDowngradeString() {
    if (!serverGlobalParams.featureCompatibility.isVersionInitialized()) {
        invariant(_startupVersion != StartupVersion::IS_44_FCV_44);

        switch (_startupVersion) {
            case StartupVersion::IS_44_FCV_42:
                return "compatibility=(release=3.3)";
            case StartupVersion::IS_42:
                return "compatibility=(release=3.3)";
            default:
                MONGO_UNREACHABLE;
        }
    }
    return "compatibility=(release=3.3)";
}

using std::set;
using std::string;

namespace dps = ::mongo::dotted_path_support;

class WiredTigerKVEngine::WiredTigerSessionSweeper : public BackgroundJob {
public:
    explicit WiredTigerSessionSweeper(WiredTigerSessionCache* sessionCache)
        : BackgroundJob(false /* deleteSelf */), _sessionCache(sessionCache) {}

    virtual string name() const {
        return "WTIdleSessionSweeper";
    }

    virtual void run() {
        ThreadClient tc(name(), getGlobalServiceContext());
        LOGV2_DEBUG(22303, 1, "starting {name} thread", "name"_attr = name());

        while (!_shuttingDown.load()) {
            {
                stdx::unique_lock<Latch> lock(_mutex);
                MONGO_IDLE_THREAD_BLOCK;
                // Check every 10 seconds or sooner in the debug builds
                _condvar.wait_for(lock, stdx::chrono::seconds(kDebugBuild ? 1 : 10));
            }

            _sessionCache->closeExpiredIdleSessions(gWiredTigerSessionCloseIdleTimeSecs.load() *
                                                    1000);
        }
        LOGV2_DEBUG(22304, 1, "stopping {name} thread", "name"_attr = name());
    }

    void shutdown() {
        _shuttingDown.store(true);
        {
            stdx::unique_lock<Latch> lock(_mutex);
            // Wake up the session sweeper thread early, we do not want the shutdown
            // to wait for us too long.
            _condvar.notify_one();
        }
        wait();
    }

private:
    WiredTigerSessionCache* _sessionCache;
    AtomicWord<bool> _shuttingDown{false};

    Mutex _mutex = MONGO_MAKE_LATCH("WiredTigerSessionSweeper::_mutex");  // protects _condvar
    // The session sweeper thread idles on this condition variable for a particular time duration
    // between cleaning up expired sessions. It can be triggered early to expediate shutdown.
    stdx::condition_variable _condvar;
};

std::string toString(const StorageEngine::OldestActiveTransactionTimestampResult& r) {
    if (r.isOK()) {
        if (r.getValue()) {
            // Timestamp.
            return r.getValue().value().toString();
        } else {
            // boost::none.
            return "null";
        }
    } else {
        return r.getStatus().toString();
    }
}

class WiredTigerKVEngine::WiredTigerCheckpointThread : public BackgroundJob {
public:
    explicit WiredTigerCheckpointThread(WiredTigerKVEngine* wiredTigerKVEngine,
                                        WiredTigerSessionCache* sessionCache)
        : BackgroundJob(false /* deleteSelf */),
          _wiredTigerKVEngine(wiredTigerKVEngine),
          _sessionCache(sessionCache) {}

    virtual string name() const {
        return "WTCheckpointThread";
    }

    virtual void run() {
        ThreadClient tc(name(), getGlobalServiceContext());
        LOGV2_DEBUG(22307, 1, "Starting thread", "threadName"_attr = name());

        while (true) {
            auto opCtx = tc->makeOperationContext();

            {
                stdx::unique_lock<Latch> lock(_mutex);
                MONGO_IDLE_THREAD_BLOCK;

                // Wait for 'wiredTigerGlobalOptions.checkpointDelaySecs' seconds; or until either
                // shutdown is signaled or a checkpoint is triggered.
                _condvar.wait_for(lock,
                                  stdx::chrono::seconds(static_cast<std::int64_t>(
                                      wiredTigerGlobalOptions.checkpointDelaySecs)),
                                  [&] { return _shuttingDown || _triggerCheckpoint; });

                // If the checkpointDelaySecs is set to 0, that means we should skip checkpointing.
                // However, checkpointDelaySecs is adjustable by a runtime server parameter, so we
                // need to wake up to check periodically. The wakeup to check period is arbitrary.
                while (wiredTigerGlobalOptions.checkpointDelaySecs == 0 && !_shuttingDown &&
                       !_triggerCheckpoint) {
                    _condvar.wait_for(lock,
                                      stdx::chrono::seconds(static_cast<std::int64_t>(3)),
                                      [&] { return _shuttingDown || _triggerCheckpoint; });
                }

                if (_shuttingDown) {
                    LOGV2_DEBUG(22309, 1, "Stopping thread", "threadName"_attr = name());
                    return;
                }

                // Clear the trigger so we do not immediately checkpoint again after this.
                _triggerCheckpoint = false;
            }

            pauseCheckpointThread.pauseWhileSet();

            const Date_t startTime = Date_t::now();

            const Timestamp stableTimestamp = _wiredTigerKVEngine->getStableTimestamp();
            const Timestamp initialDataTimestamp = _wiredTigerKVEngine->getInitialDataTimestamp();

            // The amount of oplog to keep is primarily dictated by a user setting. However, in
            // unexpected cases, durable, recover to a timestamp storage engines may need to play
            // forward from an oplog entry that would otherwise be truncated by the user
            // setting. Furthermore, the entries in prepared or large transactions can refer to
            // previous entries in the same transaction.
            //
            // Live (replication) rollback will replay oplogs from exactly the stable timestamp.
            // With prepared or large transactions, it may require some additional entries prior to
            // the stable timestamp. These requirements are summarized in getOplogNeededForRollback.
            // Truncating the oplog at this point is sufficient for in-memory configurations, but
            // could cause an unrecoverable scenario if the node crashed and has to play from the
            // last stable checkpoint.
            //
            // By recording the oplog needed for rollback "now", then taking a stable checkpoint,
            // we can safely assume that the oplog needed for crash recovery has caught up to the
            // recorded value. After the checkpoint, this value will be published such that actors
            // which truncate the oplog can read an updated value.
            try {
                // Three cases:
                //
                // First, initialDataTimestamp is Timestamp(0, 1) -> Take full checkpoint. This is
                // when there is no consistent view of the data (e.g: during initial sync).
                //
                // Second, stableTimestamp < initialDataTimestamp: Skip checkpoints. The data on
                // disk is prone to being rolled back. Hold off on checkpoints.  Hope that the
                // stable timestamp surpasses the data on disk, allowing storage to persist newer
                // copies to disk.
                //
                // Third, stableTimestamp >= initialDataTimestamp: Take stable checkpoint. Steady
                // state case.
                if (initialDataTimestamp.asULL() <= 1) {
                    UniqueWiredTigerSession session = _sessionCache->getSession();
                    WT_SESSION* s = session->getSession();
                    invariantWTOK(s->checkpoint(s, "use_timestamp=false"));
                    LOGV2_FOR_RECOVERY(5576602,
                                       2,
                                       "Completed unstable checkpoint.",
                                       "initialDataTimestamp"_attr =
                                           initialDataTimestamp.toString());
                } else if (stableTimestamp < initialDataTimestamp) {
                    LOGV2_FOR_RECOVERY(
                        23985,
                        2,
                        "Stable timestamp is behind the initial data timestamp, skipping "
                        "a checkpoint. StableTimestamp: {stableTimestamp} InitialDataTimestamp: "
                        "{initialDataTimestamp}",
                        "stableTimestamp"_attr = stableTimestamp.toString(),
                        "initialDataTimestamp"_attr = initialDataTimestamp.toString());
                } else {
                    auto oplogNeededForRollback = _wiredTigerKVEngine->getOplogNeededForRollback();

                    LOGV2_FOR_RECOVERY(
                        23986,
                        2,
                        "Performing stable checkpoint. StableTimestamp: {stableTimestamp}, "
                        "OplogNeededForRollback: {oplogNeededForRollback}",
                        "stableTimestamp"_attr = stableTimestamp,
                        "oplogNeededForRollback"_attr = toString(oplogNeededForRollback));

                    UniqueWiredTigerSession session = _sessionCache->getSession();
                    WT_SESSION* s = session->getSession();
                    invariantWTOK(s->checkpoint(s, "use_timestamp=true"));

                    if (oplogNeededForRollback.isOK()) {
                        // Now that the checkpoint is durable, publish the oplog needed to recover
                        // from it.
                        stdx::lock_guard<Latch> lk(_oplogNeededForCrashRecoveryMutex);
                        _oplogNeededForCrashRecovery.store(
                            oplogNeededForRollback.getValue().asULL());
                    }
                }
                // Do KeysDB checkpoint
                auto encryptionKeyDB = _sessionCache->getKVEngine()->getEncryptionKeyDB();
                if (encryptionKeyDB) {
                    std::unique_ptr<WiredTigerSession> sess = std::make_unique<WiredTigerSession>(encryptionKeyDB->getConnection());
                    WT_SESSION* s = sess->getSession();
                    invariantWTOK(s->checkpoint(s, "use_timestamp=false"));
                }

                const auto secondsElapsed = durationCount<Seconds>(Date_t::now() - startTime);
                if (secondsElapsed >= 30) {
                    LOGV2_DEBUG(22308,
                                1,
                                "Checkpoint took {secondsElapsed} seconds to complete.",
                                "secondsElapsed"_attr = secondsElapsed);
                }
            } catch (const WriteConflictException&) {
                // Temporary: remove this after WT-3483
                LOGV2_WARNING(22346, "Checkpoint encountered a write conflict exception.");
            } catch (const AssertionException& exc) {
                invariant(ErrorCodes::isShutdownError(exc.code()), exc.what());
            }
        }
    }

    /**
     * Returns true if we have already triggered taking the first checkpoint.
     */
    bool hasTriggeredFirstStableCheckpoint() {
        stdx::unique_lock<Latch> lock(_mutex);
        return _hasTriggeredFirstStableCheckpoint;
    }

    /**
     * Triggers taking the first stable checkpoint, which is when the stable timestamp advances past
     * the initial data timestamp.
     *
     * The checkpoint thread runs automatically every wiredTigerGlobalOptions.checkpointDelaySecs
     * seconds. This function avoids potentially waiting that full duration for a stable checkpoint,
     * initiating one immediately.
     *
     * Do not call this function if hasTriggeredFirstStableCheckpoint() returns true.
     */
    void triggerFirstStableCheckpoint(Timestamp prevStable,
                                      Timestamp initialData,
                                      Timestamp currStable) {
        stdx::unique_lock<Latch> lock(_mutex);
        invariant(!_hasTriggeredFirstStableCheckpoint);
        if (prevStable < initialData && currStable >= initialData) {
            LOGV2(22310,
                  "Triggering the first stable checkpoint. Initial Data: {initialData} PrevStable: "
                  "{prevStable} CurrStable: {currStable}",
                  "Triggering the first stable checkpoint",
                  "initialData"_attr = initialData,
                  "prevStable"_attr = prevStable,
                  "currStable"_attr = currStable);
            _hasTriggeredFirstStableCheckpoint = true;
            _triggerCheckpoint = true;
            _condvar.notify_one();
        }
    }

    std::uint64_t getOplogNeededForCrashRecovery() const {
        return _oplogNeededForCrashRecovery.load();
    }

    /*
     * Atomically assign _oplogNeededForCrashRecovery to a variable.
     * _oplogNeededForCrashRecovery will not change during assignment.
     */
    void assignOplogNeededForCrashRecoveryTo(boost::optional<Timestamp>* timestamp) {
        stdx::lock_guard<Latch> lk(_oplogNeededForCrashRecoveryMutex);
        *timestamp = Timestamp(_oplogNeededForCrashRecovery.load());
    }

    void shutdown() {
        {
            stdx::unique_lock<Latch> lock(_mutex);
            _shuttingDown = true;
            // Wake up the checkpoint thread early, to take a final checkpoint before shutting
            // down, if one has not coincidentally just been taken.
            _condvar.notify_one();
        }
        wait();
    }

private:
    WiredTigerKVEngine* _wiredTigerKVEngine;
    WiredTigerSessionCache* _sessionCache;

    Mutex _oplogNeededForCrashRecoveryMutex =
        MONGO_MAKE_LATCH("WiredTigerCheckpointThread::_oplogNeededForCrashRecoveryMutex");
    AtomicWord<std::uint64_t> _oplogNeededForCrashRecovery;

    // Protects the state below.
    Mutex _mutex = MONGO_MAKE_LATCH("WiredTigerCheckpointThread::_mutex");

    // The checkpoint thread idles on this condition variable for a particular time duration between
    // taking checkpoints. It can be triggered early to expedite either: immediate checkpointing if
    // _triggerCheckpoint is set; or shutdown cleanup if _shuttingDown is set.
    stdx::condition_variable _condvar;

    bool _shuttingDown = false;

    // This flag ensures the first stable checkpoint is only triggered once.
    bool _hasTriggeredFirstStableCheckpoint = false;

    // This flag allows the checkpoint thread to wake up early when _condvar is signaled.
    bool _triggerCheckpoint = false;
};

namespace {
TicketHolder openWriteTransaction(128);
TicketHolder openReadTransaction(128);
constexpr auto keydbDir = "key.db";
constexpr auto rotationDir = "key.db.rotation";
constexpr auto keydbBackupDir = "key.db.rotated";
}  // namespace

OpenWriteTransactionParam::OpenWriteTransactionParam(StringData name, ServerParameterType spt)
    : ServerParameter(name, spt), _data(&openWriteTransaction) {}

void OpenWriteTransactionParam::append(OperationContext* opCtx,
                                       BSONObjBuilder& b,
                                       const std::string& name) {
    b.append(name, _data->outof());
}

Status OpenWriteTransactionParam::setFromString(const std::string& str) {
    int num = 0;
    Status status = NumberParser{}(str, &num);
    if (!status.isOK()) {
        return status;
    }
    if (num <= 0) {
        return {ErrorCodes::BadValue, str::stream() << name() << " has to be > 0"};
    }
    return _data->resize(num);
}

OpenReadTransactionParam::OpenReadTransactionParam(StringData name, ServerParameterType spt)
    : ServerParameter(name, spt), _data(&openReadTransaction) {}

void OpenReadTransactionParam::append(OperationContext* opCtx,
                                      BSONObjBuilder& b,
                                      const std::string& name) {
    b.append(name, _data->outof());
}

Status OpenReadTransactionParam::setFromString(const std::string& str) {
    int num = 0;
    Status status = NumberParser{}(str, &num);
    if (!status.isOK()) {
        return status;
    }
    if (num <= 0) {
        return {ErrorCodes::BadValue, str::stream() << name() << " has to be > 0"};
    }
    return _data->resize(num);
}

namespace {

StatusWith<StorageEngine::BackupInformation> getBackupInformationFromBackupCursor(
    WT_SESSION* session,
    WT_CURSOR* cursor,
    bool incrementalBackup,
    bool fullBackup,
    std::string dbPath,
    const char* statusPrefix) {
    int wtRet;
    StorageEngine::BackupInformation backupInformation;
    const char* filename;
    const auto directoryPath = boost::filesystem::path(dbPath);
    const auto wiredTigerLogFilePrefix = "WiredTigerLog";
    while ((wtRet = cursor->next(cursor)) == 0) {
        invariantWTOK(cursor->get_key(cursor, &filename));

        std::string name(filename);

        boost::filesystem::path filePath = directoryPath;
        if (name.find(wiredTigerLogFilePrefix) == 0) {
            // TODO SERVER-13455:replace `journal/` with the configurable journal path.
            filePath /= boost::filesystem::path("journal");
        }
        filePath /= name;

        boost::system::error_code errorCode;
        const std::uint64_t fileSize = boost::filesystem::file_size(filePath, errorCode);
        uassert(31403,
                "Failed to get a file's size. Filename: {} Error: {}"_format(filePath.string(),
                                                                             errorCode.message()),
                !errorCode);

        StorageEngine::BackupFile backupFile(fileSize);
        backupInformation.insert({filePath.string(), backupFile});

        // For the first full incremental backup, include the offset and length.
        if (incrementalBackup && fullBackup) {
            backupInformation.at(filePath.string()).blocksToCopy.push_back({0, fileSize});
        }

        // Full backups cannot open an incremental cursor, even if they are the first full backup
        // for incremental.
        if (!incrementalBackup || fullBackup) {
            continue;
        }

        // For each file listed, open a duplicate backup cursor and get the blocks to copy.
        std::stringstream ss;
        ss << "incremental=(file=" << filename << ")";
        const std::string config = ss.str();
        WT_CURSOR* dupCursor;
        wtRet = session->open_cursor(session, nullptr, cursor, config.c_str(), &dupCursor);
        if (wtRet != 0) {
            return wtRCToStatus(wtRet);
        }

        while ((wtRet = dupCursor->next(dupCursor)) == 0) {
            uint64_t offset, size, type;
            invariantWTOK(dupCursor->get_key(dupCursor, &offset, &size, &type));
            LOGV2_DEBUG(22311,
                        2,
                        "Block to copy for incremental backup: filename: {filePath_string}, "
                        "offset: {offset}, size: {size}, type: {type}",
                        "filePath_string"_attr = filePath.string(),
                        "offset"_attr = offset,
                        "size"_attr = size,
                        "type"_attr = type);
            backupInformation.at(filePath.string()).blocksToCopy.push_back({offset, size});
        }

        if (wtRet != WT_NOTFOUND) {
            return wtRCToStatus(wtRet);
        }

        wtRet = dupCursor->close(dupCursor);
        if (wtRet != 0) {
            return wtRCToStatus(wtRet);
        }
    }

    if (wtRet != WT_NOTFOUND) {
        return wtRCToStatus(wtRet, statusPrefix);
    }
    return backupInformation;
}

}  // namespace

// Copy files and fill vectors for remove copied files and empty dirs
// Following files are excluded:
//   collection-*.wt
//   index-*.wt
//   collection/*.wt
//   index/*.wt
// Can throw standard exceptions
static void copy_keydb_files(const boost::filesystem::path& from,
                             const boost::filesystem::path& to,
                             std::vector<boost::filesystem::path>& emptyDirs,
                             std::vector<boost::filesystem::path>& copiedFiles,
                             bool* parent_empty = nullptr) {
    namespace fs = boost::filesystem;
    bool checkTo = true;
    bool empty = true;

    for(auto& p: fs::directory_iterator(from)) {
        if (fs::is_directory(p.status())) {
            copy_keydb_files(p.path(), to / p.path().filename(), emptyDirs, copiedFiles, &empty);
        } else {
            static std::regex rex{"/(collection|index)[-/][^/]+\\.wt$"};
            std::smatch sm;
            if (std::regex_search(p.path().string(), sm, rex)) {
                empty = false;
                if (parent_empty)
                    *parent_empty = false;
            } else {
                if (checkTo) {
                    checkTo = false;
                    if (!fs::exists(to))
                        fs::create_directories(to);
                }
                fs::copy_file(p.path(), to / p.path().filename(), fs::copy_option::none);
                copiedFiles.push_back(p.path());
            }
        }
    }

    if (empty)
        emptyDirs.push_back(from);
}

StringData WiredTigerKVEngine::kTableUriPrefix = "table:"_sd;

WiredTigerKVEngine::WiredTigerKVEngine(const std::string& canonicalName,
                                       const std::string& path,
                                       ClockSource* cs,
                                       const std::string& extraOpenOptions,
                                       size_t cacheSizeMB,
                                       size_t maxHistoryFileSizeMB,
                                       bool durable,
                                       bool ephemeral,
                                       bool repair,
                                       bool readOnly)
    : _clockSource(cs),
      _oplogManager(std::make_unique<WiredTigerOplogManager>()),
      _canonicalName(canonicalName),
      _path(path),
      _sizeStorerSyncTracker(cs, 100000, Seconds(60)),
      _durable(durable),
      _ephemeral(ephemeral),
      _inRepairMode(repair),
      _readOnly(readOnly),
      _keepDataHistory(serverGlobalParams.enableMajorityReadConcern) {
    _pinnedOplogTimestamp.store(Timestamp::max().asULL());
    boost::filesystem::path journalPath = path;
    journalPath /= "journal";
    if (_durable) {
        if (!boost::filesystem::exists(journalPath)) {
            try {
                boost::filesystem::create_directory(journalPath);
            } catch (std::exception& e) {
                LOGV2_ERROR(22312,
                            "error creating journal dir {directory} {error}",
                            "Error creating journal directory",
                            "directory"_attr = journalPath.generic_string(),
                            "error"_attr = e.what());
                throw;
            }
        }
    }

    _previousCheckedDropsQueued = _clockSource->now();

    if (encryptionGlobalParams.enableEncryption) {
        namespace fs = boost::filesystem;
        bool just_created{false};
        fs::path keyDBPath = path;
        keyDBPath /= keydbDir;
        auto keyDBPathGuard = makeGuard([&] { if (just_created) fs::remove_all(keyDBPath); });
        if (!fs::exists(keyDBPath)) {
            fs::path betaKeyDBPath = path;
            betaKeyDBPath /= "keydb";
            if (!fs::exists(betaKeyDBPath)) {
                try {
                    fs::create_directory(keyDBPath);
                    just_created = true;
                } catch (std::exception& e) {
                    LOGV2(29007, "error creating KeyDB dir {path} {what}",
                          "path"_attr = keyDBPath.string(),
                          "what"_attr = e.what());
                    throw;
                }
            } else if (!storageGlobalParams.directoryperdb) {
                // --directoryperdb is not specified - just rename
                try {
                    fs::rename(betaKeyDBPath, keyDBPath);
                } catch (std::exception& e) {
                    LOGV2(29008, "error renaming KeyDB directory from {path1} to {path2} {what}",
                          "path1"_attr = betaKeyDBPath.string(),
                          "path2"_attr = keyDBPath.string(),
                          "what"_attr = e.what());
                    throw;
                }
            } else {
                // --directoryperdb specified - there are chances betaKeyDBPath contains
                // user data from 'keydb' database
                // move everything except
                //   collection-*.wt
                //   index-*.wt
                //   collection/*.wt
                //   index/*.wt
                try {
                    std::vector<fs::path> emptyDirs;
                    std::vector<fs::path> copiedFiles;
                    copy_keydb_files(betaKeyDBPath, keyDBPath, emptyDirs, copiedFiles);
                    for (auto&& file : copiedFiles)
                        fs::remove(file);
                    for (auto&& dir : emptyDirs)
                        fs::remove(dir);
                } catch (std::exception& e) {
                    LOGV2(29009, "error moving KeyDB files from {path1} to {path2} {what}",
                          "path1"_attr = betaKeyDBPath.string(),
                          "path2"_attr = keyDBPath.string(),
                          "what"_attr = e.what());
                    throw;
                }
            }
        }
        auto encryptionKeyDB = std::make_unique<EncryptionKeyDB>(just_created, keyDBPath.string());
        encryptionKeyDB->init();
        keyDBPathGuard.dismiss();
        // do master key rotation if necessary
        if (encryptionGlobalParams.shouldRotateMasterKey()) {
            fs::path newKeyDBPath = path;
            newKeyDBPath /= rotationDir;
            if (fs::exists(newKeyDBPath)) {
                std::stringstream ss;
                ss << "Cannot do master key rotation. ";
                ss << "Rotation directory '" << newKeyDBPath << "' already exists.";
                throw std::runtime_error(ss.str());
            }
            try {
                fs::create_directory(newKeyDBPath);
            } catch (std::exception& e) {
                LOGV2(29010, "error creating rotation directory {path} {what}",
                      "path"_attr = newKeyDBPath.string(),
                      "what"_attr = e.what());
                throw;
            }
            auto rotationKeyDB = std::make_unique<EncryptionKeyDB>(newKeyDBPath.string(), true);
            rotationKeyDB->init();
            rotationKeyDB->clone(encryptionKeyDB.get());
            // store new key to the Vault
            rotationKeyDB->store_masterkey();
            // close key db instances and rename dirs
            encryptionKeyDB.reset(nullptr);
            rotationKeyDB.reset(nullptr);
            fs::path backupKeyDBPath = path;
            backupKeyDBPath /= keydbBackupDir;
            fs::remove_all(backupKeyDBPath);
            fs::rename(keyDBPath, backupKeyDBPath);
            fs::rename(newKeyDBPath, keyDBPath);
            throw std::runtime_error("master key rotation finished successfully");
        }
        _encryptionKeyDB = std::move(encryptionKeyDB);
        // add Percona encryption extension
        std::stringstream ss;
        ss << "local=(entry=percona_encryption_extension_init,early_load=true,config=(cipher=" << encryptionGlobalParams.encryptionCipherMode << "))";
        WiredTigerExtensions::get(getGlobalServiceContext())->addExtension(ss.str());
        // setup encryption hooks
        // WiredTigerEncryptionHooks instance should be created after EncryptionKeyDB (depends on it)
        if (encryptionGlobalParams.encryptionCipherMode == "AES256-CBC")
            EncryptionHooks::set(
                getGlobalServiceContext(),
                std::make_unique<WiredTigerEncryptionHooksCBC>(_encryptionKeyDB.get()));
        else // AES256-GCM
            EncryptionHooks::set(
                getGlobalServiceContext(),
                std::make_unique<WiredTigerEncryptionHooksGCM>(_encryptionKeyDB.get()));
    }

    std::stringstream ss;
    ss << "create,";
    ss << "cache_size=" << cacheSizeMB << "M,";
    ss << "session_max=33000,";
    ss << "eviction=(threads_min=4,threads_max=4),";
    ss << "config_base=false,";
    ss << "statistics=(fast),";

    if (!WiredTigerSessionCache::isEngineCachingCursors()) {
        ss << "cache_cursors=false,";
    }

    // The setting may have a later setting override it if not using the journal.  We make it
    // unconditional here because even nojournal may need this setting if it is a transition
    // from using the journal.
    ss << "log=(enabled=true,archive=" << (_readOnly ? "false" : "true")
       << ",path=journal,compressor=";
    ss << wiredTigerGlobalOptions.journalCompressor << "),";
    ss << "file_manager=(close_idle_time=" << gWiredTigerFileHandleCloseIdleTime
       << ",close_scan_interval=" << gWiredTigerFileHandleCloseScanInterval
       << ",close_handle_minimum=" << gWiredTigerFileHandleCloseMinimum << "),";
    ss << "statistics_log=(wait=" << wiredTigerGlobalOptions.statisticsLogDelaySecs << "),";

    if (shouldLog(::mongo::logv2::LogComponent::kStorageRecovery, logv2::LogSeverity::Debug(3))) {
        ss << "verbose=[recovery_progress,checkpoint_progress,compact_progress,recovery],";
    } else {
        ss << "verbose=[recovery_progress,checkpoint_progress,compact_progress],";
    }

    if (kDebugBuild && gWiredTigerEvictionDebugMode) {
        // For select debug builds, support enabling WiredTiger eviction debug mode. This uses
        // more aggressive eviction tactics, but may have a negative performance impact.
        ss << "debug_mode=(eviction=true),";
    }
    if (kAddressSanitizerEnabled) {
        // For applications using WT, advancing a cursor invalidates the data/memory that cursor was
        // pointing to. WT performs the optimization of managing its own memory. The unit of memory
        // allocation is a page. Walking a cursor from one key/value to the next often lands on the
        // same page, which has the effect of keeping the address of the prior key/value valid. For
        // a bug to occur, the cursor must move across pages, and the prior page must be
        // evicted. While rare, this can happen, resulting in reading random memory.
        //
        // The cursor copy debug mode will instead cause WT to malloc/free memory for each key/value
        // a cursor is positioned on. Thus, enabling when using with address sanitizer will catch
        // many cases of dereferencing invalid cursor positions. Note, there is a known caveat: a
        // free/malloc for roughly the same allocation size can often return the same memory
        // address. This is a scenario where the address sanitizer is not able to detect a
        // use-after-free error.
        ss << "debug_mode=(cursor_copy=true),";
    }

    if (TestingProctor::instance().isEnabled()) {
        // Enable debug write-ahead logging for all tables when testing is enabled.
        //
        // If MongoDB startup fails, there may be clues from the previous run still left in the WT
        // log files that can provide some insight into how the system got into a bad state. When
        // testing is enabled, keep around some of these files for investigative purposes.
        ss << "debug_mode=(table_logging=true,checkpoint_retention=4),";
    }

    ss << WiredTigerCustomizationHooks::get(getGlobalServiceContext())
              ->getTableCreateConfig("system");
    ss << WiredTigerExtensions::get(getGlobalServiceContext())->getOpenExtensionsConfig();
    ss << extraOpenOptions;

    if (!_durable) {
        // If we started without the journal, but previously used the journal then open with the
        // WT log enabled to perform any unclean shutdown recovery and then close and reopen in
        // the normal path without the journal.
        if (boost::filesystem::exists(journalPath)) {
            string config = ss.str();
            auto start = Date_t::now();
            LOGV2(22313,
                  "Detected WT journal files. Running recovery from last checkpoint. journal to "
                  "nojournal transition config",
                  "config"_attr = config);
            int ret = wiredtiger_open(
                path.c_str(), _eventHandler.getWtEventHandler(), config.c_str(), &_conn);
            LOGV2(4795911, "Recovery complete", "duration"_attr = Date_t::now() - start);
            if (ret == EINVAL) {
                fassertFailedNoTrace(28717);
            } else if (ret != 0) {
                Status s(wtRCToStatus(ret));
                msgasserted(28718, s.reason());
            }
            start = Date_t::now();
            invariantWTOK(_conn->close(_conn, nullptr));
            LOGV2(4795910,
                  "WiredTiger closed. Removing journal files",
                  "duration"_attr = Date_t::now() - start);
            // After successful recovery, remove the journal directory.
            try {
                start = Date_t::now();
                boost::filesystem::remove_all(journalPath);
            } catch (std::exception& e) {
                LOGV2_ERROR(22355,
                            "error removing journal dir {directory} {error}",
                            "Error removing journal directory",
                            "directory"_attr = journalPath.generic_string(),
                            "error"_attr = e.what(),
                            "duration"_attr = Date_t::now() - start);
                throw;
            }
            LOGV2(4795908, "Journal files removed", "duration"_attr = Date_t::now() - start);
        }
        // This setting overrides the earlier setting because it is later in the config string.
        ss << ",log=(enabled=false),";
    }

    string config = ss.str();
    LOGV2(22315, "Opening WiredTiger", "config"_attr = config);
    auto startTime = Date_t::now();
    _openWiredTiger(path, config);
    LOGV2(4795906, "WiredTiger opened", "duration"_attr = Date_t::now() - startTime);
    _eventHandler.setStartupSuccessful();
    _wtOpenConfig = config;

    {
        char buf[(2 * 8 /*bytes in hex*/) + 1 /*nul terminator*/];
        invariantWTOK(_conn->query_timestamp(_conn, buf, "get=recovery"));

        std::uint64_t tmp;
        fassert(50758, NumberParser().base(16)(buf, &tmp));
        _recoveryTimestamp = Timestamp(tmp);
        LOGV2_FOR_RECOVERY(23987,
                           0,
                           "WiredTiger recoveryTimestamp",
                           "recoveryTimestamp"_attr = _recoveryTimestamp);
    }

    _sessionCache.reset(new WiredTigerSessionCache(this));

    _sessionSweeper = std::make_unique<WiredTigerSessionSweeper>(_sessionCache.get());
    _sessionSweeper->go();

    // Until the Replication layer installs a real callback, prevent truncating the oplog.
    setOldestActiveTransactionTimestampCallback(
        [](Timestamp) { return StatusWith(boost::make_optional(Timestamp::min())); });

    if (!_readOnly && !_ephemeral) {
        if (!_recoveryTimestamp.isNull()) {
            setInitialDataTimestamp(_recoveryTimestamp);
            setOldestTimestamp(_recoveryTimestamp, false);
            setStableTimestamp(_recoveryTimestamp, false);

            _sessionCache->snapshotManager().setLastApplied(_recoveryTimestamp);
            {
                stdx::lock_guard<Latch> lk(_highestDurableTimestampMutex);
                _highestSeenDurableTimestamp = _recoveryTimestamp.asULL();
            }
        }
    }

    if (_ephemeral && !TestingProctor::instance().isEnabled()) {
        // We do not maintain any snapshot history for the ephemeral storage engine in production
        // because replication and sharded transactions do not currently run on the inMemory engine.
        // It is live in testing, however.
        snapshotWindowParams.targetSnapshotHistoryWindowInSeconds.store(0);
    }

    _sizeStorerUri = _uri("sizeStorer");
    WiredTigerSession session(_conn);
    if (!_readOnly && repair && _hasUri(session.getSession(), _sizeStorerUri)) {
        LOGV2(22316, "Repairing size cache");

        auto status = _salvageIfNeeded(_sizeStorerUri.c_str());
        if (status.code() != ErrorCodes::DataModifiedByRepair)
            fassertNoTrace(28577, status);
    }

    _sizeStorer = std::make_unique<WiredTigerSizeStorer>(_conn, _sizeStorerUri, _readOnly);

    Locker::setGlobalThrottling(&openReadTransaction, &openWriteTransaction);

    _runTimeConfigParam.reset(new WiredTigerEngineRuntimeConfigParameter(
        "wiredTigerEngineRuntimeConfig", ServerParameterType::kRuntimeOnly));
    _runTimeConfigParam->_data.second = this;
}

WiredTigerKVEngine::~WiredTigerKVEngine() {
    // Remove server parameters that we added in the constructor, to enable unit tests to reload the
    // storage engine again in this same process.
    ServerParameterSet::getGlobal()->remove("wiredTigerEngineRuntimeConfig");

    cleanShutdown();

    _sessionCache.reset(nullptr);
    _encryptionKeyDB.reset(nullptr);
}

void WiredTigerKVEngine::startAsyncThreads() {
    if (!_ephemeral) {
        if (!_readOnly) {
            _checkpointThread =
                std::make_unique<WiredTigerCheckpointThread>(this, _sessionCache.get());
            _checkpointThread->go();
        }
    }
}

void WiredTigerKVEngine::notifyStartupComplete() {
    WiredTigerUtil::notifyStartupComplete();
}

void WiredTigerKVEngine::appendGlobalStats(BSONObjBuilder& b) {
    BSONObjBuilder bb(b.subobjStart("concurrentTransactions"));
    {
        BSONObjBuilder bbb(bb.subobjStart("write"));
        bbb.append("out", openWriteTransaction.used());
        bbb.append("available", openWriteTransaction.available());
        bbb.append("totalTickets", openWriteTransaction.outof());
        bbb.done();
    }
    {
        BSONObjBuilder bbb(bb.subobjStart("read"));
        bbb.append("out", openReadTransaction.used());
        bbb.append("available", openReadTransaction.available());
        bbb.append("totalTickets", openReadTransaction.outof());
        bbb.done();
    }
    bb.done();
}

/**
 * Table of MongoDB<->WiredTiger<->Log version numbers:
 *
 * |                MongoDB | WiredTiger | Log |
 * |------------------------+------------+-----|
 * |                 3.0.15 |      2.5.3 |   1 |
 * |                 3.2.20 |      2.9.2 |   1 |
 * |                 3.4.15 |      2.9.2 |   1 |
 * |                  3.6.4 |      3.0.1 |   2 |
 * |                 4.0.16 |      3.1.1 |   3 |
 * |                  4.2.1 |      3.2.2 |   3 |
 * |                  4.2.6 |      3.3.0 |   3 |
 * | 4.2.6 (blessed by 4.4) |      3.3.0 |   4 |
 * |                  4.4.0 |     10.0.0 |   5 |
 */
void WiredTigerKVEngine::_openWiredTiger(const std::string& path, const std::string& wtOpenConfig) {
    // MongoDB 4.4 will always run in compatibility version 10.0.
    std::string configStr = wtOpenConfig + ",compatibility=(require_min=\"10.0.0\")";
    auto wtEventHandler = _eventHandler.getWtEventHandler();

    int ret = wiredtiger_open(path.c_str(), wtEventHandler, configStr.c_str(), &_conn);
    if (!ret) {
        _fileVersion = {WiredTigerFileVersion::StartupVersion::IS_44_FCV_44};
        return;
    }

    if (_eventHandler.isWtIncompatible()) {
        // WT 4.4+ will refuse to startup on datafiles left behind by 4.0 and earlier. This behavior
        // is enforced outside of `require_min`. This condition is detected via a specific error
        // message from WiredTiger.
        if (_inRepairMode) {
            // In case this process was started with `--repair`, remove the "repair incomplete"
            // file.
            StorageRepairObserver::get(getGlobalServiceContext())->onRepairDone(nullptr);
        }
        LOGV2_FATAL(4671205,
                    "This version of MongoDB is too recent to start up on the existing data files. "
                    "Try MongoDB 4.2 or earlier.");
        fassertFailedNoTrace(4671206);
    }

    // MongoDB 4.4 doing clean shutdown in FCV 4.2 will use compatibility version 3.3.
    configStr = wtOpenConfig + ",compatibility=(require_min=\"3.3.0\")";
    ret = wiredtiger_open(path.c_str(), wtEventHandler, configStr.c_str(), &_conn);
    if (!ret) {
        _fileVersion = {WiredTigerFileVersion::StartupVersion::IS_44_FCV_42};
        return;
    }

    // MongoDB 4.2 uses compatibility version 3.2.
    configStr = wtOpenConfig + ",compatibility=(require_min=\"3.2.0\")";
    ret = wiredtiger_open(path.c_str(), wtEventHandler, configStr.c_str(), &_conn);
    if (!ret) {
        _fileVersion = {WiredTigerFileVersion::StartupVersion::IS_42};
        return;
    }

    LOGV2_WARNING(22347,
                  "Failed to start up WiredTiger under any compatibility version. This may be due "
                  "to an unsupported upgrade or downgrade.");
    if (ret == EINVAL) {
        fassertFailedNoTrace(28561);
    }

    if (ret == WT_TRY_SALVAGE) {
        LOGV2_WARNING(22348, "WiredTiger metadata corruption detected");
        if (!_inRepairMode) {
            LOGV2_FATAL_NOTRACE(50944, kWTRepairMsg);
        }
    }

    if (!_inRepairMode) {
        LOGV2_FATAL_NOTRACE(28595, "Terminating.", "reason"_attr = wtRCToStatus(ret).reason());
    }

    // Always attempt to salvage metadata regardless of error code when in repair mode.
    LOGV2_WARNING(22349, "Attempting to salvage WiredTiger metadata");
    configStr = wtOpenConfig + ",salvage=true";
    ret = wiredtiger_open(path.c_str(), wtEventHandler, configStr.c_str(), &_conn);
    if (!ret) {
        StorageRepairObserver::get(getGlobalServiceContext())
            ->invalidatingModification("WiredTiger metadata salvaged");
        return;
    }

    LOGV2_FATAL_NOTRACE(50947,
                        "Failed to salvage WiredTiger metadata",
                        "details"_attr = wtRCToStatus(ret).reason());
}

void WiredTigerKVEngine::cleanShutdown() {
    LOGV2(22317, "WiredTigerKVEngine shutting down");
    // Ensure that key db is destroyed on exit
    ON_BLOCK_EXIT([&] { _encryptionKeyDB.reset(nullptr); });
    WiredTigerUtil::resetTableLoggingInfo();

    if (!_readOnly)
        syncSizeInfo(true);
    if (!_conn) {
        return;
    }

    // these must be the last things we do before _conn->close();
    if (_sessionSweeper) {
        LOGV2(22318, "Shutting down session sweeper thread");
        _sessionSweeper->shutdown();
        LOGV2(22319, "Finished shutting down session sweeper thread");
    }
    if (_checkpointThread) {
        LOGV2(22322, "Shutting down checkpoint thread");
        _checkpointThread->shutdown();
        LOGV2(22323, "Finished shutting down checkpoint thread");
    }
    LOGV2_FOR_RECOVERY(23988,
                       2,
                       "Shutdown timestamps. StableTimestamp: {stableTimestamp_load} Initial data "
                       "timestamp: {initialDataTimestamp_load}",
                       "stableTimestamp_load"_attr = _stableTimestamp.load(),
                       "initialDataTimestamp_load"_attr = _initialDataTimestamp.load());

    _sizeStorer.reset();
    _sessionCache->shuttingDown();

    // We want WiredTiger to leak memory for faster shutdown except when we are running tools to
    // look for memory leaks.
    bool leak_memory = !kAddressSanitizerEnabled;
    std::string closeConfig = "";

    if (RUNNING_ON_VALGRIND) {
        leak_memory = false;
    }

    if (leak_memory) {
        closeConfig = "leak_memory=true,";
    }

    const Timestamp stableTimestamp = getStableTimestamp();
    const Timestamp initialDataTimestamp = getInitialDataTimestamp();
    if (gTakeUnstableCheckpointOnShutdown) {
        closeConfig += "use_timestamp=false,";
    } else if (!serverGlobalParams.enableMajorityReadConcern &&
               stableTimestamp < initialDataTimestamp) {
        // After a rollback via refetch, WT update chains for _id index keys can be logically
        // corrupt for read timestamps earlier than the `_initialDataTimestamp`. Because the stable
        // timestamp is really a read timestamp, we must avoid taking a stable checkpoint.
        //
        // If a stable timestamp is not set, there's no risk of reading corrupt history.
        LOGV2(22326,
              "Skipping checkpoint during clean shutdown because stableTimestamp is less than the "
              "initialDataTimestamp and enableMajorityReadConcern is false",
              "stableTimestamp"_attr = stableTimestamp,
              "initialDataTimestamp"_attr = initialDataTimestamp);
        quickExit(EXIT_SUCCESS);
    }

    bool downgrade = false; 
    if (_fileVersion.shouldDowngrade(_readOnly, _inRepairMode, !_recoveryTimestamp.isNull())) {
        downgrade = true;

        auto startTime = Date_t::now();
        LOGV2(22324,
              "Closing WiredTiger in preparation for reconfiguring",
              "closeConfig"_attr = closeConfig);
        invariantWTOK(_conn->close(_conn, closeConfig.c_str()));
        LOGV2(4795905, "WiredTiger closed", "duration"_attr = Date_t::now() - startTime);

        startTime = Date_t::now();
        invariantWTOK(wiredtiger_open(
            _path.c_str(), _eventHandler.getWtEventHandler(), _wtOpenConfig.c_str(), &_conn));
        LOGV2(4795904, "WiredTiger re-opened", "duration"_attr = Date_t::now() - startTime);

        startTime = Date_t::now();
        LOGV2(22325, "Reconfiguring", "newConfig"_attr = _fileVersion.getDowngradeString());
        invariantWTOK(_conn->reconfigure(_conn, _fileVersion.getDowngradeString().c_str()));
        LOGV2(4795903, "Reconfigure complete", "duration"_attr = Date_t::now() - startTime);
    }

    auto startTime = Date_t::now();
    LOGV2(4795902, "Closing WiredTiger", "closeConfig"_attr = closeConfig);
    invariantWTOK(_conn->close(_conn, closeConfig.c_str()));
    LOGV2(4795901, "WiredTiger closed", "duration"_attr = Date_t::now() - startTime);
    _conn = nullptr;

    if (_encryptionKeyDB && downgrade) {
        _encryptionKeyDB->reconfigure(_fileVersion.getDowngradeString().c_str());
    }
}

Status WiredTigerKVEngine::okToRename(OperationContext* opCtx,
                                      StringData fromNS,
                                      StringData toNS,
                                      StringData ident,
                                      const RecordStore* originalRecordStore) const {
    syncSizeInfo(false);

    return Status::OK();
}

int64_t WiredTigerKVEngine::getIdentSize(OperationContext* opCtx, StringData ident) {
    WiredTigerSession* session = WiredTigerRecoveryUnit::get(opCtx)->getSession();
    return WiredTigerUtil::getIdentSize(session->getSession(), _uri(ident));
}

Status WiredTigerKVEngine::repairIdent(OperationContext* opCtx, StringData ident) {
    WiredTigerSession* session = WiredTigerRecoveryUnit::get(opCtx)->getSession();
    string uri = _uri(ident);
    session->closeAllCursors(uri);
    _sessionCache->closeAllCursors(uri);
    if (isEphemeral()) {
        return Status::OK();
    }
    _ensureIdentPath(ident);
    return _salvageIfNeeded(uri.c_str());
}

Status WiredTigerKVEngine::_salvageIfNeeded(const char* uri) {
    // Using a side session to avoid transactional issues
    WiredTigerSession sessionWrapper(_conn);
    WT_SESSION* session = sessionWrapper.getSession();

    int rc = (session->verify)(session, uri, nullptr);
    if (rc == 0) {
        LOGV2(22327, "Verify succeeded. Not salvaging.", "uri"_attr = uri);
        return Status::OK();
    }

    if (rc == EBUSY) {
        // SERVER-16457: verify and salvage are occasionally failing with EBUSY. For now we
        // lie and return OK to avoid breaking tests. This block should go away when that ticket
        // is resolved.
        LOGV2_ERROR(22356,
                    "Verify failed with EBUSY. This means the collection was being "
                    "accessed. No repair is necessary unless other "
                    "errors are reported.",
                    "uri"_attr = uri);
        return Status::OK();
    }

    if (rc == ENOENT) {
        LOGV2_WARNING(22350,
                      "Data file is missing. Attempting to drop and re-create the collection.",
                      "uri"_attr = uri);

        return _rebuildIdent(session, uri);
    }

    LOGV2(22328, "Verify failed. Running a salvage operation.", "uri"_attr = uri);
    auto status = wtRCToStatus(session->salvage(session, uri, nullptr), "Salvage failed:");
    if (status.isOK()) {
        return {ErrorCodes::DataModifiedByRepair, str::stream() << "Salvaged data for " << uri};
    }

    LOGV2_WARNING(22351,
                  "Salvage failed. The file will be moved out of "
                  "the way and a new ident will be created.",
                  "uri"_attr = uri,
                  "error"_attr = status);

    //  If the data is unsalvageable, we should completely rebuild the ident.
    return _rebuildIdent(session, uri);
}

Status WiredTigerKVEngine::_rebuildIdent(WT_SESSION* session, const char* uri) {
    invariant(_inRepairMode);

    invariant(std::string(uri).find(kTableUriPrefix.rawData()) == 0);

    const std::string identName(uri + kTableUriPrefix.size());
    auto filePath = getDataFilePathForIdent(identName);
    if (filePath) {
        const boost::filesystem::path corruptFile(filePath->string() + ".corrupt");
        LOGV2_WARNING(22352,
                      "Moving data file {file} to backup as {backup}",
                      "Moving data file to backup",
                      "file"_attr = filePath->generic_string(),
                      "backup"_attr = corruptFile.generic_string());

        auto status = fsyncRename(filePath.get(), corruptFile);
        if (!status.isOK()) {
            return status;
        }
    }

    LOGV2_WARNING(22353, "Rebuilding ident {ident}", "Rebuilding ident", "ident"_attr = identName);

    // This is safe to call after moving the file because it only reads from the metadata, and not
    // the data file itself.
    auto swMetadata = WiredTigerUtil::getMetadataCreate(session, uri);
    if (!swMetadata.isOK()) {
        auto status = swMetadata.getStatus();
        LOGV2_ERROR(22357,
                    "Failed to get metadata for {uri}",
                    "Rebuilding ident failed: failed to get metadata",
                    "uri"_attr = uri,
                    "error"_attr = status);
        return status;
    }

    int rc = session->drop(session, uri, nullptr);
    if (rc != 0) {
        auto status = wtRCToStatus(rc);
        LOGV2_ERROR(22358,
                    "Failed to drop {uri}",
                    "Rebuilding ident failed: failed to drop",
                    "uri"_attr = uri,
                    "error"_attr = status);
        return status;
    }

    rc = session->create(session, uri, swMetadata.getValue().c_str());
    if (rc != 0) {
        auto status = wtRCToStatus(rc);
        LOGV2_ERROR(22359,
                    "Failed to create {uri} with config: {config}",
                    "Rebuilding ident failed: failed to create with config",
                    "uri"_attr = uri,
                    "config"_attr = swMetadata.getValue(),
                    "error"_attr = status);
        return status;
    }
    LOGV2(22329, "Successfully re-created table", "uri"_attr = uri);
    return {ErrorCodes::DataModifiedByRepair,
            str::stream() << "Re-created empty data file for " << uri};
}

void WiredTigerKVEngine::flushAllFiles(OperationContext* opCtx, bool callerHoldsReadLock) {
    LOGV2_DEBUG(22330, 1, "WiredTigerKVEngine::flushAllFiles");
    if (_ephemeral) {
        return;
    }
    syncSizeInfo(false);

    // If there's no journal, we must checkpoint all of the data.
    WiredTigerSessionCache::Fsync fsyncType = _durable
        ? WiredTigerSessionCache::Fsync::kCheckpointStableTimestamp
        : WiredTigerSessionCache::Fsync::kCheckpointAll;

    // We will skip updating the journal listener if the caller holds read locks.
    // The JournalListener may do writes, and taking write locks would conflict with the read locks.
    WiredTigerSessionCache::UseJournalListener useListener = callerHoldsReadLock
        ? WiredTigerSessionCache::UseJournalListener::kSkip
        : WiredTigerSessionCache::UseJournalListener::kUpdate;

    _sessionCache->waitUntilDurable(opCtx, fsyncType, useListener);
}

Status WiredTigerKVEngine::beginBackup(OperationContext* opCtx) {
    invariant(!_backupSession);

    // The inMemory Storage Engine cannot create a backup cursor.
    if (_ephemeral) {
        return Status::OK();
    }

    // Persist the sizeStorer information to disk before opening the backup cursor.
    syncSizeInfo(true);

    // This cursor will be freed by the backupSession being closed as the session is uncached
    auto session = std::make_unique<WiredTigerSession>(_conn);
    WT_CURSOR* c = nullptr;
    WT_SESSION* s = session->getSession();
    int ret = WT_OP_CHECK(s->open_cursor(s, "backup:", nullptr, nullptr, &c));
    if (ret != 0) {
        return wtRCToStatus(ret);
    }
    _backupSession = std::move(session);
    return Status::OK();
}

void WiredTigerKVEngine::endBackup(OperationContext* opCtx) {
    if (_sessionCache->isShuttingDown()) {
        // There could be a race with clean shutdown which unconditionally closes all the sessions.
        _backupSession->_session = nullptr;  // Prevent calling _session->close() in destructor.
    }
    _backupSession.reset();
}

Status WiredTigerKVEngine::disableIncrementalBackup(OperationContext* opCtx) {
    // Opening an incremental backup cursor with the "force_stop=true" configuration option then
    // closing the cursor will set a flag in WiredTiger that causes it to release all incremental
    // information and resources.
    // Opening a subsequent incremental backup cursor will reset the flag in WiredTiger and
    // reinstate incremental backup history.
    uassert(31401, "Cannot open backup cursor with in-memory storage engine.", !isEphemeral());

    auto sessionRaii = std::make_unique<WiredTigerSession>(_conn);
    WT_CURSOR* cursor = nullptr;
    WT_SESSION* session = sessionRaii->getSession();
    int wtRet =
        session->open_cursor(session, "backup:", nullptr, "incremental=(force_stop=true)", &cursor);
    if (wtRet != 0) {
        LOGV2_ERROR(22360, "Could not open a backup cursor to disable incremental backups");
        return wtRCToStatus(wtRet);
    }

    return Status::OK();
}

// Similar to beginNonBlockingBackup but
// - don't disable oplog truncation
// - don't call syncSizeInfo
// - returns empty list of files
// Similar to disableIncrementalBackup() above but persists session and cursor to _backupSession and
// _backupCursor
StatusWith<StorageEngine::BackupInformation> WiredTigerKVEngine::_disableIncrementalBackup() {
    // This cursor will be freed by the backupSession being closed as the session is uncached
    auto sessionRaii = std::make_unique<WiredTigerSession>(_conn);
    WT_CURSOR* cursor = nullptr;
    WT_SESSION* session = sessionRaii->getSession();
    int wtRet =
        session->open_cursor(session, "backup:", nullptr, "incremental=(force_stop=true)", &cursor);
    if (wtRet != 0) {
        LOGV2_ERROR(22360, "Could not open a backup cursor to disable incremental backups");
        return wtRCToStatus(wtRet);
    }

    _backupSession = std::move(sessionRaii);
    _backupCursor = cursor;

    return StorageEngine::BackupInformation{};
}

StatusWith<StorageEngine::BackupInformation> WiredTigerKVEngine::beginNonBlockingBackup(
    OperationContext* opCtx, const StorageEngine::BackupOptions& options) {
    uassert(51034, "Cannot open backup cursor with in-memory mode.", !isEphemeral());

    // incrementalBackup and disableIncrementalBackup are mutually exclusive
    // this is guaranteed by checks in DocumentSourceBackupCursor::createFromBson
    if (options.disableIncrementalBackup) {
        return _disableIncrementalBackup();
    }

    std::stringstream ss;
    if (options.incrementalBackup) {
        invariant(options.thisBackupName);
        ss << "incremental=(enabled=true,force_stop=false,";
        ss << "granularity=" << options.blockSizeMB << "MB,";
        ss << "this_id=" << std::quoted(str::escape(*options.thisBackupName)) << ",";

        if (options.srcBackupName) {
            ss << "src_id=" << std::quoted(str::escape(*options.srcBackupName)) << ",";
        }

        ss << ")";
    }

    // Oplog truncation thread won't remove oplog since the checkpoint pinned by the backup cursor.
    stdx::lock_guard<Latch> lock(_oplogPinnedByBackupMutex);
    _checkpointThread->assignOplogNeededForCrashRecoveryTo(&_oplogPinnedByBackup);
    auto pinOplogGuard = makeGuard([&] { _oplogPinnedByBackup = boost::none; });

    // Persist the sizeStorer information to disk before opening the backup cursor. We aren't
    // guaranteed to have the most up-to-date size information after the backup as writes can still
    // occur during a nonblocking backup.
    syncSizeInfo(true);

    // This cursor will be freed by the backupSession being closed as the session is uncached
    auto sessionRaii = std::make_unique<WiredTigerSession>(_conn);
    WT_CURSOR* cursor = nullptr;
    WT_SESSION* session = sessionRaii->getSession();
    const std::string config = ss.str();
    int wtRet = session->open_cursor(session, "backup:", nullptr, config.c_str(), &cursor);
    if (wtRet != 0) {
        return wtRCToStatus(wtRet);
    }

    const bool fullBackup = !options.srcBackupName;
    auto swBackupInfo = getBackupInformationFromBackupCursor(session,
                                                             cursor,
                                                             options.incrementalBackup,
                                                             fullBackup,
                                                             _path,
                                                             "Error opening backup cursor.");

    if (!swBackupInfo.isOK()) {
        return swBackupInfo;
    }

    pinOplogGuard.dismiss();
    _backupSession = std::move(sessionRaii);
    _backupCursor = cursor;

    return swBackupInfo;
}

void WiredTigerKVEngine::endNonBlockingBackup(OperationContext* opCtx) {
    _backupSession.reset();
    // Oplog truncation thread can now remove the pinned oplog.
    stdx::lock_guard<Latch> lock(_oplogPinnedByBackupMutex);
    _oplogPinnedByBackup = boost::none;
    _backupCursor = nullptr;
}

StatusWith<std::vector<std::string>> WiredTigerKVEngine::extendBackupCursor(
    OperationContext* opCtx) {
    uassert(51033, "Cannot extend backup cursor with in-memory mode.", !isEphemeral());
    invariant(_backupCursor);

    // The "target=(\"log:\")" configuration string for the cursor will ensure that we only see the
    // log files when iterating on the cursor.
    WT_CURSOR* cursor = nullptr;
    WT_SESSION* session = _backupSession->getSession();
    int wtRet = session->open_cursor(session, nullptr, _backupCursor, "target=(\"log:\")", &cursor);
    if (wtRet != 0) {
        return wtRCToStatus(wtRet);
    }

    StatusWith<StorageEngine::BackupInformation> swBackupInfo =
        getBackupInformationFromBackupCursor(session,
                                             cursor,
                                             /*incrementalBackup=*/false,
                                             /*fullBackup=*/true,
                                             _path,
                                             "Error extending backup cursor.");

    wtRet = cursor->close(cursor);
    if (wtRet != 0) {
        return wtRCToStatus(wtRet);
    }

    if (!swBackupInfo.isOK()) {
        return swBackupInfo.getStatus();
    }

    // Once all the backup cursors have been opened on a sharded cluster, we need to ensure that the
    // data being copied from each shard is at the same point-in-time across the entire cluster to
    // have a consistent view of the data. For shards that opened their backup cursor before the
    // established point-in-time for backup, they will need to create a full copy of the additional
    // journal files returned by this method to ensure a consistent backup of the data is taken.
    std::vector<std::string> filenames;
    for (const auto& entry : swBackupInfo.getValue()) {
        filenames.push_back(entry.first);
    }

    return {filenames};
}

// Similar to beginNonBlockingBackup but
// - returns empty list of files
StatusWith<StorageEngine::BackupInformation> EncryptionKeyDB::_disableIncrementalBackup() {
    // This cursor will be freed by the backupSession being closed as the session is uncached
    auto sessionRaii = std::make_unique<WiredTigerSession>(_conn);
    WT_CURSOR* cursor = nullptr;
    WT_SESSION* session = sessionRaii->getSession();
    int wtRet =
        session->open_cursor(session, "backup:", nullptr, "incremental=(force_stop=true)", &cursor);
    if (wtRet != 0) {
        LOGV2_ERROR(22360, "Could not open a backup cursor to disable incremental backups");
        return wtRCToStatus(wtRet);
    }

    _backupSession = std::move(sessionRaii);
    _backupCursor = cursor;

    return StorageEngine::BackupInformation{};
}

StatusWith<StorageEngine::BackupInformation> EncryptionKeyDB::beginNonBlockingBackup(
    const StorageEngine::BackupOptions& options) {
    // incrementalBackup and disableIncrementalBackup are mutually exclusive
    // this is guaranteed by checks in DocumentSourceBackupCursor::createFromBson
    if (options.disableIncrementalBackup) {
        return _disableIncrementalBackup();
    }

    std::stringstream ss;
    if (options.incrementalBackup) {
        invariant(options.thisBackupName);
        ss << "incremental=(enabled=true,force_stop=false,";
        ss << "granularity=" << options.blockSizeMB << "MB,";
        ss << "this_id=" << std::quoted(str::escape(*options.thisBackupName)) << ",";

        if (options.srcBackupName) {
            ss << "src_id=" << std::quoted(str::escape(*options.srcBackupName)) << ",";
        }

        ss << ")";
    }

    // This cursor will be freed by the backupSession being closed as the session is uncached
    auto sessionRaii = std::make_unique<WiredTigerSession>(_conn);
    WT_CURSOR* cursor = nullptr;
    WT_SESSION* session = sessionRaii->getSession();
    const std::string config = ss.str();
    int wtRet = session->open_cursor(session, "backup:", nullptr, config.c_str(), &cursor);
    if (wtRet != 0) {
        return wtRCToStatus(wtRet);
    }

    const bool fullBackup = !options.srcBackupName;
    auto swBackupInfo = getBackupInformationFromBackupCursor(session,
                                                             cursor,
                                                             options.incrementalBackup,
                                                             fullBackup,
                                                             _path,
                                                             "Error opening backup cursor.");

    if (!swBackupInfo.isOK()) {
        return swBackupInfo;
    }

    _backupSession = std::move(sessionRaii);
    _backupCursor = cursor;

    return swBackupInfo;
}

Status EncryptionKeyDB::endNonBlockingBackup() {
    _backupSession.reset();
    _backupCursor = nullptr;
    return Status::OK();
}

StatusWith<std::vector<std::string>> EncryptionKeyDB::extendBackupCursor() {
    invariant(_backupCursor);

    // The "target=(\"log:\")" configuration string for the cursor will ensure that we only see the
    // log files when iterating on the cursor.
    WT_CURSOR* cursor = nullptr;
    WT_SESSION* session = _backupSession->getSession();
    int wtRet = session->open_cursor(session, nullptr, _backupCursor, "target=(\"log:\")", &cursor);
    if (wtRet != 0) {
        return wtRCToStatus(wtRet);
    }

    StatusWith<StorageEngine::BackupInformation> swBackupInfo =
        getBackupInformationFromBackupCursor(session,
                                             cursor,
                                             /*incrementalBackup=*/false,
                                             /*fullBackup=*/true,
                                             _path,
                                             "Error extending backup cursor.");

    wtRet = cursor->close(cursor);
    if (wtRet != 0) {
        return wtRCToStatus(wtRet);
    }

    if (!swBackupInfo.isOK()) {
        return swBackupInfo.getStatus();
    }

    // Once all the backup cursors have been opened on a sharded cluster, we need to ensure that the
    // data being copied from each shard is at the same point-in-time across the entire cluster to
    // have a consistent view of the data. For shards that opened their backup cursor before the
    // established point-in-time for backup, they will need to create a full copy of the additional
    // journal files returned by this method to ensure a consistent backup of the data is taken.
    std::vector<std::string> filenames;
    for (const auto& entry : swBackupInfo.getValue()) {
        filenames.push_back(entry.first);
    }

    return {filenames};
}

// Can throw standard exceptions
static void copy_file_size(OperationContext* opCtx,
                           const boost::filesystem::path& srcFile,
                           const boost::filesystem::path& destFile,
                           boost::uintmax_t fsize,
                           ProgressMeterHolder& progressMeter) {
    constexpr int bufsize = 8 * 1024;
    auto buf = std::make_unique<char[]>(bufsize);
    auto bufptr = buf.get();
    constexpr auto samplerate = 128;
    auto sampler = 1;

    std::ifstream src{};
    src.exceptions(std::ios::failbit | std::ios::badbit);
    src.open(srcFile.string(), std::ios::binary);

    std::ofstream dst{};
    dst.exceptions(std::ios::failbit | std::ios::badbit);
    dst.open(destFile.string(), std::ios::binary);

    while (fsize > 0) {
        if (--sampler == 0) {
            opCtx->checkForInterrupt();
            sampler = samplerate;
        }
        boost::uintmax_t cnt = bufsize;
        if (fsize < bufsize)
            cnt = fsize;
        src.read(bufptr, cnt);
        dst.write(bufptr, cnt);
        fsize -= cnt;
        progressMeter.hit(cnt);
    }
}

Status WiredTigerKVEngine::_hotBackupPopulateLists(OperationContext* opCtx,
                                                   const std::string& path,
                                                   std::vector<DBTuple>& dbList,
                                                   std::vector<FileTuple>& filesList,
                                                   boost::uintmax_t& totalfsize) {
    // Nothing to backup for non-durable engine.
    if (!_durable) {
        return EngineExtension::hotBackup(opCtx, path);
    }

    namespace fs = boost::filesystem;
    int ret;

    const char* journalDir = "journal";
    fs::path destPath{path};

    // Prevent any DB writes between two backup cursors
    std::unique_ptr<Lock::GlobalRead> global;
    if (_encryptionKeyDB) {
        global = std::make_unique<decltype(global)::element_type>(opCtx);
    }

    // Open backup cursor in new session, the session will kill the
    // cursor upon closing.
    {
        auto session = std::make_shared<WiredTigerSession>(_conn);
        WT_SESSION* s = session->getSession();
        ret = s->log_flush(s, "sync=off");
        if (ret != 0) {
            return wtRCToStatus(ret);
        }
        WT_CURSOR* c = nullptr;
        ret = s->open_cursor(s, "backup:", nullptr, nullptr, &c);
        if (ret != 0) {
            return wtRCToStatus(ret);
        }
        dbList.emplace_back(_path, destPath, session, c);
    }

    // Open backup cursor for keyDB
    if (_encryptionKeyDB) {
        auto session = std::make_shared<WiredTigerSession>(_encryptionKeyDB->getConnection());
        WT_SESSION* s = session->getSession();
        ret = s->log_flush(s, "sync=off");
        if (ret != 0) {
            return wtRCToStatus(ret);
        }
        WT_CURSOR* c = nullptr;
        ret = s->open_cursor(s, "backup:", nullptr, nullptr, &c);
        if (ret != 0) {
            return wtRCToStatus(ret);
        }
        dbList.emplace_back(fs::path{_path} / keydbDir, destPath / keydbDir, session, c);
    }

    // Populate list of files to copy
    for (auto&& db : dbList) {
        fs::path srcPath = std::get<0>(db);
        fs::path destPath = std::get<1>(db);
        WT_CURSOR* c = std::get<WT_CURSOR*>(db);

        const char* filename = NULL;
        while ((ret = c->next(c)) == 0 && (ret = c->get_key(c, &filename)) == 0) {
            fs::path srcFile{srcPath / filename};
            fs::path destFile{destPath / filename};

            if (fs::exists(srcFile)) {
                auto fsize = fs::file_size(srcFile);
                totalfsize += fsize;
                filesList.emplace_back(srcFile, destFile, fsize, fs::last_write_time(srcFile));
            } else {
                // WT-999: check journal folder.
                srcFile = srcPath / journalDir / filename;
                destFile = destPath / journalDir / filename;
                if (fs::exists(srcFile)) {
                    auto fsize = fs::file_size(srcFile);
                    totalfsize += fsize;
                    filesList.emplace_back(srcFile, destFile, fsize, fs::last_write_time(srcFile));
                } else {
                    return Status(ErrorCodes::InvalidPath,
                                  str::stream() << "Cannot find source file for backup :" << filename << ", source path: " << srcPath.string());
                }
            }
        }
        if (ret == WT_NOTFOUND)
            ret = 0;
        else
            return wtRCToStatus(ret);
    }
    // We also need to backup storage engine metadata
    {
        const char* storageMetadata = "storage.bson";
        fs::path srcFile{fs::path{_path} / storageMetadata};
        fs::path destFile{destPath / storageMetadata};
        auto fsize = fs::file_size(srcFile);
        totalfsize += fsize;
        filesList.emplace_back(srcFile, destFile, fsize, fs::last_write_time(srcFile));
    }

    // Release global lock (if it was created)
    global.reset();

    return wtRCToStatus(ret);
}

static void setupHotBackupProgressMeter(OperationContext* opCtx,
                                        ProgressMeterHolder& progressMeter,
                                        boost::uintmax_t totalfsize) {
    constexpr auto curopMessage = "Hot Backup: copying data bytes"_sd;
    stdx::unique_lock<Client> lk(*opCtx->getClient());
    progressMeter.set(CurOp::get(opCtx)->setProgress_inlock(curopMessage));
    progressMeter->reset(totalfsize, 10, 512);
}

namespace {

// Define log redirector for AWS SDK
class MongoLogSystem : public Aws::Utils::Logging::FormattedLogSystem
{
public:

    using Base = FormattedLogSystem;

    MongoLogSystem() :
        Base(Aws::Utils::Logging::LogLevel::Info)
    {}

    virtual ~MongoLogSystem() {}

protected:

    virtual void ProcessFormattedStatement(Aws::String&& statement) override {
        LOGV2(29011, "{statement}", "statement"_attr = statement);
    }

    virtual void Flush() override {}
};

// Special version of filebuf to read exact number of bytes from the input file
// It works with TransferManager because TransferManager uses seekg/tellg
// in its CreateUploadFileHandle method to get file length and then does not
// try to read after acquired length value.
class AWS_CORE_API SizedFileBuf : public std::filebuf
{
public:
    SizedFileBuf(std::size_t lengthToRead) : _lengthToRead(lengthToRead) {}

protected:
    pos_type seekoff(off_type off, std::ios_base::seekdir dir,
                     std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override {
        if (dir == std::ios_base::end)
            return std::filebuf::seekpos(_lengthToRead + off);
        return std::filebuf::seekoff(off, dir, which);
    }

private:
    const std::size_t _lengthToRead;

};

// Subclass Aws::IOStream to manage SizedFileBuf's lifetime
class AWS_CORE_API SizedFileStream : public Aws::IOStream
{
public:
    SizedFileStream(std::size_t lengthToRead, const std::string &filename, ios_base::openmode mode = ios_base::in)
        : _filebuf(lengthToRead) {
        init(&_filebuf);

        if (!_filebuf.open(filename, mode)) {
            setstate(failbit);
        }
    }

private:
    SizedFileBuf _filebuf;
};

// Subclass AsyncCallerContext
class UploadContext : public Aws::Client::AsyncCallerContext {
public:
    UploadContext(std::shared_ptr<SizedFileStream>& stream)
        : _stream(stream) {}

    const std::shared_ptr<SizedFileStream>& GetStream() const { return _stream; }

    bool ShouldRetry() const { return _retry_cnt-- > 0; }

    void doProgress(ProgressMeterHolder& progressMeter, uint64_t bytes_transferred) const {
        if (bytes_transferred > _bytes_reported) {
            progressMeter.hit(bytes_transferred - _bytes_reported);
            _bytes_reported = bytes_transferred;
        }
    }

private:
    std::shared_ptr<SizedFileStream> _stream;
    mutable int _retry_cnt = 5;
    mutable uint64_t _bytes_reported = 0;
};

}

//TODO: (15) consider replacing s3params with BSONObj and moving parse code from backup_commands.cpp
Status WiredTigerKVEngine::hotBackup(OperationContext* opCtx, const percona::S3BackupParameters& s3params) {
    WiredTigerHotBackupGuard backupGuard{opCtx};
    // list of DBs to backup
    std::vector<DBTuple> dbList;
    // list of files to backup
    std::vector<FileTuple> filesList;
    // total size of files to backup
    boost::uintmax_t totalfsize = 0;

    auto status = _hotBackupPopulateLists(opCtx, s3params.path, dbList, filesList, totalfsize);
    if (!status.isOK()) {
        return status;
    }

    ProgressMeterHolder progressMeter;
    setupHotBackupProgressMeter(opCtx, progressMeter, totalfsize);

    // stream files to S3-compatible storage
    Aws::SDKOptions options;
    Aws::InitAPI(options);
    ON_BLOCK_EXIT([&] { Aws::ShutdownAPI(options); });
    Aws::Utils::Logging::InitializeAWSLogging(Aws::MakeShared<MongoLogSystem>("AWS"));
    ON_BLOCK_EXIT([&] { Aws::Utils::Logging::ShutdownAWSLogging(); });

    Aws::Client::ClientConfiguration config;
    config.endpointOverride = s3params.endpoint; // for example "127.0.0.1:9000"
    config.scheme = Aws::Http::SchemeMapper::FromString(s3params.scheme.c_str());
    if (!s3params.region.empty())
        config.region = s3params.region;

    std::shared_ptr<Aws::Auth::AWSCredentialsProvider> credentialsProvider;
    if (!s3params.accessKeyId.empty()) {
        credentialsProvider = Aws::MakeShared<Aws::Auth::SimpleAWSCredentialsProvider>("AWS",
                                                                                       s3params.accessKeyId,
                                                                                       s3params.secretAccessKey);
    } else {
        // using ProfileConfigFileAWSCredentialsProvider to allow loading of non-default profile
        credentialsProvider = s3params.profile.empty()
            ? Aws::MakeShared<Aws::Auth::ProfileConfigFileAWSCredentialsProvider>("AWS", 1000 * 3600)
            : Aws::MakeShared<Aws::Auth::ProfileConfigFileAWSCredentialsProvider>("AWS", s3params.profile.c_str(), 1000 * 3600);
    }
    auto s3_client = Aws::MakeShared<Aws::S3::S3Client>("AWS", credentialsProvider, config, Aws::Client::AWSAuthV4Signer::PayloadSigningPolicy::Never, s3params.useVirtualAddressing);

    // check if bucket already exists and skip create if it does
    bool bucketExists{false};
    {
        auto outcome = s3_client->ListBuckets();
        if (!outcome.IsSuccess()) {
            return Status(ErrorCodes::InternalError,
                          str::stream() << "Cannot list buckets on storage server"
                                        << " : " << outcome.GetError().GetExceptionName()
                                        << " : " << outcome.GetError().GetMessage());
        }
        for (auto&& bucket : outcome.GetResult().GetBuckets()) {
            if (bucket.GetName() == s3params.bucket) {
                bucketExists = true;
            }
        }
    }

    // create bucket for the backup
    if (!bucketExists) {
        Aws::S3::Model::CreateBucketRequest request;
        request.SetBucket(s3params.bucket);

        auto outcome = s3_client->CreateBucket(request);
        if (!outcome.IsSuccess()) {
            return Status(ErrorCodes::InvalidPath,
                          str::stream() << "Cannot create '" << s3params.bucket << "' bucket for the backup"
                                        << " : " << outcome.GetError().GetExceptionName()
                                        << " : " << outcome.GetError().GetMessage());
        }
        LOGV2(29012, "Successfully created bucket for backup: {bucket}",
              "bucket"_attr = s3params.bucket);
    }

    // check if target location is empty, fail if not
    if (bucketExists) {
        Aws::S3::Model::ListObjectsRequest request;
        request.SetBucket(s3params.bucket);
        if (!s3params.path.empty())
            request.SetPrefix(s3params.path);

        auto outcome = s3_client->ListObjects(request);
        if (!outcome.IsSuccess()) {
            return Status(ErrorCodes::InvalidPath,
                          str::stream() << "Cannot list objects in the target location"
                                        << " : " << outcome.GetError().GetExceptionName()
                                        << " : " << outcome.GetError().GetMessage());
        }
        const auto root = s3params.path + '/';
        Aws::Vector<Aws::S3::Model::Object> object_list = outcome.GetResult().GetContents();
        for (auto const &s3_object : object_list) {
            if (s3_object.GetKey() != root) {
                return Status(ErrorCodes::InvalidPath,
                              str::stream() << "Target location is not empty"
                                            << " : " << s3params.bucket << '/' << s3params.path);
            }
        }
    }

    // multipart uploads do not work with GCP/GCS
    // so we need to check if we can start multipart upload before
    // trying to use TransferManager
    bool multipart_supported = true;
    {
        boost::filesystem::path key{s3params.path};
        key /= "multipart_upload_probe";
        auto outcome = s3_client->CreateMultipartUpload(
                Aws::S3::Model::CreateMultipartUploadRequest()
                .WithBucket(s3params.bucket)
                .WithKey(key.string())
                .WithContentType("application/octet-stream"));
        
        if (!outcome.IsSuccess()) {
            auto e = outcome.GetError();
            if (e.GetResponseCode() == Aws::Http::HttpResponseCode::BAD_REQUEST
                && e.GetErrorType() == Aws::S3::S3Errors::UNKNOWN) {
                multipart_supported = false;
            } else {
                return Status(ErrorCodes::InternalError,
                              str::stream() << "Unexpected error while trying to probe multipart upload support."
                                            << " Response code: " << int(e.GetResponseCode())
                                            << " Error type: " << int(e.GetErrorType()));
            }
        } else {
            // cancel test upload
            auto upload_id = outcome.GetResult().GetUploadId();
            auto outcome2 = s3_client->AbortMultipartUpload(
                    Aws::S3::Model::AbortMultipartUploadRequest()
                    .WithBucket(s3params.bucket)
                    .WithKey(key.string())
                    .WithUploadId(upload_id));
            if (!outcome2.IsSuccess()) {
                return Status(ErrorCodes::InternalError,
                              str::stream() << "Cannot abort test multipart upload"
                                            << " : " << upload_id);
            }
        }
    }

    if (multipart_supported) {
        // stream files using TransferManager
        using namespace Aws::Transfer;

        const size_t poolSize = s3params.threadPoolSize;
        auto executor = Aws::MakeShared<Aws::Utils::Threading::PooledThreadExecutor>("PooledThreadExecutor", poolSize);

        TransferManagerConfiguration trManConf(executor.get());
        trManConf.s3Client = s3_client;
        trManConf.computeContentMD5 = true;

        // by default part size is 5MB and number of parts is limited by 10000
        // if we have files bigger than 50GB we need to increase bufferSize
        // and transferBufferMaxHeapSize
        {
            // s3 object maximum size is 5TB
            constexpr size_t maxS3Object = (1ull << 40) * 5;
            // find biggest file
            size_t biggestFile = 0;
            for (auto&& file : filesList) {
                auto fsize{std::get<2>(file)};
                if (fsize > maxS3Object) {
                    boost::filesystem::path srcFile{std::get<0>(file)};
                    return Status(ErrorCodes::InvalidPath,
                                  str::stream() << "Cannot upload '" << srcFile.string() << "' to s3 "
                                                << "because its size is over maximum s3 object size (5TB)");
                }
                if (fsize > biggestFile) {
                    biggestFile = fsize;
                }
            }
            // find minimum chunk size and round it to MB
            size_t minChunkSizeMB = ((biggestFile / 10000) + (1 << 20) - 1) >> 20;
            if (minChunkSizeMB << 20 > trManConf.bufferSize) {
                LOGV2_DEBUG(29075, 2, "setting multipart upload's chunk size to {minChunkSizeMB}MB", "minChunkSizeMB"_attr = minChunkSizeMB);
                trManConf.bufferSize = minChunkSizeMB << 20;
                trManConf.transferBufferMaxHeapSize = poolSize * trManConf.bufferSize;
            }
        }

        // cancellation indicator
        AtomicWord<bool> backupCancelled(false);
        // error message set when backupCancelled was set to true
        synchronized_value<std::string> cancelMessage;

        // upload callback
        trManConf.uploadProgressCallback = [&](const TransferManager* trMan, const std::shared_ptr<const TransferHandle>& h) {
            if (backupCancelled.load()) {
                if (h->IsMultipart()) {
                    const_cast<TransferManager*>(trMan)->AbortMultipartUpload(
                            std::const_pointer_cast<TransferHandle>(h));
                } else {
                    std::const_pointer_cast<TransferHandle>(h)->Cancel();
                }
            }
            auto uploadContext = std::static_pointer_cast<const UploadContext>(h->GetContext());
            uploadContext->doProgress(progressMeter, h->GetBytesTransferred());
            opCtx->checkForInterrupt();
        };

        // error callback
        trManConf.errorCallback = [](const TransferManager*, const std::shared_ptr<const TransferHandle>& h, const Aws::Client::AWSError<Aws::S3::S3Errors>& e) {
            LOGV2(29076, "errorCallback",
                  "IsMultipart"_attr = h->IsMultipart(),
                  "Id"_attr = h->GetId(),
                  "Key"_attr = h->GetKey(),
                  "MultiPartId"_attr = h->GetMultiPartId(),
                  "VersionId"_attr = h->GetVersionId());
            LOGV2(29077, "errorcallback error",
                  "ErrorType"_attr = static_cast<int>(e.GetErrorType()),
                  "ExceptionName"_attr = e.GetExceptionName(),
                  "Message"_attr = e.GetMessage(),
                  "RemoteHostIpAddress"_attr = e.GetRemoteHostIpAddress(),
                  "RequestId"_attr = e.GetRequestId(),
                  "ResponseCode"_attr = static_cast<int>(e.GetResponseCode()),
                  "ShouldRetry"_attr = e.ShouldRetry());
            // response headers 
            std::stringstream ss;
            for (auto&& header : e.GetResponseHeaders()) {
                ss << header.first << " = " << header.second << ";";
            }
            LOGV2(29078, "errorCallback response headers",
                  "headers"_attr = ss.str());
        };

        // transfer status update callback
        trManConf.transferStatusUpdatedCallback = [&](const TransferManager* trMan, const std::shared_ptr<const TransferHandle>& h) {
            const char* status = "nullptr";
            switch (h->GetStatus()) {
            //this value is only used for directory synchronization
            case TransferStatus::EXACT_OBJECT_ALREADY_EXISTS:
                status = "EXACT_OBJECT_ALREADY_EXISTS"; break;
            //Operation is still queued and has not begun processing
            case TransferStatus::NOT_STARTED:
                status = "NOT_STARTED"; break;
            //Operation is now running
            case TransferStatus::IN_PROGRESS:
                status = "IN_PROGRESS"; break;
            //Operation was canceled. A Canceled operation can still be retried
            case TransferStatus::CANCELED:
                status = "CANCELED"; break;
            //Operation failed, A failed operaton can still be retried.
            case TransferStatus::FAILED:
                status = "FAILED"; break;
            //Operation was successful
            case TransferStatus::COMPLETED:
                status = "COMPLETED"; break;
            //Operation either failed or was canceled and a user deleted the multi-part upload from S3.
            case TransferStatus::ABORTED:
                status = "ABORTED"; break;
            }
            LOGV2_DEBUG(29079, 2, "transferStatusUpdatedCallback",
                        "status"_attr = status,
                        "Id"_attr = h->GetId());
            if (h->GetStatus() == TransferStatus::FAILED) {
                auto uploadContext = std::static_pointer_cast<const UploadContext>(h->GetContext());
                auto err = h->GetLastError();
                LOGV2_WARNING(29080, "Error uploading",
                              "Key"_attr = h->GetKey(),
                              "errmsg"_attr = err.GetMessage());
                if (err.ShouldRetry() && uploadContext->ShouldRetry()) {
                    LOGV2(29081, "Retrying upload",
                          "Key"_attr = h->GetKey());
                    const_cast<TransferManager*>(trMan)->RetryUpload(
                            uploadContext->GetStream(), std::const_pointer_cast<TransferHandle>(h));
                } else {
                    LOGV2_ERROR(29082, "Unrecoverable error occured or retry count exhausted. Cancelling backup");
                    cancelMessage = err.GetMessage();
                    backupCancelled.store(true);
                    if (h->IsMultipart()) {
                        const_cast<TransferManager*>(trMan)->AbortMultipartUpload(
                                std::const_pointer_cast<TransferHandle>(h));
                    } else {
                        std::const_pointer_cast<TransferHandle>(h)->Cancel();
                    }
                }
            }
        };

        auto trMan = TransferManager::Create(trManConf);

        bool failed = false;

        // create code block to run ON_BLOCK_EXIT before
        // checking failed flag value
        {
            std::vector<std::shared_ptr<TransferHandle>> trHandles;
            ON_BLOCK_EXIT([&] {
                for (auto&& h : trHandles) {
                    h->WaitUntilFinished();
                    if (h->GetStatus() != TransferStatus::COMPLETED)
                        failed = true;
                }
            });

            try {
                for (auto&& file : filesList) {
                    boost::filesystem::path srcFile{std::get<0>(file)};
                    boost::filesystem::path destFile{std::get<1>(file)};
                    auto fsize{std::get<2>(file)};

                    LOGV2_DEBUG(29083, 2, "uploading",
                                "fileName"_attr = srcFile.string(),
                                "Key"_attr = destFile.string());

                    auto fileStream = Aws::MakeShared<SizedFileStream>("AWS", static_cast<std::size_t>(fsize),
                            srcFile.string(), std::ios_base::in | std::ios_base::binary);
                    if (!fileStream->good()) {
                        auto eno = errno;
                        // cancel all uploads
                        cancelMessage = 
                            str::stream() << "Cannot open file '" << srcFile.string() << "' for upload. "
                                          << "Error is: " << errnoWithDescription(eno);
                        backupCancelled.store(true);
                        break;
                    }

                    trHandles.push_back(
                        trMan->UploadFile(fileStream,
                                          s3params.bucket,
                                          destFile.string(),
                                          "application/octet-stream",
                                          Aws::Map<Aws::String, Aws::String>(),
                                          Aws::MakeShared<UploadContext>("AWS", fileStream)));
                }
            } catch (const std::exception& ex) {
                // set backupCancelled on any exception
                cancelMessage = ex.what();
                backupCancelled.store(true);
            } 
        }

        if (failed) {
            auto msg = cancelMessage.get();
            if (!msg.empty())
                return Status(ErrorCodes::CommandFailed, cancelMessage.get());
            return Status(ErrorCodes::CommandFailed,
                          "Backup failed. See server log for detailed error messages.");
        }

        return Status::OK();
    }

    // upload files without TransferManager (for those servers which have no 
    // multipart upload support)
    // TODO: for GCP/GCS it is possible to use 'compose' operations

    // reconfigure progressMeter since in this case we will call hit() once per file
    progressMeter->reset(totalfsize, 10, 1);

    for (auto&& file : filesList) {
        boost::filesystem::path srcFile{std::get<0>(file)};
        boost::filesystem::path destFile{std::get<1>(file)};
        auto fsize{std::get<2>(file)};

        LOGV2_DEBUG(29002, 2, "uploading file: {srcFile}", "srcFile"_attr = srcFile.string());
        LOGV2_DEBUG(29003, 2, "      key name: {destFile}", "destFile"_attr = destFile.string());

        Aws::S3::Model::PutObjectRequest request;
        request.SetBucket(s3params.bucket);
        request.SetKey(destFile.string());
        request.SetContentLength(fsize);
        request.SetContentType("application/octet-stream");

        auto fileToUpload = Aws::MakeShared<Aws::FStream>("AWS", srcFile.string(), std::ios_base::in | std::ios_base::binary);
        if (!fileToUpload) {
            return Status(ErrorCodes::InvalidPath,
                          str::stream() << "Cannot open file '" << srcFile.string() << "' for backup"
                                        << " : " << strerror(errno));
        }
        request.SetBody(fileToUpload);

        auto outcome = s3_client->PutObject(request);
        if (!outcome.IsSuccess()) {
            return Status(ErrorCodes::InternalError,
                          str::stream() << "Cannot backup '" << srcFile.string() << "'"
                                        << " : " << outcome.GetError().GetExceptionName()
                                        << " : " << outcome.GetError().GetMessage());
        }
        progressMeter.hit(fsize);
        LOGV2_DEBUG(29004, 2, "Successfully uploaded file: {destFile}",
                    "destFile"_attr = destFile.string());
        opCtx->checkForInterrupt();
    }

    return Status::OK();
}

Status WiredTigerKVEngine::hotBackup(OperationContext* opCtx, const std::string& path) {
    namespace fs = boost::filesystem;

    WiredTigerHotBackupGuard backupGuard{opCtx};
    // list of DBs to backup
    std::vector<DBTuple> dbList;
    // list of files to backup
    std::vector<FileTuple> filesList;
    // total size of files to backup
    boost::uintmax_t totalfsize = 0;

    auto status = _hotBackupPopulateLists(opCtx, path, dbList, filesList, totalfsize);
    if (!status.isOK()) {
        return status;
    }

    ProgressMeterHolder progressMeter;
    setupHotBackupProgressMeter(opCtx, progressMeter, totalfsize);

    // We assume destination dir exists - it is created during command validation
    fs::path destPath{path};
    std::set<fs::path> existDirs{destPath};

    // Do copy files
    for (auto&& file : filesList) {
        fs::path srcFile{std::get<0>(file)};
        fs::path destFile{std::get<1>(file)};
        auto fsize{std::get<2>(file)};

        try {
            // Try creating destination directories if needed.
            const fs::path destDir(destFile.parent_path());
            if (!existDirs.count(destDir)) {
                fs::create_directories(destDir);
                existDirs.insert(destDir);
            }
            // fs::copy_file(srcFile, destFile, fs::copy_option::none);
            // copy_file cannot copy part of file so we need to use
            // more fine-grained copy
            copy_file_size(opCtx, srcFile, destFile, fsize, progressMeter);
        } catch (const fs::filesystem_error& ex) {
            return Status(ErrorCodes::InvalidPath, ex.what());
        } catch (const std::exception& ex) {
            return Status(ErrorCodes::InternalError, ex.what());
        }

    }

    return Status::OK();
}

namespace {

template<typename T1, typename T2>
void a_assert_eq(struct archive *a, T1 r1, T2 r2) {
    if (r1 != r2) {
        std::stringstream ss;
        ss << "libarchive error " << archive_errno(a);
        ss << ": " << archive_error_string(a);
        throw std::runtime_error(ss.str());
    }
}

} // namespace

Status WiredTigerKVEngine::hotBackupTar(OperationContext* opCtx, const std::string& path) {
    namespace fs = boost::filesystem;

    WiredTigerHotBackupGuard backupGuard{opCtx};
    // list of DBs to backup
    std::vector<DBTuple> dbList;
    // list of files to backup
    std::vector<FileTuple> filesList;
    // total size of files to backup
    boost::uintmax_t totalfsize = 0;

    auto status = _hotBackupPopulateLists(opCtx, "", dbList, filesList, totalfsize);
    if (!status.isOK()) {
        return status;
    }

    ProgressMeterHolder progressMeter;
    setupHotBackupProgressMeter(opCtx, progressMeter, totalfsize);

    // Write tar archive
    try {
        struct archive *a{archive_write_new()};
        if (a == nullptr)
            throw std::runtime_error("cannot create archive");
        ON_BLOCK_EXIT([&] { archive_write_free(a);});
        a_assert_eq(a, 0, archive_write_set_format_pax_restricted(a));
        a_assert_eq(a, 0, archive_write_open_filename(a, path.c_str()));

        struct archive_entry *entry{archive_entry_new()};
        if (entry == nullptr)
            throw std::runtime_error("cannot create archive entry");
        ON_BLOCK_EXIT([&] { archive_entry_free(entry);});

        constexpr int bufsize = 8 * 1024;
        auto buf = std::make_unique<char[]>(bufsize);
        auto bufptr = buf.get();
        constexpr auto samplerate = 128;
        auto sampler = 1;

        for (auto&& file : filesList) {
            fs::path srcFile{std::get<0>(file)};
            fs::path destFile{std::get<1>(file)};
            auto fsize{std::get<2>(file)};
            auto fmtime{std::get<3>(file)};

            LOGV2_DEBUG(29005, 2, "backup of file: {srcFile}",
                        "srcFile"_attr = srcFile.string());
            LOGV2_DEBUG(29006, 2, "    storing as: {destFile}",
                        "destFile"_attr = destFile.string());

            archive_entry_clear(entry);
            archive_entry_set_pathname(entry, destFile.string().c_str());
            archive_entry_set_size(entry, fsize);
            archive_entry_set_filetype(entry, AE_IFREG);
            archive_entry_set_perm(entry, 0660);
            archive_entry_set_mtime(entry, fmtime, 0);
            a_assert_eq(a, 0, archive_write_header(a, entry));

            std::ifstream src{};
            src.exceptions(std::ios::failbit | std::ios::badbit);
            src.open(srcFile.string(), std::ios::binary);

            while (fsize > 0) {
                if (--sampler == 0) {
                    opCtx->checkForInterrupt();
                    sampler = samplerate;
                }
                auto cnt = bufsize;
                if (fsize < bufsize)
                    cnt = fsize;
                src.read(bufptr, cnt);
                a_assert_eq(a, cnt, archive_write_data(a, bufptr, cnt));
                fsize -= cnt;
                progressMeter.hit(cnt);
            }
        }
    } catch (const fs::filesystem_error& ex) {
        return Status(ErrorCodes::InvalidPath, ex.what());
    } catch (const std::exception& ex) {
        return Status(ErrorCodes::InternalError, ex.what());
    }

    return Status::OK();
}

void WiredTigerKVEngine::syncSizeInfo(bool sync) const {
    if (!_sizeStorer)
        return;

    try {
        _sizeStorer->flush(sync);
    } catch (const WriteConflictException&) {
        // ignore, we'll try again later.
    } catch (const AssertionException& ex) {
        // re-throw exception if it's not WT_CACHE_FULL.
        if (!_durable && ex.code() == ErrorCodes::ExceededMemoryLimit) {
            LOGV2_ERROR(29000,
                        "size storer failed to sync cache... ignoring: {ex_what}",
                        "ex_what"_attr = ex.what());
        } else {
            throw;
        }
    }
}

void WiredTigerKVEngine::setOldestActiveTransactionTimestampCallback(
    StorageEngine::OldestActiveTransactionTimestampCallback callback) {
    stdx::lock_guard<Latch> lk(_oldestActiveTransactionTimestampCallbackMutex);
    _oldestActiveTransactionTimestampCallback = std::move(callback);
};

RecoveryUnit* WiredTigerKVEngine::newRecoveryUnit() {
    return new WiredTigerRecoveryUnit(_sessionCache.get());
}

void WiredTigerKVEngine::setRecordStoreExtraOptions(const std::string& options) {
    _rsOptions = options;
}

void WiredTigerKVEngine::setSortedDataInterfaceExtraOptions(const std::string& options) {
    _indexOptions = options;
}

Status WiredTigerKVEngine::createGroupedRecordStore(OperationContext* opCtx,
                                                    StringData ns,
                                                    StringData ident,
                                                    const CollectionOptions& options,
                                                    KVPrefix prefix) {
    _ensureIdentPath(ident);
    WiredTigerSession session(_conn);

    const bool prefixed = prefix.isPrefixed();
    StatusWith<std::string> result = WiredTigerRecordStore::generateCreateString(
        _canonicalName, ns, options, _rsOptions, prefixed);
    if (!result.isOK()) {
        return result.getStatus();
    }
    std::string config = result.getValue();

    string uri = _uri(ident);
    WT_SESSION* s = session.getSession();
    LOGV2_DEBUG(22331,
                2,
                "WiredTigerKVEngine::createRecordStore ns: {ns} uri: {uri} config: {config}",
                "ns"_attr = ns,
                "uri"_attr = uri,
                "config"_attr = config);
    return wtRCToStatus(s->create(s, uri.c_str(), config.c_str()));
}

Status WiredTigerKVEngine::recoverOrphanedIdent(OperationContext* opCtx,
                                                const NamespaceString& nss,
                                                StringData ident,
                                                const CollectionOptions& options) {
#ifdef _WIN32
    return {ErrorCodes::CommandNotSupported, "Orphan file recovery is not supported on Windows"};
#else
    invariant(_inRepairMode);

    // Moves the data file to a temporary name so that a new RecordStore can be created with the
    // same ident name. We will delete the new empty collection and rename the data file back so it
    // can be salvaged.

    boost::optional<boost::filesystem::path> identFilePath = getDataFilePathForIdent(ident);
    if (!identFilePath) {
        return {ErrorCodes::UnknownError, "Data file for ident " + ident + " not found"};
    }

    boost::system::error_code ec;
    invariant(boost::filesystem::exists(*identFilePath, ec));

    boost::filesystem::path tmpFile{*identFilePath};
    tmpFile += ".tmp";

    LOGV2(22332,
          "Renaming data file {file} to temporary file {temporary}",
          "Renaming data file to temporary",
          "file"_attr = identFilePath->generic_string(),
          "temporary"_attr = tmpFile.generic_string());
    auto status = fsyncRename(identFilePath.get(), tmpFile);
    if (!status.isOK()) {
        return status;
    }

    LOGV2(22333,
          "Creating new RecordStore for collection {namespace} with UUID: {uuid}",
          "Creating new RecordStore",
          "namespace"_attr = nss,
          "uuid"_attr = options.uuid);

    status = createGroupedRecordStore(opCtx, nss.ns(), ident, options, KVPrefix::kNotPrefixed);
    if (!status.isOK()) {
        return status;
    }

    LOGV2(22334,
          "Moving orphaned data file back as {file}",
          "Restoring orphaned data file",
          "file"_attr = identFilePath->generic_string());

    boost::filesystem::remove(*identFilePath, ec);
    if (ec) {
        return {ErrorCodes::UnknownError, "Error deleting empty data file: " + ec.message()};
    }
    status = fsyncParentDirectory(*identFilePath);
    if (!status.isOK()) {
        return status;
    }

    status = fsyncRename(tmpFile, identFilePath.get());
    if (!status.isOK()) {
        return status;
    }

    auto start = Date_t::now();
    LOGV2(22335, "Salvaging ident {ident}", "Salvaging ident", "ident"_attr = ident);

    WiredTigerSession sessionWrapper(_conn);
    WT_SESSION* session = sessionWrapper.getSession();
    status =
        wtRCToStatus(session->salvage(session, _uri(ident).c_str(), nullptr), "Salvage failed: ");
    LOGV2(4795907, "Salvage complete", "duration"_attr = Date_t::now() - start);
    if (status.isOK()) {
        return {ErrorCodes::DataModifiedByRepair,
                str::stream() << "Salvaged data for ident " << ident};
    }
    LOGV2_WARNING(22354,
                  "Could not salvage data. Rebuilding ident: {status_reason}",
                  "Could not salvage data. Rebuilding ident",
                  "ident"_attr = ident,
                  "error"_attr = status.reason());

    //  If the data is unsalvageable, we should completely rebuild the ident.
    return _rebuildIdent(session, _uri(ident).c_str());
#endif
}

std::unique_ptr<RecordStore> WiredTigerKVEngine::getGroupedRecordStore(
    OperationContext* opCtx,
    StringData ns,
    StringData ident,
    const CollectionOptions& options,
    KVPrefix prefix) {

    WiredTigerRecordStore::Params params;
    params.ns = ns;
    params.ident = ident.toString();
    params.engineName = _canonicalName;
    params.isCapped = options.capped;
    params.isEphemeral = _ephemeral;
    params.cappedCallback = nullptr;
    params.sizeStorer = _sizeStorer.get();
    params.isReadOnly = _readOnly;
    params.tracksSizeAdjustments = true;

    params.cappedMaxSize = -1;
    if (options.capped) {
        if (options.cappedSize) {
            params.cappedMaxSize = options.cappedSize;
        } else {
            params.cappedMaxSize = kDefaultCappedSizeBytes;
        }
    }
    params.cappedMaxDocs = -1;
    if (options.capped && options.cappedMaxDocs)
        params.cappedMaxDocs = options.cappedMaxDocs;

    std::unique_ptr<WiredTigerRecordStore> ret;
    if (prefix == KVPrefix::kNotPrefixed) {
        ret = std::make_unique<StandardWiredTigerRecordStore>(this, opCtx, params);
    } else {
        ret = std::make_unique<PrefixedWiredTigerRecordStore>(this, opCtx, params, prefix);
    }
    ret->postConstructorInit(opCtx);

    // Sizes should always be checked when creating a collection during rollback or replication
    // recovery. This is in case the size storer information is no longer accurate. This may be
    // necessary if capped deletes are rolled-back, if rollback occurs across a collection rename,
    // or when collection creation is not part of a stable checkpoint.
    const auto replCoord = repl::ReplicationCoordinator::get(getGlobalServiceContext());
    const bool inRollback = replCoord && replCoord->getMemberState().rollback();
    if (inRollback || inReplicationRecovery(getGlobalServiceContext())) {
        ret->checkSize(opCtx);
    }

    return std::move(ret);
}

string WiredTigerKVEngine::_uri(StringData ident) const {
    invariant(ident.find(kTableUriPrefix) == string::npos);
    return kTableUriPrefix + ident.toString();
}

Status WiredTigerKVEngine::createGroupedSortedDataInterface(OperationContext* opCtx,
                                                            const CollectionOptions& collOptions,
                                                            StringData ident,
                                                            const IndexDescriptor* desc,
                                                            KVPrefix prefix) {
    _ensureIdentPath(ident);

    std::string collIndexOptions;
    const Collection* collection = desc->getCollection();

    // Treat 'collIndexOptions' as an empty string when the collection member of 'desc' is NULL in
    // order to allow for unit testing WiredTigerKVEngine::createSortedDataInterface().
    if (collection) {
        if (!collOptions.indexOptionDefaults["storageEngine"].eoo()) {
            BSONObj storageEngineOptions = collOptions.indexOptionDefaults["storageEngine"].Obj();
            collIndexOptions =
                dps::extractElementAtPath(storageEngineOptions, _canonicalName + ".configString")
                    .valuestrsafe();
        }
    }

    StatusWith<std::string> result = WiredTigerIndex::generateCreateString(
        _canonicalName, _indexOptions, collIndexOptions, *desc, prefix.isPrefixed());
    if (!result.isOK()) {
        return result.getStatus();
    }

    std::string config = result.getValue();

    LOGV2_DEBUG(22336,
                2,
                "WiredTigerKVEngine::createSortedDataInterface ns: {collection_ns} ident: {ident} "
                "config: {config}",
                "collection_ns"_attr = collection->ns(),
                "ident"_attr = ident,
                "config"_attr = config);
    return wtRCToStatus(WiredTigerIndex::Create(opCtx, _uri(ident), config));
}

std::unique_ptr<SortedDataInterface> WiredTigerKVEngine::getGroupedSortedDataInterface(
    OperationContext* opCtx, StringData ident, const IndexDescriptor* desc, KVPrefix prefix) {
    if (desc->unique()) {
        return std::make_unique<WiredTigerIndexUnique>(opCtx, _uri(ident), desc, prefix, _readOnly);
    }

    return std::make_unique<WiredTigerIndexStandard>(opCtx, _uri(ident), desc, prefix, _readOnly);
}

std::unique_ptr<RecordStore> WiredTigerKVEngine::makeTemporaryRecordStore(OperationContext* opCtx,
                                                                          StringData ident) {
    invariant(!_readOnly || !recoverToOplogTimestamp.empty());

    _ensureIdentPath(ident);
    WiredTigerSession wtSession(_conn);

    CollectionOptions noOptions;
    StatusWith<std::string> swConfig = WiredTigerRecordStore::generateCreateString(
        _canonicalName, "" /* internal table */, noOptions, _rsOptions, false /* prefixed */);
    uassertStatusOK(swConfig.getStatus());

    std::string config = swConfig.getValue();

    std::string uri = _uri(ident);
    WT_SESSION* session = wtSession.getSession();
    LOGV2_DEBUG(22337,
                2,
                "WiredTigerKVEngine::createTemporaryRecordStore uri: {uri} config: {config}",
                "uri"_attr = uri,
                "config"_attr = config);
    uassertStatusOK(wtRCToStatus(session->create(session, uri.c_str(), config.c_str())));

    WiredTigerRecordStore::Params params;
    params.ns = "";
    params.ident = ident.toString();
    params.engineName = _canonicalName;
    params.isCapped = false;
    params.isEphemeral = _ephemeral;
    params.cappedCallback = nullptr;
    // Temporary collections do not need to persist size information to the size storer.
    params.sizeStorer = nullptr;
    // Temporary collections do not need to reconcile collection size/counts.
    params.tracksSizeAdjustments = false;
    params.isReadOnly = false;

    params.cappedMaxSize = -1;
    params.cappedMaxDocs = -1;

    std::unique_ptr<WiredTigerRecordStore> rs;
    rs = std::make_unique<StandardWiredTigerRecordStore>(this, opCtx, params);
    rs->postConstructorInit(opCtx);

    return std::move(rs);
}

void WiredTigerKVEngine::alterIdentMetadata(OperationContext* opCtx,
                                            StringData ident,
                                            const IndexDescriptor* desc) {
    WiredTigerSession session(_conn);
    std::string uri = _uri(ident);

    // Make the alter call to update metadata without taking exclusive lock to avoid conflicts with
    // concurrent operations.
    std::string alterString =
        WiredTigerIndex::generateAppMetadataString(*desc) + "exclusive_refreshed=false,";
    invariantWTOK(
        session.getSession()->alter(session.getSession(), uri.c_str(), alterString.c_str()));
}

Status WiredTigerKVEngine::dropIdent(OperationContext* opCtx, RecoveryUnit* ru, StringData ident) {
    string uri = _uri(ident);

    WiredTigerRecoveryUnit* wtRu = checked_cast<WiredTigerRecoveryUnit*>(ru);
    wtRu->getSessionNoTxn()->closeAllCursors(uri);
    _sessionCache->closeAllCursors(uri);

    WiredTigerSession session(_conn);

    int ret = session.getSession()->drop(
        session.getSession(), uri.c_str(), "force,checkpoint_wait=false");
    LOGV2_DEBUG(22338, 1, "WT drop of {uri} res {ret}", "uri"_attr = uri, "ret"_attr = ret);

    if (ret == 0) {
        // yay, it worked
        return Status::OK();
    }

    if (ret == EBUSY) {
        // this is expected, queue it up
        {
            stdx::lock_guard<Latch> lk(_identToDropMutex);
            _identToDrop.push_front(uri);
        }
        _sessionCache->closeCursorsForQueuedDrops();
        return Status::OK();
    }

    if (ret == ENOENT) {
        return Status::OK();
    }

    invariantWTOK(ret);
    return Status::OK();
}

void WiredTigerKVEngine::keydbDropDatabase(const std::string& db) {
    if (_encryptionKeyDB) {
        int res = _encryptionKeyDB->delete_key_by_id(db);
        if (res) {
            // we cannot throw exceptions here because we are inside WUOW::commit
            // every other part of DB is already dropped so we just log error message
            LOGV2_ERROR(29001,
                        "failed to delete encryption key for db: {db}",
                        "db"_attr = db);
        }
    }
}

std::list<WiredTigerCachedCursor> WiredTigerKVEngine::filterCursorsWithQueuedDrops(
    std::list<WiredTigerCachedCursor>* cache) {
    std::list<WiredTigerCachedCursor> toDrop;

    stdx::lock_guard<Latch> lk(_identToDropMutex);
    if (_identToDrop.empty())
        return toDrop;

    for (auto i = cache->begin(); i != cache->end();) {
        if (!i->_cursor ||
            std::find(_identToDrop.begin(), _identToDrop.end(), std::string(i->_cursor->uri)) ==
                _identToDrop.end()) {
            ++i;
            continue;
        }
        toDrop.push_back(*i);
        i = cache->erase(i);
    }

    return toDrop;
}

bool WiredTigerKVEngine::haveDropsQueued() const {
    Date_t now = _clockSource->now();
    Milliseconds delta = now - _previousCheckedDropsQueued;

    if (!_readOnly && _sizeStorerSyncTracker.intervalHasElapsed()) {
        _sizeStorerSyncTracker.resetLastTime();
        syncSizeInfo(false);
    }

    // We only want to check the queue max once per second or we'll thrash
    if (delta < Milliseconds(1000))
        return false;

    _previousCheckedDropsQueued = now;

    // Don't wait for the mutex: if we can't get it, report that no drops are queued.
    stdx::unique_lock<Latch> lk(_identToDropMutex, stdx::defer_lock);
    return lk.try_lock() && !_identToDrop.empty();
}

void WiredTigerKVEngine::dropSomeQueuedIdents() {
    int numInQueue;

    WiredTigerSession session(_conn);

    {
        stdx::lock_guard<Latch> lk(_identToDropMutex);
        numInQueue = _identToDrop.size();
    }

    int numToDelete = 10;
    int tenPercentQueue = numInQueue * 0.1;
    if (tenPercentQueue > 10)
        numToDelete = tenPercentQueue;

    LOGV2_DEBUG(22339,
                1,
                "WT Queue is: {numInQueue} attempting to drop: {numToDelete} tables",
                "numInQueue"_attr = numInQueue,
                "numToDelete"_attr = numToDelete);
    for (int i = 0; i < numToDelete; i++) {
        string uri;
        {
            stdx::lock_guard<Latch> lk(_identToDropMutex);
            if (_identToDrop.empty())
                break;
            uri = _identToDrop.front();
            _identToDrop.pop_front();
        }
        int ret = session.getSession()->drop(
            session.getSession(), uri.c_str(), "force,checkpoint_wait=false");
        LOGV2_DEBUG(
            22340, 1, "WT queued drop of  {uri} res {ret}", "uri"_attr = uri, "ret"_attr = ret);

        if (ret == EBUSY) {
            stdx::lock_guard<Latch> lk(_identToDropMutex);
            _identToDrop.push_back(uri);
        } else {
            invariantWTOK(ret);
        }
    }
}

bool WiredTigerKVEngine::supportsDocLocking() const {
    return true;
}

bool WiredTigerKVEngine::supportsDirectoryPerDB() const {
    return true;
}

bool WiredTigerKVEngine::hasIdent(OperationContext* opCtx, StringData ident) const {
    return _hasUri(WiredTigerRecoveryUnit::get(opCtx)->getSession()->getSession(), _uri(ident));
}

bool WiredTigerKVEngine::_hasUri(WT_SESSION* session, const std::string& uri) const {
    // can't use WiredTigerCursor since this is called from constructor.
    WT_CURSOR* c = nullptr;
    // No need for a metadata:create cursor, since it gathers extra information and is slower.
    int ret = session->open_cursor(session, "metadata:", nullptr, nullptr, &c);
    if (ret == ENOENT)
        return false;
    invariantWTOK(ret);
    ON_BLOCK_EXIT([&] { c->close(c); });

    c->set_key(c, uri.c_str());
    return c->search(c) == 0;
}

std::vector<std::string> WiredTigerKVEngine::getAllIdents(OperationContext* opCtx) const {
    std::vector<std::string> all;
    int ret;
    // No need for a metadata:create cursor, since it gathers extra information and is slower.
    WiredTigerCursor cursor("metadata:", WiredTigerSession::kMetadataTableId, false, opCtx);
    WT_CURSOR* c = cursor.get();
    if (!c)
        return all;

    while ((ret = c->next(c)) == 0) {
        const char* raw;
        c->get_key(c, &raw);
        StringData key(raw);
        size_t idx = key.find(':');
        if (idx == string::npos)
            continue;
        StringData type = key.substr(0, idx);
        if (type != "table")
            continue;

        StringData ident = key.substr(idx + 1);
        if (ident == "sizeStorer")
            continue;

        all.push_back(ident.toString());
    }

    fassert(50663, ret == WT_NOTFOUND);

    return all;
}

boost::optional<boost::filesystem::path> WiredTigerKVEngine::getDataFilePathForIdent(
    StringData ident) const {
    boost::filesystem::path identPath = _path;
    identPath /= ident.toString() + ".wt";

    boost::system::error_code ec;
    if (!boost::filesystem::exists(identPath, ec)) {
        return boost::none;
    }
    return identPath;
}

int WiredTigerKVEngine::reconfigure(const char* str) {
    return _conn->reconfigure(_conn, str);
}

void WiredTigerKVEngine::_ensureIdentPath(StringData ident) {
    size_t start = 0;
    size_t idx;
    while ((idx = ident.find('/', start)) != string::npos) {
        StringData dir = ident.substr(0, idx);

        boost::filesystem::path subdir = _path;
        subdir /= dir.toString();
        if (!boost::filesystem::exists(subdir)) {
            LOGV2_DEBUG(22341, 1, "creating subdirectory: {dir}", "dir"_attr = dir);
            try {
                boost::filesystem::create_directory(subdir);
            } catch (const std::exception& e) {
                LOGV2_ERROR(22361,
                            "error creating path {directory} {error}",
                            "Error creating directory",
                            "directory"_attr = subdir.string(),
                            "error"_attr = e.what());
                throw;
            }
        }

        start = idx + 1;
    }
}

void WiredTigerKVEngine::setJournalListener(JournalListener* jl) {
    return _sessionCache->setJournalListener(jl);
}

void WiredTigerKVEngine::setStableTimestamp(Timestamp stableTimestamp, bool force) {
    if (stableTimestamp.isNull()) {
        return;
    }

    // Do not set the stable timestamp backward, unless 'force' is set.
    Timestamp prevStable(_stableTimestamp.load());
    if ((stableTimestamp < prevStable) && !force) {
        return;
    }

    // Communicate to WiredTiger what the "stable timestamp" is. Timestamp-aware checkpoints will
    // only persist to disk transactions committed with a timestamp earlier than the "stable
    // timestamp".
    //
    // After passing the "stable timestamp" to WiredTiger, communicate it to the
    // `CheckpointThread`. It's not obvious a stale stable timestamp in the `CheckpointThread` is
    // safe. Consider the following arguments:
    //
    // Setting the "stable timestamp" is only meaningful when the "initial data timestamp" is real
    // (i.e: not `kAllowUnstableCheckpointsSentinel`). In this normal case, the `stableTimestamp`
    // input must be greater than the current value. The only effect this can have in the
    // `CheckpointThread` is to transition it from a state of not taking any checkpoints, to
    // taking "stable checkpoints". In the transitioning case, it's imperative for the "stable
    // timestamp" to have first been communicated to WiredTiger.
    using namespace fmt::literals;
    std::string stableTSConfigString;
    auto ts = stableTimestamp.asULL();
    if (force) {
        stableTSConfigString =
            "force=true,oldest_timestamp={0:x},commit_timestamp={0:x},stable_timestamp={0:x}"_format(
                ts);
        stdx::lock_guard<Latch> lk(_highestDurableTimestampMutex);
        _highestSeenDurableTimestamp = ts;
    } else {
        stableTSConfigString = "stable_timestamp={:x}"_format(ts);
    }
    invariantWTOK(_conn->set_timestamp(_conn, stableTSConfigString.c_str()));

    // After publishing a stable timestamp to WT, we can record the updated stable timestamp value
    // for the necessary oplog to keep.
    _stableTimestamp.store(stableTimestamp.asULL());
    if (_checkpointThread && !_checkpointThread->hasTriggeredFirstStableCheckpoint()) {
        _checkpointThread->triggerFirstStableCheckpoint(
            prevStable, Timestamp(_initialDataTimestamp.load()), stableTimestamp);
    }

    // If 'force' is set, then we have already set the oldest timestamp equal to the stable
    // timestamp, so there is nothing left to do.
    if (force) {
        return;
    }

    // Forward the oldest timestamp so that WiredTiger can clean up earlier timestamp data.
    setOldestTimestampFromStable();
}

void WiredTigerKVEngine::setOldestTimestampFromStable() {
    Timestamp stableTimestamp(_stableTimestamp.load());

    // Set the oldest timestamp to the stable timestamp to ensure that there is no lag window
    // between the two.
    if (MONGO_unlikely(WTSetOldestTSToStableTS.shouldFail())) {
        setOldestTimestamp(stableTimestamp, false);
        return;
    }

    // Calculate what the oldest_timestamp should be from the stable_timestamp. The oldest
    // timestamp should lag behind stable by 'targetSnapshotHistoryWindowInSeconds' to create a
    // window of available snapshots. If the lag window is not yet large enough, we will not
    // update/forward the oldest_timestamp yet and instead return early.
    Timestamp newOldestTimestamp = _calculateHistoryLagFromStableTimestamp(stableTimestamp);
    if (newOldestTimestamp.isNull()) {
        return;
    }

    setOldestTimestamp(newOldestTimestamp, false);
}

void WiredTigerKVEngine::setOldestTimestamp(Timestamp newOldestTimestamp, bool force) {
    if (MONGO_unlikely(WTPreserveSnapshotHistoryIndefinitely.shouldFail())) {
        return;
    }

    if (force) {
        auto oldestTSConfigString =
            "force=true,oldest_timestamp={0:x},commit_timestamp={0:x}"_format(
                newOldestTimestamp.asULL());
        invariantWTOK(_conn->set_timestamp(_conn, oldestTSConfigString.c_str()));
        _oldestTimestamp.store(newOldestTimestamp.asULL());
        stdx::lock_guard<Latch> lk(_highestDurableTimestampMutex);
        _highestSeenDurableTimestamp = newOldestTimestamp.asULL();
        LOGV2_DEBUG(22342,
                    2,
                    "oldest_timestamp and commit_timestamp force set to {newOldestTimestamp}",
                    "newOldestTimestamp"_attr = newOldestTimestamp);
    } else {
        auto oldestTSConfigString = "oldest_timestamp={:x}"_format(newOldestTimestamp.asULL());
        invariantWTOK(_conn->set_timestamp(_conn, oldestTSConfigString.c_str()));
        // set_timestamp above ignores backwards in time if 'force' is not set.
        if (_oldestTimestamp.load() < newOldestTimestamp.asULL())
            _oldestTimestamp.store(newOldestTimestamp.asULL());
        LOGV2_DEBUG(22343,
                    2,
                    "oldest_timestamp set to {newOldestTimestamp}",
                    "newOldestTimestamp"_attr = newOldestTimestamp);
    }
}

Timestamp WiredTigerKVEngine::_calculateHistoryLagFromStableTimestamp(Timestamp stableTimestamp) {
    // The oldest_timestamp should lag behind the stable_timestamp by
    // 'targetSnapshotHistoryWindowInSeconds' seconds.

    if (_ephemeral && !TestingProctor::instance().isEnabled()) {
        // No history should be maintained for the inMemory engine because it is not used yet.
        invariant(snapshotWindowParams.targetSnapshotHistoryWindowInSeconds.load() == 0);
    }

    if (stableTimestamp.getSecs() <
        static_cast<unsigned>(snapshotWindowParams.targetSnapshotHistoryWindowInSeconds.load())) {
        // The history window is larger than the timestamp history thus far. We must wait for
        // the history to reach the window size before moving oldest_timestamp forward.
        return Timestamp();
    }

    Timestamp calculatedOldestTimestamp(
        stableTimestamp.getSecs() -
            snapshotWindowParams.targetSnapshotHistoryWindowInSeconds.load(),
        stableTimestamp.getInc());

    if (calculatedOldestTimestamp.asULL() <= _oldestTimestamp.load()) {
        // The stable_timestamp is not far enough ahead of the oldest_timestamp for the
        // oldest_timestamp to be moved forward: the window is still too small.
        return Timestamp();
    }

    return calculatedOldestTimestamp;
}

void WiredTigerKVEngine::setInitialDataTimestamp(Timestamp initialDataTimestamp) {
    LOGV2_DEBUG(22344,
                2,
                "Setting initial data timestamp. Value: {initialDataTimestamp}",
                "initialDataTimestamp"_attr = initialDataTimestamp);
    _initialDataTimestamp.store(initialDataTimestamp.asULL());
}

Timestamp WiredTigerKVEngine::getInitialDataTimestamp() {
    return Timestamp(_initialDataTimestamp.load());
}

bool WiredTigerKVEngine::supportsRecoverToStableTimestamp() const {
    if (!_keepDataHistory) {
        return false;
    }
    return true;
}

bool WiredTigerKVEngine::supportsRecoveryTimestamp() const {
    return true;
}

bool WiredTigerKVEngine::_canRecoverToStableTimestamp() const {
    static const std::uint64_t allowUnstableCheckpointsSentinel =
        static_cast<std::uint64_t>(Timestamp::kAllowUnstableCheckpointsSentinel.asULL());
    const std::uint64_t initialDataTimestamp = _initialDataTimestamp.load();
    // Illegal to be called when the dataset is incomplete.
    invariant(initialDataTimestamp > allowUnstableCheckpointsSentinel);
    return _stableTimestamp.load() >= initialDataTimestamp;
}

StatusWith<Timestamp> WiredTigerKVEngine::recoverToStableTimestamp(OperationContext* opCtx) {
    if (!supportsRecoverToStableTimestamp()) {
        LOGV2_FATAL(50665, "WiredTiger is configured to not support recover to a stable timestamp");
    }

    if (!_canRecoverToStableTimestamp()) {
        Timestamp stableTS(_stableTimestamp.load());
        Timestamp initialDataTS(_initialDataTimestamp.load());
        return Status(ErrorCodes::UnrecoverableRollbackError,
                      str::stream()
                          << "No stable timestamp available to recover to. Initial data timestamp: "
                          << initialDataTS.toString()
                          << ", Stable timestamp: " << stableTS.toString());
    }

    LOGV2_FOR_ROLLBACK(
        23989, 2, "WiredTiger::RecoverToStableTimestamp syncing size storer to disk.");
    syncSizeInfo(true);

    if (!_ephemeral) {
        LOGV2_FOR_ROLLBACK(
            23990, 2, "WiredTiger::RecoverToStableTimestamp shutting down checkpoint thread.");
        // Shutdown WiredTigerKVEngine owned accesses into the storage engine.
        _checkpointThread->shutdown();
    }

    const Timestamp stableTimestamp(_stableTimestamp.load());
    const Timestamp initialDataTimestamp(_initialDataTimestamp.load());

    LOGV2_FOR_ROLLBACK(23991,
                       0,
                       "Rolling back to the stable timestamp. StableTimestamp: {stableTimestamp} "
                       "Initial Data Timestamp: {initialDataTimestamp}",
                       "Rolling back to the stable timestamp",
                       "stableTimestamp"_attr = stableTimestamp,
                       "initialDataTimestamp"_attr = initialDataTimestamp);
    int ret = _conn->rollback_to_stable(_conn, nullptr);
    if (ret) {
        return {ErrorCodes::UnrecoverableRollbackError,
                str::stream() << "Error rolling back to stable. Err: " << wiredtiger_strerror(ret)};
    }

    if (!_ephemeral) {
        _checkpointThread = std::make_unique<WiredTigerCheckpointThread>(this, _sessionCache.get());
        _checkpointThread->go();
    }

    _sizeStorer = std::make_unique<WiredTigerSizeStorer>(_conn, _sizeStorerUri, _readOnly);

    return {stableTimestamp};
}

namespace {
uint64_t _fetchAllDurableValue(WT_CONNECTION* conn) {
    // Fetch the latest all_durable value from the storage engine. This value will be a timestamp
    // that has no holes (uncommitted transactions with lower timestamps) behind it.
    char buf[(2 * 8 /*bytes in hex*/) + 1 /*nul terminator*/];
    auto wtstatus = conn->query_timestamp(conn, buf, "get=all_durable");
    if (wtstatus == WT_NOTFOUND) {
        // Treat this as lowest possible timestamp; we need to see all preexisting data but no new
        // (timestamped) data.
        return StorageEngine::kMinimumTimestamp;
    } else {
        invariantWTOK(wtstatus);
    }

    uint64_t tmp;
    fassert(38002, NumberParser().base(16)(buf, &tmp));
    return tmp;
}
}  // namespace

Timestamp WiredTigerKVEngine::getAllDurableTimestamp() const {
    auto ret = _fetchAllDurableValue(_conn);

    stdx::lock_guard<Latch> lk(_highestDurableTimestampMutex);
    if (ret < _highestSeenDurableTimestamp) {
        ret = _highestSeenDurableTimestamp;
    } else {
        _highestSeenDurableTimestamp = ret;
    }
    return Timestamp(ret);
}

Timestamp WiredTigerKVEngine::getOldestOpenReadTimestamp() const {
    // Return the minimum read timestamp of all open transactions.
    char buf[(2 * 8 /*bytes in hex*/) + 1 /*null terminator*/];
    auto wtstatus = _conn->query_timestamp(_conn, buf, "get=oldest_reader");
    if (wtstatus == WT_NOTFOUND) {
        return Timestamp();
    } else {
        invariantWTOK(wtstatus);
    }

    uint64_t tmp;
    fassert(38802, NumberParser().base(16)(buf, &tmp));
    return Timestamp(tmp);
}

boost::optional<Timestamp> WiredTigerKVEngine::getRecoveryTimestamp() const {
    if (!supportsRecoveryTimestamp()) {
        LOGV2_FATAL(50745,
                    "WiredTiger is configured to not support providing a recovery timestamp");
    }

    if (_recoveryTimestamp.isNull()) {
        return boost::none;
    }

    return _recoveryTimestamp;
}

boost::optional<Timestamp> WiredTigerKVEngine::getLastStableRecoveryTimestamp() const {
    if (_ephemeral) {
        Timestamp stable(_stableTimestamp.load());
        Timestamp initialData(_initialDataTimestamp.load());
        if (stable.isNull() || stable < initialData) {
            return boost::none;
        }
        return stable;
    }

    const auto ret = _getCheckpointTimestamp();
    if (ret) {
        return Timestamp(ret);
    }

    if (!_recoveryTimestamp.isNull()) {
        return _recoveryTimestamp;
    }

    return boost::none;
}

StatusWith<Timestamp> WiredTigerKVEngine::getOplogNeededForRollback() const {
    // Get the current stable timestamp and use it throughout this function, ignoring updates from
    // another thread.
    auto stableTimestamp = _stableTimestamp.load();

    // Only one thread can set or execute this callback.
    stdx::lock_guard<Latch> lk(_oldestActiveTransactionTimestampCallbackMutex);
    boost::optional<Timestamp> oldestActiveTransactionTimestamp;
    if (_oldestActiveTransactionTimestampCallback) {
        auto status = _oldestActiveTransactionTimestampCallback(Timestamp(stableTimestamp));
        if (status.isOK()) {
            oldestActiveTransactionTimestamp.swap(status.getValue());
        } else {
            LOGV2_DEBUG(22345,
                        1,
                        "getting oldest active transaction timestamp: {status_getStatus}",
                        "status_getStatus"_attr = status.getStatus());
            return status.getStatus();
        }
    }

    if (oldestActiveTransactionTimestamp) {
        return std::min(oldestActiveTransactionTimestamp.value(), Timestamp(stableTimestamp));
    } else {
        return Timestamp(stableTimestamp);
    }
}

boost::optional<Timestamp> WiredTigerKVEngine::getOplogNeededForCrashRecovery() const {
    if (_ephemeral) {
        return boost::none;
    }

    if (_readOnly) {
        return boost::none;
    }

    return Timestamp(_checkpointThread->getOplogNeededForCrashRecovery());
}

Timestamp WiredTigerKVEngine::getPinnedOplog() const {
    // The storage engine may have been told to keep oplog back to a certain timestamp.
    Timestamp pinned = Timestamp(_pinnedOplogTimestamp.load());

    {
        stdx::lock_guard<Latch> lock(_oplogPinnedByBackupMutex);
        if (!storageGlobalParams.allowOplogTruncation) {
            // If oplog truncation is not allowed, then return the min timestamp so that no history
            // is ever allowed to be deleted.
            return Timestamp::min();
        }
        if (_oplogPinnedByBackup) {
            // All the oplog since `_oplogPinnedByBackup` should remain intact during the backup.
            return std::min(_oplogPinnedByBackup.get(), pinned);
        }
    }

    auto oplogNeededForCrashRecovery = getOplogNeededForCrashRecovery();
    if (!_keepDataHistory) {
        // We use rollbackViaRefetch, so we only need to pin oplog for crash recovery.
        return std::min((oplogNeededForCrashRecovery.value_or(Timestamp::max())), pinned);
    }

    if (oplogNeededForCrashRecovery) {
        return std::min(oplogNeededForCrashRecovery.value(), pinned);
    }

    auto status = getOplogNeededForRollback();
    if (status.isOK()) {
        return std::min(status.getValue(), pinned);
    }

    // If getOplogNeededForRollback fails, don't truncate any oplog right now.
    return Timestamp::min();
}

void WiredTigerKVEngine::setPinnedOplogTimestamp(const Timestamp& pinnedTimestamp) {
    _pinnedOplogTimestamp.store(pinnedTimestamp.asULL());
}

bool WiredTigerKVEngine::supportsReadConcernSnapshot() const {
    return true;
}

bool WiredTigerKVEngine::supportsReadConcernMajority() const {
    return _keepDataHistory;
}

bool WiredTigerKVEngine::supportsOplogStones() const {
    return true;
}

void WiredTigerKVEngine::startOplogManager(OperationContext* opCtx,
                                           WiredTigerRecordStore* oplogRecordStore) {
    stdx::lock_guard<Latch> lock(_oplogManagerMutex);
    _oplogManager->startVisibilityThread(opCtx, oplogRecordStore);
}

void WiredTigerKVEngine::haltOplogManager() {
    stdx::unique_lock<Latch> lock(_oplogManagerMutex);
    _oplogManager->haltVisibilityThread();
}

bool WiredTigerKVEngine::isCacheUnderPressure(OperationContext* opCtx) const {
    WiredTigerSession* session = WiredTigerRecoveryUnit::get(opCtx)->getSessionNoTxn();
    invariant(session);

    int64_t score = uassertStatusOK(WiredTigerUtil::getStatisticsValue(
        session->getSession(), "statistics:", "", WT_STAT_CONN_CACHE_LOOKASIDE_SCORE));

    return (score >= snapshotWindowParams.cachePressureThreshold.load());
}

Timestamp WiredTigerKVEngine::getStableTimestamp() const {
    return Timestamp(_stableTimestamp.load());
}

Timestamp WiredTigerKVEngine::getOldestTimestamp() const {
    return Timestamp(_oldestTimestamp.load());
}

Timestamp WiredTigerKVEngine::getCheckpointTimestamp() const {
    return Timestamp(_getCheckpointTimestamp());
}

std::uint64_t WiredTigerKVEngine::_getCheckpointTimestamp() const {
    char buf[(2 * 8 /*bytes in hex*/) + 1 /*nul terminator*/];
    invariantWTOK(_conn->query_timestamp(_conn, buf, "get=last_checkpoint"));

    std::uint64_t tmp;
    fassert(50963, NumberParser().base(16)(buf, &tmp));
    return tmp;
}

}  // namespace mongo
