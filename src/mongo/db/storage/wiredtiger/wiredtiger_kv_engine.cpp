// wiredtiger_kv_engine.cpp


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

#define MONGO_LOG_DEFAULT_COMPONENT ::mongo::logger::LogComponent::kStorage

#include "mongo/platform/basic.h"

#ifdef _WIN32
#define NVALGRIND
#endif

#include <memory>
#include <regex>

#include "mongo/db/storage/wiredtiger/wiredtiger_kv_engine.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/operations.hpp>
#include <libarchive/archive.h>
#include <libarchive/archive_entry.h>
#include <valgrind/valgrind.h>


#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/utils/logging/AWSLogging.h>
#include <aws/core/utils/logging/FormattedLogSystem.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/CreateBucketRequest.h>
#include <aws/s3/model/ListObjectsRequest.h>
#include <aws/s3/model/PutObjectRequest.h>

#include "mongo/base/error_codes.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/bson/dotted_path_support.h"
#include "mongo/db/catalog/collection.h"
#include "mongo/db/catalog/collection_catalog_entry.h"
#include "mongo/db/client.h"
#include "mongo/db/commands/server_status_metric.h"
#include "mongo/db/concurrency/locker.h"
#include "mongo/db/concurrency/write_conflict_exception.h"
#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/index/index_descriptor.h"
#include "mongo/db/mongod_options.h"
#include "mongo/db/repl/repl_settings.h"
#include "mongo/db/server_options.h"
#include "mongo/db/server_parameters.h"
#include "mongo/db/service_context.h"
#include "mongo/db/storage/journal_listener.h"
#include "mongo/db/storage/storage_options.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_customization_hooks.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_encryption_hooks.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_extensions.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_global_options.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_index.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_record_store.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_recovery_unit.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_session_cache.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_size_storer.h"
#include "mongo/platform/atomic_word.h"
#include "mongo/stdx/memory.h"
#include "mongo/util/background.h"
#include "mongo/util/concurrency/idle_thread_block.h"
#include "mongo/util/concurrency/ticketholder.h"
#include "mongo/util/exit.h"
#include "mongo/util/log.h"
#include "mongo/util/processinfo.h"
#include "mongo/util/scopeguard.h"
#include "mongo/util/time_support.h"

#if !defined(__has_feature)
#define __has_feature(x) 0
#endif

namespace mongo {

using std::set;
using std::string;

namespace dps = ::mongo::dotted_path_support;

const int WiredTigerKVEngine::kDefaultJournalDelayMillis = 100;

// Close idle wiredtiger sessions in the session cache after this many seconds.
// The default is 5 mins. Have a shorter default in the debug build to aid testing.
MONGO_EXPORT_SERVER_PARAMETER(wiredTigerSessionCloseIdleTimeSecs,
                              std::int32_t,
                              kDebugBuild ? 5 : 300)
    ->withValidator([](const auto& potentialNewValue) {
        if (potentialNewValue < 0) {
            return Status(ErrorCodes::BadValue,
                          "wiredTigerSessionCloseIdleTimeSecs must be greater than or equal to 0s");
        }
        return Status::OK();
    });

class WiredTigerKVEngine::WiredTigerSessionSweeper : public BackgroundJob {
public:
    explicit WiredTigerSessionSweeper(WiredTigerSessionCache* sessionCache)
        : BackgroundJob(false /* deleteSelf */), _sessionCache(sessionCache) {}

    virtual string name() const {
        return "WTIdleSessionSweeper";
    }

    virtual void run() {
        Client::initThread(name().c_str());

        LOG(1) << "starting " << name() << " thread";

        while (!_shuttingDown.load()) {
            {
                stdx::unique_lock<stdx::mutex> lock(_mutex);
                MONGO_IDLE_THREAD_BLOCK;
                // Check every 10 seconds or sooner in the debug builds
                _condvar.wait_for(lock, stdx::chrono::seconds(kDebugBuild ? 1 : 10));
            }

            _sessionCache->closeExpiredIdleSessions(wiredTigerSessionCloseIdleTimeSecs.load() *
                                                    1000);
        }
        LOG(1) << "stopping " << name() << " thread";
    }

    void shutdown() {
        _shuttingDown.store(true);
        {
            stdx::unique_lock<stdx::mutex> lock(_mutex);
            // Wake up the session sweeper thread early, we do not want the shutdown
            // to wait for us too long.
            _condvar.notify_one();
        }
        wait();
    }

private:
    WiredTigerSessionCache* _sessionCache;
    AtomicBool _shuttingDown{false};

    stdx::mutex _mutex;  // protects _condvar
    // The session sweeper thread idles on this condition variable for a particular time duration
    // between cleaning up expired sessions. It can be triggered early to expediate shutdown.
    stdx::condition_variable _condvar;
};

class WiredTigerKVEngine::WiredTigerJournalFlusher : public BackgroundJob {
public:
    explicit WiredTigerJournalFlusher(WiredTigerSessionCache* sessionCache)
        : BackgroundJob(false /* deleteSelf */), _sessionCache(sessionCache) {}

    virtual string name() const {
        return "WTJournalFlusher";
    }

    virtual void run() {
        Client::initThread(name().c_str());

        LOG(1) << "starting " << name() << " thread";

        while (!_shuttingDown.load()) {
            try {
                const bool forceCheckpoint = false;
                const bool stableCheckpoint = false;
                _sessionCache->waitUntilDurable(forceCheckpoint, stableCheckpoint);
            } catch (const AssertionException& e) {
                invariant(e.code() == ErrorCodes::ShutdownInProgress);
            }

            int ms = storageGlobalParams.journalCommitIntervalMs.load();
            if (!ms) {
                ms = kDefaultJournalDelayMillis;
            }

            MONGO_IDLE_THREAD_BLOCK;
            sleepmillis(ms);
        }
        LOG(1) << "stopping " << name() << " thread";
    }

    void shutdown() {
        _shuttingDown.store(true);
        wait();
    }

private:
    WiredTigerSessionCache* _sessionCache;
    AtomicBool _shuttingDown{false};
};

class WiredTigerKVEngine::WiredTigerCheckpointThread : public BackgroundJob {
public:
    explicit WiredTigerCheckpointThread(WiredTigerSessionCache* sessionCache)
        : BackgroundJob(false /* deleteSelf */),
          _sessionCache(sessionCache),
          _stableTimestamp(0),
          _initialDataTimestamp(0) {}

    virtual string name() const {
        return "WTCheckpointThread";
    }

    virtual void run() {
        Client::initThread(name().c_str());

        LOG(1) << "starting " << name() << " thread";

        while (!_shuttingDown.load()) {
            {
                stdx::unique_lock<stdx::mutex> lock(_mutex);
                MONGO_IDLE_THREAD_BLOCK;
                _condvar.wait_for(lock,
                                  stdx::chrono::seconds(static_cast<std::int64_t>(
                                      wiredTigerGlobalOptions.checkpointDelaySecs)));
            }

            const Timestamp stableTimestamp(_stableTimestamp.load());
            const Timestamp initialDataTimestamp(_initialDataTimestamp.load());
            const bool keepOldBehavior = true;

            try {
                if (keepOldBehavior) {
                    UniqueWiredTigerSession session = _sessionCache->getSession();
                    WT_SESSION* s = session->getSession();
                    invariantWTOK(s->checkpoint(s, nullptr));
                    LOG(4) << "created checkpoint (forced)";
                    // Do KeysDB checkpoint
                    auto encryptionKeyDB = _sessionCache->getKVEngine()->getEncryptionKeyDB();
                    if (encryptionKeyDB) {
                        std::unique_ptr<WiredTigerSession> sess = stdx::make_unique<WiredTigerSession>(encryptionKeyDB->getConnection());
                        WT_SESSION* s = sess->getSession();
                        invariantWTOK(s->checkpoint(s, nullptr));
                    }
                } else {
                    // Three cases:
                    //
                    // First, initialDataTimestamp is Timestamp(0, 1) -> Take full
                    // checkpoint. This is when there is no consistent view of the data (i.e:
                    // during initial sync).
                    //
                    // Second, stableTimestamp < initialDataTimestamp: Skip checkpoints. The data
                    // on disk is prone to being rolled back. Hold off on checkpoints.  Hope that
                    // the stable timestamp surpasses the data on disk, allowing storage to
                    // persist newer copies to disk.
                    //
                    // Third, stableTimestamp >= initialDataTimestamp: Take stable
                    // checkpoint. Steady state case.
                    if (initialDataTimestamp.asULL() <= 1) {
                        const bool forceCheckpoint = true;
                        const bool stableCheckpoint = false;
                        _sessionCache->waitUntilDurable(forceCheckpoint, stableCheckpoint);
                    } else if (stableTimestamp < initialDataTimestamp) {
                        LOG(1) << "Stable timestamp is behind the initial data timestamp, skipping "
                                  "a checkpoint. StableTimestamp: "
                               << stableTimestamp.toString()
                               << " InitialDataTimestamp: " << initialDataTimestamp.toString();
                    } else {
                        const bool forceCheckpoint = true;
                        const bool stableCheckpoint = true;
                        _sessionCache->waitUntilDurable(forceCheckpoint, stableCheckpoint);
                    }
                }
            } catch (const WriteConflictException&) {
                // Temporary: remove this after WT-3483
                warning() << "Checkpoint encountered a write conflict exception.";
            } catch (const AssertionException& exc) {
                invariant(exc.code() == ErrorCodes::ShutdownInProgress);
            }
        }
        LOG(1) << "stopping " << name() << " thread";
    }

    bool supportsRecoverToStableTimestamp() {
        // Replication is calling this method, however it is not setting the
        // `_initialDataTimestamp` in all necessary cases. This may be removed when replication
        // believes all sets of `_initialDataTimestamp` are correct. See SERVER-30184,
        // SERVER-30185, SERVER-30335.
        const bool keepOldBehavior = true;
        if (keepOldBehavior) {
            return false;
        }

        static const std::uint64_t allowUnstableCheckpointsSentinel =
            static_cast<std::uint64_t>(Timestamp::kAllowUnstableCheckpointsSentinel.asULL());
        const std::uint64_t initialDataTimestamp = _initialDataTimestamp.load();
        // Illegal to be called when the dataset is incomplete.
        invariant(initialDataTimestamp > allowUnstableCheckpointsSentinel);

        // Must return false until `recoverToStableTimestamp` is implemented. See SERVER-29213.
        if (keepOldBehavior) {
            return false;
        }
        return _stableTimestamp.load() > initialDataTimestamp;
    }

    void setStableTimestamp(Timestamp stableTimestamp) {
        _stableTimestamp.store(stableTimestamp.asULL());
    }

    void setInitialDataTimestamp(Timestamp initialDataTimestamp) {
        _initialDataTimestamp.store(initialDataTimestamp.asULL());
    }

    void shutdown() {
        _shuttingDown.store(true);
        _condvar.notify_one();
        wait();
    }

private:
    WiredTigerSessionCache* _sessionCache;

    // _mutex/_condvar used to notify when _shuttingDown is flipped.
    stdx::mutex _mutex;
    stdx::condition_variable _condvar;
    AtomicBool _shuttingDown{false};
    AtomicWord<std::uint64_t> _stableTimestamp;
    AtomicWord<std::uint64_t> _initialDataTimestamp;
};

namespace {

constexpr auto keydbDir = "key.db";
constexpr auto rotationDir = "key.db.rotation";
constexpr auto keydbBackupDir = "key.db.rotated";

class TicketServerParameter : public ServerParameter {
    MONGO_DISALLOW_COPYING(TicketServerParameter);

public:
    TicketServerParameter(TicketHolder* holder, const std::string& name)
        : ServerParameter(ServerParameterSet::getGlobal(), name, true, true), _holder(holder) {}

    virtual void append(OperationContext* opCtx, BSONObjBuilder& b, const std::string& name) {
        b.append(name, _holder->outof());
    }

    virtual Status set(const BSONElement& newValueElement) {
        if (!newValueElement.isNumber())
            return Status(ErrorCodes::BadValue, str::stream() << name() << " has to be a number");
        return _set(newValueElement.numberInt());
    }

    virtual Status setFromString(const std::string& str) {
        int num = 0;
        Status status = parseNumberFromString(str, &num);
        if (!status.isOK())
            return status;
        return _set(num);
    }

    Status _set(int newNum) {
        if (newNum <= 0) {
            return Status(ErrorCodes::BadValue, str::stream() << name() << " has to be > 0");
        }

        return _holder->resize(newNum);
    }

private:
    TicketHolder* _holder;
};

TicketHolder openWriteTransaction(128);
TicketServerParameter openWriteTransactionParam(&openWriteTransaction,
                                                "wiredTigerConcurrentWriteTransactions");

TicketHolder openReadTransaction(128);
TicketServerParameter openReadTransactionParam(&openReadTransaction,
                                               "wiredTigerConcurrentReadTransactions");

stdx::function<bool(StringData)> initRsOplogBackgroundThreadCallback = [](StringData) -> bool {
    fassertFailed(40358);
};
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

WiredTigerKVEngine::WiredTigerKVEngine(const std::string& canonicalName,
                                       const std::string& path,
                                       ClockSource* cs,
                                       const std::string& extraOpenOptions,
                                       size_t cacheSizeMB,
                                       size_t maxCacheOverflowFileSizeMB,
                                       bool durable,
                                       bool ephemeral,
                                       bool repair,
                                       bool readOnly)
    : _keepDataHistory(serverGlobalParams.enableMajorityReadConcern),
      _clockSource(cs),
      _oplogManager(stdx::make_unique<WiredTigerOplogManager>()),
      _canonicalName(canonicalName),
      _path(path),
      _sizeStorerSyncTracker(cs, 100000, Seconds(60)),
      _durable(durable),
      _ephemeral(ephemeral),
      _readOnly(readOnly) {
    boost::filesystem::path journalPath = path;
    journalPath /= "journal";
    if (_durable) {
        if (!boost::filesystem::exists(journalPath)) {
            try {
                boost::filesystem::create_directory(journalPath);
            } catch (std::exception& e) {
                log() << "error creating journal dir " << journalPath.string() << ' ' << e.what();
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
        const auto keyDBPathGuard = MakeGuard([&] { if (just_created) fs::remove_all(keyDBPath); });
        if (!fs::exists(keyDBPath)) {
            fs::path betaKeyDBPath = path;
            betaKeyDBPath /= "keydb";
            if (!fs::exists(betaKeyDBPath)) {
                try {
                    fs::create_directory(keyDBPath);
                    just_created = true;
                } catch (std::exception& e) {
                    log() << "error creating KeyDB dir " << keyDBPath.string() << ' ' << e.what();
                    throw;
                }
            } else if (!storageGlobalParams.directoryperdb) {
                // --directoryperdb is not specified - just rename
                try {
                    fs::rename(betaKeyDBPath, keyDBPath);
                } catch (std::exception& e) {
                    log() << "error renaming KeyDB directory from " << betaKeyDBPath.string()
                          << " to " << keyDBPath.string() << ' ' << e.what();
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
                    log() << "error moving KeyDB files from " << betaKeyDBPath.string()
                          << " to " << keyDBPath.string() << ' ' << e.what();
                    throw;
                }
            }
        }
        auto encryptionKeyDB = stdx::make_unique<EncryptionKeyDB>(just_created, keyDBPath.string());
        encryptionKeyDB->init();
        keyDBPathGuard.Dismiss();
        // do master key rotation if necessary
        if (encryptionGlobalParams.vaultRotateMasterKey) {
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
                log() << "error creating rotation directory " << newKeyDBPath.string() << ' ' << e.what();
                throw;
            }
            auto rotationKeyDB = stdx::make_unique<EncryptionKeyDB>(newKeyDBPath.string(), true);
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
            EncryptionHooks::set(getGlobalServiceContext(), stdx::make_unique<WiredTigerEncryptionHooksCBC>());
        else // AES256-GCM
            EncryptionHooks::set(getGlobalServiceContext(), stdx::make_unique<WiredTigerEncryptionHooksGCM>());
    }

    std::stringstream ss;
    ss << "create,";
    ss << "cache_size=" << cacheSizeMB << "M,";
    ss << "cache_overflow=(file_max=" << maxCacheOverflowFileSizeMB << "M),";
    ss << "session_max=20000,";
    ss << "eviction=(threads_min=4,threads_max=4),";
    ss << "config_base=false,";
    ss << "statistics=(fast),";

    if (!WiredTigerSessionCache::isEngineCachingCursors()) {
        ss << "cache_cursors=false,";
    }

    // Ensure WiredTiger creates data in the expected format and attempting to start with a
    // data directory created using a newer version will fail.
    ss << "compatibility=(release=\"3.0\",require_max=\"3.0\"),";

    // The setting may have a later setting override it if not using the journal.  We make it
    // unconditional here because even nojournal may need this setting if it is a transition
    // from using the journal.
    if (!_readOnly) {
        // If we're readOnly skip all WAL-related settings.
        ss << "log=(enabled=true,archive=true,path=journal,compressor=";
        ss << wiredTigerGlobalOptions.journalCompressor << "),";
        ss << "file_manager=(close_idle_time=100000),";  //~28 hours, will put better fix in 3.1.x
        ss << "statistics_log=(wait=" << wiredTigerGlobalOptions.statisticsLogDelaySecs << "),";
        ss << "verbose=(recovery_progress),";
    }
    ss << WiredTigerCustomizationHooks::get(getGlobalServiceContext())
              ->getTableCreateConfig("system");
    ss << WiredTigerExtensions::get(getGlobalServiceContext())->getOpenExtensionsConfig();
    ss << extraOpenOptions;
    if (_readOnly) {
        invariant(!_durable);
        ss << ",readonly=true,";
    }
    if (!_durable && !_readOnly) {
        // If we started without the journal, but previously used the journal then open with the
        // WT log enabled to perform any unclean shutdown recovery and then close and reopen in
        // the normal path without the journal.
        if (boost::filesystem::exists(journalPath)) {
            string config = ss.str();
            log() << "Detected WT journal files.  Running recovery from last checkpoint.";
            log() << "journal to nojournal transition config: " << config;
            int ret = wiredtiger_open(
                path.c_str(), _eventHandler.getWtEventHandler(), config.c_str(), &_conn);
            if (ret == EINVAL) {
                fassertFailedNoTrace(28717);
            } else if (ret != 0) {
                Status s(wtRCToStatus(ret));
                msgasserted(28718, s.reason());
            }
            invariantWTOK(_conn->close(_conn, NULL));
            // After successful recovery, remove the journal directory.
            try {
                boost::filesystem::remove_all(journalPath);
            } catch (std::exception& e) {
                error() << "error removing journal dir " << journalPath.string() << ' ' << e.what();
                throw;
            }
        }
        // This setting overrides the earlier setting because it is later in the config string.
        ss << ",log=(enabled=false),";
    }
    string config = ss.str();
    log() << "wiredtiger_open config: " << config;
    _wtOpenConfig = config;
    int ret =
        wiredtiger_open(path.c_str(), _eventHandler.getWtEventHandler(), config.c_str(), &_conn);
    // Invalid argument (EINVAL) is usually caused by invalid configuration string.
    // We still fassert() but without a stack trace.
    if (ret == EINVAL) {
        fassertFailedNoTrace(28561);
    } else if (ret != 0) {
        Status s(wtRCToStatus(ret));
        msgasserted(28595, s.reason());
    }

    _sessionCache.reset(new WiredTigerSessionCache(this));

    _sessionSweeper = stdx::make_unique<WiredTigerSessionSweeper>(_sessionCache.get());
    _sessionSweeper->go();

    if (_durable && !_ephemeral) {
        _journalFlusher = stdx::make_unique<WiredTigerJournalFlusher>(_sessionCache.get());
        _journalFlusher->go();
    }

    if (!_readOnly && !_ephemeral) {
        _checkpointThread = stdx::make_unique<WiredTigerCheckpointThread>(_sessionCache.get());
        _checkpointThread->go();
    }

    _sizeStorerUri = "table:sizeStorer";
    WiredTigerSession session(_conn);
    if (!_readOnly && repair && _hasUri(session.getSession(), _sizeStorerUri)) {
        log() << "Repairing size cache";
        fassertNoTrace(28577, _salvageIfNeeded(_sizeStorerUri.c_str()));
    }

    const bool sizeStorerLoggingEnabled = !getGlobalReplSettings().usingReplSets();
    _sizeStorer = std::make_unique<WiredTigerSizeStorer>(
        _conn, _sizeStorerUri, sizeStorerLoggingEnabled, _readOnly);

    Locker::setGlobalThrottling(&openReadTransaction, &openWriteTransaction);
}


WiredTigerKVEngine::~WiredTigerKVEngine() {
    if (_conn) {
        cleanShutdown();
    }

    _sessionCache.reset(NULL);
    _encryptionKeyDB.reset(nullptr);
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

void WiredTigerKVEngine::cleanShutdown() {
    log() << "WiredTigerKVEngine shutting down";
    // Ensure that key db is destroyed on exit
    ON_BLOCK_EXIT([&] { _encryptionKeyDB.reset(nullptr); });
    if (!_readOnly)
        syncSizeInfo(true);
    if (_conn) {
        // these must be the last things we do before _conn->close();
        if (_sessionSweeper)
            _sessionSweeper->shutdown();
        if (_journalFlusher)
            _journalFlusher->shutdown();
        if (_checkpointThread)
            _checkpointThread->shutdown();
        _sizeStorer.reset();
        _sessionCache->shuttingDown();

// We want WiredTiger to leak memory for faster shutdown except when we are running tools to
// look for memory leaks.
#if !__has_feature(address_sanitizer)
        bool leak_memory = true;
#else
        bool leak_memory = false;
#endif
        const char* closeConfig = nullptr;

        if (RUNNING_ON_VALGRIND) {
            leak_memory = false;
        }

        if (leak_memory) {
            closeConfig = "leak_memory=true";
        }

        // There are two cases to consider where the server will shutdown before the in-memory FCV
        // state is set. One is when `EncryptionHooks::restartRequired` is true. The other is when
        // the server shuts down because it refuses to acknowledge an FCV value more than one
        // version behind (e.g: 3.6 errors when reading 3.2).
        //
        // In the first case, we ideally do not perform a file format downgrade (but it is
        // acceptable). In the second, the server must downgrade to allow a 3.4 binary to start
        // up. Ideally, our internal FCV value would allow for older values, even if only to
        // immediately shutdown. This would allow downstream logic, such as this method, to make
        // an informed decision.
        const bool needsDowngrade = !_readOnly &&
            serverGlobalParams.featureCompatibility.getVersion() ==
                ServerGlobalParams::FeatureCompatibility::Version::kFullyDowngradedTo34;

        invariantWTOK(_conn->close(_conn, closeConfig));
        _conn = nullptr;

        // If FCV 3.4, enable WT logging on all tables.
        if (needsDowngrade) {
            // Steps for downgrading:
            //
            // 1) Close and reopen WiredTiger. This clears out any leftover cursors that get in
            //    the way of performing the downgrade.
            //
            // 2) Enable WiredTiger logging on all tables.
            //
            // 3) Reconfigure the WiredTiger to release compatibility 2.9. The WiredTiger version
            //    shipped with MongoDB 3.4 will always refuse to start up without this reconfigure
            //    being successful. Doing this last prevents MongoDB running in 3.4 with only some
            //    underlying tables being logged.
            LOG(1) << "Downgrading WiredTiger tables to release compatibility 2.9";
            WT_CONNECTION* conn;
            std::stringstream openConfig;
            openConfig << _wtOpenConfig << ",log=(archive=false)";
            invariantWTOK(wiredtiger_open(
                _path.c_str(), _eventHandler.getWtEventHandler(), openConfig.str().c_str(), &conn));

            WT_SESSION* session;
            conn->open_session(conn, nullptr, "", &session);

            WT_CURSOR* tableCursor;
            invariantWTOK(
                session->open_cursor(session, "metadata:", nullptr, nullptr, &tableCursor));
            while (tableCursor->next(tableCursor) == 0) {
                const char* raw;
                tableCursor->get_key(tableCursor, &raw);
                StringData key(raw);
                size_t idx = key.find(':');
                if (idx == string::npos) {
                    continue;
                }

                StringData type = key.substr(0, idx);
                if (type != "table") {
                    continue;
                }

                uassertStatusOK(WiredTigerUtil::setTableLogging(session, raw, true));
            }

            tableCursor->close(tableCursor);
            session->close(session, nullptr);
            invariantWTOK(conn->reconfigure(conn, "compatibility=(release=2.9)"));
            invariantWTOK(conn->close(conn, closeConfig));
        }
    }  // namespace mongo
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
    return _salvageIfNeeded(uri.c_str());
}

Status WiredTigerKVEngine::_salvageIfNeeded(const char* uri) {
    // Using a side session to avoid transactional issues
    WiredTigerSession sessionWrapper(_conn);
    WT_SESSION* session = sessionWrapper.getSession();

    int rc = (session->verify)(session, uri, NULL);
    if (rc == 0) {
        log() << "Verify succeeded on uri " << uri << ". Not salvaging.";
        return Status::OK();
    }

    if (rc == EBUSY) {
        // SERVER-16457: verify and salvage are occasionally failing with EBUSY. For now we
        // lie and return OK to avoid breaking tests. This block should go away when that ticket
        // is resolved.
        error()
            << "Verify on " << uri << " failed with EBUSY. "
            << "This means the collection was being accessed. No repair is necessary unless other "
               "errors are reported.";
        return Status::OK();
    }

    // TODO need to cleanup the sizeStorer cache after salvaging.
    log() << "Verify failed on uri " << uri << ". Running a salvage operation.";
    return wtRCToStatus(session->salvage(session, uri, NULL), "Salvage failed:");
}

int WiredTigerKVEngine::flushAllFiles(OperationContext* opCtx, bool sync) {
    LOG(1) << "WiredTigerKVEngine::flushAllFiles";
    if (_ephemeral) {
        return 0;
    }
    syncSizeInfo(false);
    const bool forceCheckpoint = true;
    // If there's no journal, we must take a full checkpoint.
    const bool stableCheckpoint = _durable;
    _sessionCache->waitUntilDurable(forceCheckpoint, stableCheckpoint);

    return 1;
}

Status WiredTigerKVEngine::beginBackup(OperationContext* opCtx) {
    invariant(!_backupSession);

    // The inMemory Storage Engine cannot create a backup cursor.
    if (_ephemeral) {
        return Status::OK();
    }

    // This cursor will be freed by the backupSession being closed as the session is uncached
    auto session = stdx::make_unique<WiredTigerSession>(_conn);
    WT_CURSOR* c = NULL;
    WT_SESSION* s = session->getSession();
    int ret = WT_OP_CHECK(s->open_cursor(s, "backup:", NULL, NULL, &c));
    if (ret != 0) {
        return wtRCToStatus(ret);
    }
    _backupSession = std::move(session);
    return Status::OK();
}

void WiredTigerKVEngine::endBackup(OperationContext* opCtx) {
    _backupSession.reset();
}

// Can throw standard exceptions
static void copy_file_size(const boost::filesystem::path& srcFile, const boost::filesystem::path& destFile, boost::uintmax_t fsize) {
    constexpr int bufsize = 8 * 1024;
    auto buf = stdx::make_unique<char[]>(bufsize);
    auto bufptr = buf.get();

    std::ifstream src{};
    src.exceptions(std::ios::failbit | std::ios::badbit);
    src.open(srcFile.string(), std::ios::binary);

    std::ofstream dst{};
    dst.exceptions(std::ios::failbit | std::ios::badbit);
    dst.open(destFile.string(), std::ios::binary);

    while (fsize > 0) {
        boost::uintmax_t cnt = bufsize;
        if (fsize < bufsize)
            cnt = fsize;
        src.read(bufptr, cnt);
        dst.write(bufptr, cnt);
        fsize -= cnt;
    }
}

Status WiredTigerKVEngine::_hotBackupPopulateLists(OperationContext* opCtx, const std::string& path, std::vector<DBTuple>& dbList, std::vector<FileTuple>& filesList) {
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
        global = stdx::make_unique<decltype(global)::element_type>(opCtx);
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
                filesList.emplace_back(srcFile, destFile, fs::file_size(srcFile), fs::last_write_time(srcFile));
            } else {
                // WT-999: check journal folder.
                srcFile = srcPath / journalDir / filename;
                destFile = destPath / journalDir / filename;
                if (fs::exists(srcFile)) {
                    filesList.emplace_back(srcFile, destFile, fs::file_size(srcFile), fs::last_write_time(srcFile));
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
        filesList.emplace_back(srcFile, destFile, fs::file_size(srcFile), fs::last_write_time(srcFile));
    }

    // Release global lock (if it was created)
    global.reset();

    return wtRCToStatus(ret);
}

// Define log redirector for AWS SDK
namespace {

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
        log() << statement;
    }
};

}

//TODO: (15) consider replacing s3params with BSONObj and moving parse code from backup_commands.cpp
Status WiredTigerKVEngine::hotBackup(OperationContext* opCtx, const percona::S3BackupParameters& s3params) {
    // list of DBs to backup
    std::vector<DBTuple> dbList;
    // list of files to backup
    std::vector<FileTuple> filesList;

    auto status = _hotBackupPopulateLists(opCtx, s3params.path, dbList, filesList);
    if (!status.isOK()) {
        return status;
    }

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
    Aws::S3::S3Client s3_client{credentialsProvider, config, Aws::Client::AWSAuthV4Signer::PayloadSigningPolicy::Never, s3params.useVirtualAddressing};

    // check if bucket already exists and skip create if it does
    bool bucketExists{false};
    {
        auto outcome = s3_client.ListBuckets();
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

        auto outcome = s3_client.CreateBucket(request);
        if (!outcome.IsSuccess()) {
            return Status(ErrorCodes::InvalidPath,
                          str::stream() << "Cannot create '" << s3params.bucket << "' bucket for the backup"
                                        << " : " << outcome.GetError().GetExceptionName()
                                        << " : " << outcome.GetError().GetMessage());
        }
        log() << "Successfully created bucket for backup: " << s3params.bucket;
    }

    // check if target location is empty, fail if not
    if (bucketExists) {
        Aws::S3::Model::ListObjectsRequest request;
        request.SetBucket(s3params.bucket);
        if (!s3params.path.empty())
            request.SetPrefix(s3params.path);

        auto outcome = s3_client.ListObjects(request);
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

    // stream files to the bucket
    for (auto&& file : filesList) {
        boost::filesystem::path srcFile{std::get<0>(file)};
        boost::filesystem::path destFile{std::get<1>(file)};
        auto fsize{std::get<2>(file)};

        LOG(2) << "uploading file: " << srcFile.string() << std::endl;
        LOG(2) << "      key name: " << destFile.string() << std::endl;

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

        auto outcome = s3_client.PutObject(request);
        if (!outcome.IsSuccess()) {
            return Status(ErrorCodes::InternalError,
                          str::stream() << "Cannot backup '" << srcFile.string() << "'"
                                        << " : " << outcome.GetError().GetExceptionName()
                                        << " : " << outcome.GetError().GetMessage());
        }
        LOG(2) << "Successfully uploaded file: " << destFile.string();
    }

    return Status::OK();
}

Status WiredTigerKVEngine::hotBackup(OperationContext* opCtx, const std::string& path) {
    namespace fs = boost::filesystem;

    // list of DBs to backup
    std::vector<DBTuple> dbList;
    // list of files to backup
    std::vector<FileTuple> filesList;

    auto status = _hotBackupPopulateLists(opCtx, path, dbList, filesList);
    if (!status.isOK()) {
        return status;
    }

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
            copy_file_size(srcFile, destFile, fsize);
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

    // list of DBs to backup
    std::vector<DBTuple> dbList;
    // list of files to backup
    std::vector<FileTuple> filesList;

    auto status = _hotBackupPopulateLists(opCtx, "", dbList, filesList);
    if (!status.isOK()) {
        return status;
    }

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
        auto buf = stdx::make_unique<char[]>(bufsize);
        auto bufptr = buf.get();

        for (auto&& file : filesList) {
            fs::path srcFile{std::get<0>(file)};
            fs::path destFile{std::get<1>(file)};
            auto fsize{std::get<2>(file)};
            auto fmtime{std::get<3>(file)};

            LOG(2) << "backup of file: " << srcFile.string() << std::endl;
            LOG(2) << "    storing as: " << destFile.string() << std::endl;

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
                boost::uintmax_t cnt = bufsize;
                if (fsize < bufsize)
                    cnt = fsize;
                src.read(bufptr, cnt);
                a_assert_eq(a, cnt, archive_write_data(a, bufptr, cnt));
                fsize -= cnt;
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
            error() << "size storer failed to sync cache... ignoring: " << ex.what();
        } else {
            throw;
        }
    }
}

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
    _checkIdentPath(ident);
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
    LOG(2) << "WiredTigerKVEngine::createRecordStore ns: " << ns << " uri: " << uri
           << " config: " << config;
    return wtRCToStatus(s->create(s, uri.c_str(), config.c_str()));
}

std::unique_ptr<RecordStore> WiredTigerKVEngine::getGroupedRecordStore(
    OperationContext* opCtx,
    StringData ns,
    StringData ident,
    const CollectionOptions& options,
    KVPrefix prefix) {

    WiredTigerRecordStore::Params params;
    params.ns = ns;
    params.uri = _uri(ident);
    params.engineName = _canonicalName;
    params.isCapped = options.capped;
    params.isEphemeral = _ephemeral;
    params.cappedCallback = nullptr;
    params.sizeStorer = _sizeStorer.get();
    params.isReadOnly = _readOnly;

    params.cappedMaxSize = -1;
    if (options.capped) {
        if (options.cappedSize) {
            params.cappedMaxSize = options.cappedSize;
        } else {
            params.cappedMaxSize = 4096;
        }
    }
    params.cappedMaxDocs = -1;
    if (options.capped && options.cappedMaxDocs)
        params.cappedMaxDocs = options.cappedMaxDocs;

    std::unique_ptr<WiredTigerRecordStore> ret;
    if (prefix == KVPrefix::kNotPrefixed) {
        ret = stdx::make_unique<StandardWiredTigerRecordStore>(this, opCtx, params);
    } else {
        ret = stdx::make_unique<PrefixedWiredTigerRecordStore>(this, opCtx, params, prefix);
    }
    ret->postConstructorInit(opCtx);

    return std::move(ret);
}

string WiredTigerKVEngine::_uri(StringData ident) const {
    return string("table:") + ident.toString();
}

Status WiredTigerKVEngine::createGroupedSortedDataInterface(OperationContext* opCtx,
                                                            StringData ident,
                                                            const IndexDescriptor* desc,
                                                            KVPrefix prefix) {
    _checkIdentPath(ident);

    std::string collIndexOptions;
    const Collection* collection = desc->getCollection();

    // Treat 'collIndexOptions' as an empty string when the collection member of 'desc' is NULL in
    // order to allow for unit testing WiredTigerKVEngine::createSortedDataInterface().
    if (collection) {
        const CollectionCatalogEntry* cce = collection->getCatalogEntry();
        const CollectionOptions collOptions = cce->getCollectionOptions(opCtx);

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

    LOG(2) << "WiredTigerKVEngine::createSortedDataInterface ns: " << collection->ns()
           << " ident: " << ident << " config: " << config;
    return wtRCToStatus(WiredTigerIndex::Create(opCtx, _uri(ident), config));
}

SortedDataInterface* WiredTigerKVEngine::getGroupedSortedDataInterface(OperationContext* opCtx,
                                                                       StringData ident,
                                                                       const IndexDescriptor* desc,
                                                                       KVPrefix prefix) {
    if (desc->unique())
        return new WiredTigerIndexUnique(opCtx, _uri(ident), desc, prefix, _readOnly);
    return new WiredTigerIndexStandard(opCtx, _uri(ident), desc, prefix, _readOnly);
}

Status WiredTigerKVEngine::dropIdent(OperationContext* opCtx, StringData ident) {
    string uri = _uri(ident);

    WiredTigerRecoveryUnit* ru = WiredTigerRecoveryUnit::get(opCtx);
    ru->getSessionNoTxn()->closeAllCursors(uri);
    _sessionCache->closeAllCursors(uri);

    WiredTigerSession session(_conn);

    int ret = session.getSession()->drop(
        session.getSession(), uri.c_str(), "force,checkpoint_wait=false");
    LOG(1) << "WT drop of  " << uri << " res " << ret;

    if (ret == 0) {
        // yay, it worked
        return Status::OK();
    }

    if (ret == EBUSY) {
        // this is expected, queue it up
        {
            stdx::lock_guard<stdx::mutex> lk(_identToDropMutex);
            _identToDrop.push_front(uri);
        }
        _sessionCache->closeCursorsForQueuedDrops();
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
            error() << "failed to delete encryption key for db: " << db;
        }
    }
}

std::list<WiredTigerCachedCursor> WiredTigerKVEngine::filterCursorsWithQueuedDrops(
    std::list<WiredTigerCachedCursor>* cache) {
    std::list<WiredTigerCachedCursor> toDrop;

    stdx::lock_guard<stdx::mutex> lk(_identToDropMutex);
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
    stdx::unique_lock<stdx::mutex> lk(_identToDropMutex, stdx::defer_lock);
    return lk.try_lock() && !_identToDrop.empty();
}

void WiredTigerKVEngine::dropSomeQueuedIdents() {
    int numInQueue;

    WiredTigerSession session(_conn);

    {
        stdx::lock_guard<stdx::mutex> lk(_identToDropMutex);
        numInQueue = _identToDrop.size();
    }

    int numToDelete = 10;
    int tenPercentQueue = numInQueue * 0.1;
    if (tenPercentQueue > 10)
        numToDelete = tenPercentQueue;

    LOG(1) << "WT Queue is: " << numInQueue << " attempting to drop: " << numToDelete << " tables";
    for (int i = 0; i < numToDelete; i++) {
        string uri;
        {
            stdx::lock_guard<stdx::mutex> lk(_identToDropMutex);
            if (_identToDrop.empty())
                break;
            uri = _identToDrop.front();
            _identToDrop.pop_front();
        }
        int ret = session.getSession()->drop(
            session.getSession(), uri.c_str(), "force,checkpoint_wait=false");
        LOG(1) << "WT queued drop of  " << uri << " res " << ret;

        if (ret == EBUSY) {
            stdx::lock_guard<stdx::mutex> lk(_identToDropMutex);
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
    ON_BLOCK_EXIT(c->close, c);

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

int WiredTigerKVEngine::reconfigure(const char* str) {
    return _conn->reconfigure(_conn, str);
}

void WiredTigerKVEngine::_checkIdentPath(StringData ident) {
    size_t start = 0;
    size_t idx;
    while ((idx = ident.find('/', start)) != string::npos) {
        StringData dir = ident.substr(0, idx);

        boost::filesystem::path subdir = _path;
        subdir /= dir.toString();
        if (!boost::filesystem::exists(subdir)) {
            LOG(1) << "creating subdirectory: " << dir;
            try {
                boost::filesystem::create_directory(subdir);
            } catch (const std::exception& e) {
                error() << "error creating path " << subdir.string() << ' ' << e.what();
                throw;
            }
        }

        start = idx + 1;
    }
}

void WiredTigerKVEngine::setJournalListener(JournalListener* jl) {
    return _sessionCache->setJournalListener(jl);
}

void WiredTigerKVEngine::setInitRsOplogBackgroundThreadCallback(
    stdx::function<bool(StringData)> cb) {
    initRsOplogBackgroundThreadCallback = std::move(cb);
}

bool WiredTigerKVEngine::initRsOplogBackgroundThread(StringData ns) {
    return initRsOplogBackgroundThreadCallback(ns);
}

void WiredTigerKVEngine::setStableTimestamp(Timestamp stableTimestamp) {
    const bool keepOldBehavior = true;
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
    if (!keepOldBehavior) {
        std::string conf = "stable_timestamp=" + stableTimestamp.toString();
        _conn->set_timestamp(_conn, conf.c_str());
    }
    if (_checkpointThread) {
        _checkpointThread->setStableTimestamp(stableTimestamp);
    }

    if (_keepDataHistory) {
        // If `_keepDataHistory` is false, the OplogManager is responsible for setting the
        // `oldest_timestamp`.
        //
        // Communicate to WiredTiger that it can clean up timestamp data earlier than the
        // timestamp provided.  No future queries will need point-in-time reads at a timestamp
        // prior to the one provided here.
        advanceOldestTimestamp(stableTimestamp);
    }
}

void WiredTigerKVEngine::setOldestTimestamp(Timestamp oldestTimestamp) {
    invariant(oldestTimestamp != Timestamp::min());

    char commitTSConfigString["force=true,oldest_timestamp=,commit_timestamp="_sd.size() +
                              (2 * 8 * 2) /* 8 hexadecimal characters */ + 1 /* trailing null */];
    auto size = std::snprintf(commitTSConfigString,
                              sizeof(commitTSConfigString),
                              "force=true,oldest_timestamp=%llx,commit_timestamp=%llx",
                              oldestTimestamp.asULL(),
                              oldestTimestamp.asULL());
    if (size < 0) {
        int e = errno;
        error() << "error snprintf " << errnoWithDescription(e);
        fassertFailedNoTrace(40662);
    }

    invariant(static_cast<std::size_t>(size) < sizeof(commitTSConfigString));
    invariantWTOK(_conn->set_timestamp(_conn, commitTSConfigString));

    _oplogManager->setOplogReadTimestamp(oldestTimestamp);

    stdx::unique_lock<stdx::mutex> lock(_oplogManagerMutex);
    _previousSetOldestTimestamp = oldestTimestamp;
    LOG(1) << "Forced a new oldest_timestamp. Value: " << oldestTimestamp;
}

void WiredTigerKVEngine::advanceOldestTimestamp(Timestamp oldestTimestamp) {
    if (oldestTimestamp == Timestamp()) {
        // No oldestTimestamp to set, yet.
        return;
    }

    Timestamp timestampToSet;
    {
        stdx::unique_lock<stdx::mutex> lock(_oplogManagerMutex);
        if (!_oplogManager) {
            // No oplog yet, so don't bother setting oldest_timestamp.
            return;
        }
        auto oplogReadTimestamp = _oplogManager->getOplogReadTimestamp();
        if (oplogReadTimestamp < oldestTimestamp.asULL()) {
            // For one node replica sets, the commit point might race ahead of the oplog read
            // timestamp.
            oldestTimestamp = Timestamp(oplogReadTimestamp);
            if (_previousSetOldestTimestamp > oldestTimestamp) {
                // Do not go backwards.
                return;
            }
        }

        // Lag the oldest_timestamp by one timestamp set, to give a bit more history.
        timestampToSet = _previousSetOldestTimestamp;
        _previousSetOldestTimestamp = oldestTimestamp;
    }

    if (timestampToSet == Timestamp()) {
        // Nothing to set yet.
        return;
    }

    char oldestTSConfigString["oldest_timestamp="_sd.size() + (8 * 2) /* 16 hexadecimal digits */ +
                              1 /* trailing null */];
    auto size = std::snprintf(oldestTSConfigString,
                              sizeof(oldestTSConfigString),
                              "oldest_timestamp=%llx",
                              timestampToSet.asULL());
    if (size < 0) {
        int e = errno;
        error() << "error snprintf " << errnoWithDescription(e);
        fassertFailedNoTrace(40661);
    }
    invariant(static_cast<std::size_t>(size) < sizeof(oldestTSConfigString));
    invariantWTOK(_conn->set_timestamp(_conn, oldestTSConfigString));
    LOG(2) << "oldest_timestamp set to " << timestampToSet;
}

void WiredTigerKVEngine::setInitialDataTimestamp(Timestamp initialDataTimestamp) {
    if (_checkpointThread) {
        _checkpointThread->setInitialDataTimestamp(initialDataTimestamp);
    }
}

bool WiredTigerKVEngine::supportsRecoverToStableTimestamp() const {
    if (_ephemeral) {
        return false;
    }

    return _checkpointThread->supportsRecoverToStableTimestamp();
}

Timestamp WiredTigerKVEngine::getAllCommittedTimestamp() const {
    return Timestamp(_oplogManager->fetchAllCommittedValue(_conn));
}

void WiredTigerKVEngine::startOplogManager(OperationContext* opCtx,
                                           const std::string& uri,
                                           WiredTigerRecordStore* oplogRecordStore) {
    stdx::lock_guard<stdx::mutex> lock(_oplogManagerMutex);
    if (_oplogManagerCount == 0) {
        // If we don't want to keep a long history of data changes, have the OplogManager thread
        // update the oldest timestamp with the "all committed" timestamp, i.e: the latest time at
        // which there are no holes.
        _oplogManager->start(opCtx, uri, oplogRecordStore, !_keepDataHistory);
    }
    _oplogManagerCount++;
}

void WiredTigerKVEngine::haltOplogManager() {
    stdx::unique_lock<stdx::mutex> lock(_oplogManagerMutex);
    invariant(_oplogManagerCount > 0);
    _oplogManagerCount--;
    if (_oplogManagerCount == 0) {
        // Destructor may lock the mutex, so we must unlock here.
        // Oplog managers only destruct at shutdown or test exit, so it is safe to unlock here.
        lock.unlock();
        _oplogManager->halt();
    }
}

void WiredTigerKVEngine::replicationBatchIsComplete() const {
    _oplogManager->triggerJournalFlush();
}

}  // namespace mongo
