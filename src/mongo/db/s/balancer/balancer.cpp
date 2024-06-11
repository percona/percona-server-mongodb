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

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kSharding

#include "mongo/platform/basic.h"

#include "mongo/db/s/balancer/balancer.h"

#include <algorithm>
#include <memory>
#include <pcrecpp.h>
#include <string>

#include "mongo/base/status_with.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/client/read_preference.h"
#include "mongo/db/client.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/s/balancer/balancer_chunk_selection_policy_impl.h"
#include "mongo/db/s/balancer/cluster_statistics_impl.h"
#include "mongo/db/s/config/sharding_catalog_manager.h"
#include "mongo/db/s/sharding_config_server_parameters_gen.h"
#include "mongo/db/s/sharding_logging.h"
#include "mongo/logv2/log.h"
#include "mongo/s/balancer_configuration.h"
#include "mongo/s/catalog/type_chunk.h"
#include "mongo/s/client/shard_registry.h"
#include "mongo/s/grid.h"
#include "mongo/s/request_types/balancer_collection_status_gen.h"
#include "mongo/s/shard_util.h"
#include "mongo/s/sharding_feature_flags_gen.h"
#include "mongo/util/concurrency/idle_thread_block.h"
#include "mongo/util/exit.h"
#include "mongo/util/fail_point.h"
#include "mongo/util/timer.h"
#include "mongo/util/version.h"

namespace mongo {

using std::map;
using std::string;
using std::vector;

namespace {

MONGO_FAIL_POINT_DEFINE(overrideBalanceRoundInterval);

const Milliseconds kBalanceRoundDefaultInterval(10000);  // 10 sec

/**
 * Balancer status response
 */
static constexpr StringData kBalancerPolicyStatusDraining = "draining"_sd;
static constexpr StringData kBalancerPolicyStatusZoneViolation = "zoneViolation"_sd;
static constexpr StringData kBalancerPolicyStatusChunksImbalance = "chunksImbalance"_sd;

// Time interval between checks on draining shards.
constexpr Minutes kDrainingShardsCheckInterval{10};

/**
 * Utility class to generate timing and statistics for a single balancer round.
 */
class BalanceRoundDetails {
public:
    BalanceRoundDetails() : _executionTimer() {}

    void setSucceeded(int candidateChunks,
                      int chunksMoved,
                      Milliseconds selectionTime,
                      Milliseconds migrationTime) {
        invariant(!_errMsg);
        _candidateChunks = candidateChunks;
        _chunksMoved = chunksMoved;
        _selectionTime = selectionTime;
        _migrationTime = migrationTime;
    }

    void setFailed(const string& errMsg) {
        _errMsg = errMsg;
    }

    BSONObj toBSON() const {
        BSONObjBuilder builder;
        builder.append("executionTimeMillis", _executionTimer.millis());
        builder.append("errorOccured", _errMsg.is_initialized());

        if (_errMsg) {
            builder.append("errmsg", *_errMsg);
        } else {
            builder.append("candidateChunks", _candidateChunks);
            builder.append("chunksMoved", _chunksMoved);
            BSONObjBuilder timeInfo{builder.subobjStart("times"_sd)};
            timeInfo.append("selectionTimeMillis"_sd, _selectionTime.count());
            timeInfo.append("migrationTimeMillis"_sd, _migrationTime.count());
            timeInfo.done();
        }

        return builder.obj();
    }

private:
    const Timer _executionTimer;
    Milliseconds _selectionTime;
    Milliseconds _migrationTime;

    // Set only on success
    int _candidateChunks{0};
    int _chunksMoved{0};

    // Set only on failure
    boost::optional<string> _errMsg;
};

const auto _balancerDecoration = ServiceContext::declareDecoration<Balancer>();

const ReplicaSetAwareServiceRegistry::Registerer<Balancer> _balancerRegisterer("Balancer");

/**
 * Returns the names of shards that are currently draining. When the balancer is disabled, draining
 * shards are stuck in this state as chunks cannot be migrated.
 */
std::vector<std::string> getDrainingShardNames(OperationContext* opCtx) {
    // Find the shards that are currently draining.
    const auto configShard{Grid::get(opCtx)->shardRegistry()->getConfigShard()};
    const auto drainingShardsDocs{
        uassertStatusOK(
            configShard->exhaustiveFindOnConfig(opCtx,
                                                ReadPreferenceSetting{ReadPreference::Nearest},
                                                repl::ReadConcernLevel::kMajorityReadConcern,
                                                NamespaceString::kConfigsvrShardsNamespace,
                                                BSON(ShardType::draining << true),
                                                BSONObj() /* No sorting */,
                                                boost::none /* No limit */))
            .docs};

    // Build the list of the draining shard names.
    std::vector<std::string> drainingShardNames;
    std::transform(drainingShardsDocs.begin(),
                   drainingShardsDocs.end(),
                   std::back_inserter(drainingShardNames),
                   [](const auto& shardDoc) {
                       const auto shardEntry{uassertStatusOK(ShardType::fromBSON(shardDoc))};
                       return shardEntry.getName();
                   });
    return drainingShardNames;
}

}  // namespace

Balancer* Balancer::get(ServiceContext* serviceContext) {
    return &_balancerDecoration(serviceContext);
}

Balancer* Balancer::get(OperationContext* operationContext) {
    return get(operationContext->getServiceContext());
}

Balancer::Balancer()
    : _balancedLastTime(0),
      _random(std::random_device{}()),
      _clusterStats(std::make_unique<ClusterStatisticsImpl>(_random)),
      _chunkSelectionPolicy(
          std::make_unique<BalancerChunkSelectionPolicyImpl>(_clusterStats.get(), _random)),
      _migrationManager(_balancerDecoration.owner(this)) {}


Balancer::~Balancer() {
    // Terminate the balancer thread so it doesn't leak memory.
    interruptBalancer();
    waitForBalancerToStop();
}

void Balancer::onStepUpBegin(OperationContext* opCtx, long long term) {
    // Before starting step-up, ensure the balancer is ready to start. Specifically, that the
    // balancer is actually stopped, because it may still be in the process of stopping if this
    // node was previously primary.
    waitForBalancerToStop();
}

void Balancer::onStepUpComplete(OperationContext* opCtx, long long term) {
    initiateBalancer(opCtx);
}

void Balancer::onStepDown() {
    interruptBalancer();
}

void Balancer::onBecomeArbiter() {
    // The Balancer is only active on config servers, and arbiters are not permitted in config
    // server replica sets.
    MONGO_UNREACHABLE;
}

void Balancer::initiateBalancer(OperationContext* opCtx) {
    stdx::lock_guard<Latch> scopedLock(_mutex);
    invariant(_state == kStopped);
    _state = kRunning;

    _migrationManager.startRecoveryAndAcquireDistLocks(opCtx);

    invariant(!_thread.joinable());
    invariant(!_threadOperationContext);
    _thread = stdx::thread([this] { _mainThread(); });
}

void Balancer::interruptBalancer() {
    stdx::lock_guard<Latch> scopedLock(_mutex);
    if (_state != kRunning)
        return;

    _state = kStopping;
    _thread.detach();

    // Interrupt the balancer thread if it has been started. We are guaranteed that the operation
    // context of that thread is still alive, because we hold the balancer mutex.
    if (_threadOperationContext) {
        stdx::lock_guard<Client> scopedClientLock(*_threadOperationContext->getClient());
        _threadOperationContext->markKilled(ErrorCodes::InterruptedDueToReplStateChange);
    }

    // Schedule a separate thread to shutdown the migration manager in order to avoid deadlock with
    // replication step down
    invariant(!_migrationManagerInterruptThread.joinable());
    _migrationManagerInterruptThread =
        stdx::thread([this] { _migrationManager.interruptAndDisableMigrations(); });

    _condVar.notify_all();
}

void Balancer::waitForBalancerToStop() {
    stdx::unique_lock<Latch> scopedLock(_mutex);

    _joinCond.wait(scopedLock, [this] { return _state == kStopped; });
}

void Balancer::joinCurrentRound(OperationContext* opCtx) {
    stdx::unique_lock<Latch> scopedLock(_mutex);
    const auto numRoundsAtStart = _numBalancerRounds;
    opCtx->waitForConditionOrInterrupt(_condVar, scopedLock, [&] {
        return !_inBalancerRound || _numBalancerRounds != numRoundsAtStart;
    });
}

Balancer::ScopedPauseBalancerRequest Balancer::requestPause() {
    return ScopedPauseBalancerRequest(this);
}

Status Balancer::rebalanceSingleChunk(OperationContext* opCtx, const ChunkType& chunk) {
    auto migrateStatus = _chunkSelectionPolicy->selectSpecificChunkToMove(opCtx, chunk);
    if (!migrateStatus.isOK()) {
        return migrateStatus.getStatus();
    }

    auto migrateInfo = std::move(migrateStatus.getValue());
    if (!migrateInfo) {
        LOGV2_DEBUG(21854,
                    1,
                    "Unable to find more appropriate location for chunk {chunk}",
                    "Unable to find more appropriate location for chunk",
                    "chunk"_attr = redact(chunk.toString()));
        return Status::OK();
    }

    auto balancerConfig = Grid::get(opCtx)->getBalancerConfiguration();
    Status refreshStatus = balancerConfig->refreshAndCheck(opCtx);
    if (!refreshStatus.isOK()) {
        return refreshStatus;
    }

    return _migrationManager.executeManualMigration(opCtx,
                                                    *migrateInfo,
                                                    balancerConfig->getMaxChunkSizeBytes(),
                                                    balancerConfig->getSecondaryThrottle(),
                                                    balancerConfig->waitForDelete());
}

Status Balancer::moveSingleChunk(OperationContext* opCtx,
                                 const ChunkType& chunk,
                                 const ShardId& newShardId,
                                 uint64_t maxChunkSizeBytes,
                                 const MigrationSecondaryThrottleOptions& secondaryThrottle,
                                 bool waitForDelete,
                                 bool forceJumbo) {
    auto moveAllowedStatus = _chunkSelectionPolicy->checkMoveAllowed(opCtx, chunk, newShardId);
    if (!moveAllowedStatus.isOK()) {
        return moveAllowedStatus;
    }

    return _migrationManager.executeManualMigration(
        opCtx,
        MigrateInfo(newShardId,
                    chunk,
                    forceJumbo ? MoveChunkRequest::ForceJumbo::kForceManual
                               : MoveChunkRequest::ForceJumbo::kDoNotForce,
                    MigrateInfo::chunksImbalance),
        maxChunkSizeBytes,
        secondaryThrottle,
        waitForDelete);
}

void Balancer::report(OperationContext* opCtx, BSONObjBuilder* builder) {
    auto balancerConfig = Grid::get(opCtx)->getBalancerConfiguration();
    balancerConfig->refreshAndCheck(opCtx).ignore();

    const auto mode = balancerConfig->getBalancerMode();

    stdx::lock_guard<Latch> scopedLock(_mutex);
    builder->append("mode", BalancerSettingsType::kBalancerModes[mode]);
    builder->append("inBalancerRound", _inBalancerRound);
    builder->append("numBalancerRounds", _numBalancerRounds);
}

void Balancer::_mainThread() {
    ON_BLOCK_EXIT([this] {
        stdx::lock_guard<Latch> scopedLock(_mutex);

        _state = kStopped;
        _joinCond.notify_all();

        LOGV2_DEBUG(21855, 1, "Balancer thread terminated");
    });

    Client::initThread("Balancer");
    auto opCtx = cc().makeOperationContext();
    auto shardingContext = Grid::get(opCtx.get());

    LOGV2(21856, "CSRS balancer is starting");

    {
        stdx::lock_guard<Latch> scopedLock(_mutex);
        _threadOperationContext = opCtx.get();
    }

    const Seconds kInitBackoffInterval(10);

    auto balancerConfig = shardingContext->getBalancerConfiguration();
    while (!_stopRequested()) {
        Status refreshStatus = balancerConfig->refreshAndCheck(opCtx.get());
        if (!refreshStatus.isOK()) {
            LOGV2_WARNING(
                21876,
                "Balancer settings could not be loaded because of {error} and will be retried in "
                "{backoffInterval}",
                "Got error while refreshing balancer settings, will retry with a backoff",
                "backoffInterval"_attr = Milliseconds(kInitBackoffInterval),
                "error"_attr = refreshStatus);

            _sleepFor(opCtx.get(), kInitBackoffInterval);
            continue;
        }

        break;
    }

    LOGV2(21857, "CSRS balancer thread is recovering");

    _migrationManager.finishRecovery(opCtx.get(),
                                     balancerConfig->getMaxChunkSizeBytes(),
                                     balancerConfig->getSecondaryThrottle());

    LOGV2(21858, "CSRS balancer thread is recovered");

    // Main balancer loop
    auto lastDrainingShardsCheckTime{Date_t::fromMillisSinceEpoch(0)};
    while (!_stopRequested()) {
        BalanceRoundDetails roundDetails;

        _beginRound(opCtx.get());

        try {
            shardingContext->shardRegistry()->reload(opCtx.get());

            uassert(13258, "oids broken after resetting!", _checkOIDs(opCtx.get()));

            Status refreshStatus = balancerConfig->refreshAndCheck(opCtx.get());
            if (!refreshStatus.isOK()) {
                LOGV2_WARNING(21877,
                              "Skipping balancing round due to {error}",
                              "Skipping balancing round",
                              "error"_attr = refreshStatus);
                _endRound(opCtx.get(), kBalanceRoundDefaultInterval);
                continue;
            }

            if (!balancerConfig->shouldBalance() || _stopOrPauseRequested()) {
                if (balancerConfig->getBalancerMode() == BalancerSettingsType::BalancerMode::kOff &&
                    Date_t::now() - lastDrainingShardsCheckTime >= kDrainingShardsCheckInterval) {
                    const auto drainingShardNames{getDrainingShardNames(opCtx.get())};
                    if (!drainingShardNames.empty()) {
                        LOGV2_WARNING(6434000,
                                      "Draining of removed shards cannot be completed because the "
                                      "balancer is disabled",
                                      "shards"_attr = drainingShardNames);
                    }

                    lastDrainingShardsCheckTime = Date_t::now();
                }

                LOGV2_DEBUG(21859, 1, "Skipping balancing round because balancing is disabled");
                _endRound(opCtx.get(), kBalanceRoundDefaultInterval);
                continue;
            }

            LOGV2_DEBUG(21860,
                        1,
                        "Start balancing round. waitForDelete: {waitForDelete}, "
                        "secondaryThrottle: {secondaryThrottle}",
                        "Start balancing round",
                        "waitForDelete"_attr = balancerConfig->waitForDelete(),
                        "secondaryThrottle"_attr = balancerConfig->getSecondaryThrottle().toBSON());

            // Split chunk to match zones boundaries
            {
                Status status = _splitChunksIfNeeded(opCtx.get());
                if (!status.isOK()) {
                    LOGV2_WARNING(21878,
                                  "Failed to split chunks due to {error}",
                                  "Failed to split chunks",
                                  "error"_attr = status);
                } else {
                    LOGV2_DEBUG(21861, 1, "Done enforcing tag range boundaries.");
                }
            }

            // Select and migrate chunks
            {
                Timer selectionTimer;
                const auto candidateChunks =
                    uassertStatusOK(_chunkSelectionPolicy->selectChunksToMove(opCtx.get()));
                const Milliseconds selectionTimeMillis{selectionTimer.millis()};

                if (candidateChunks.empty()) {
                    LOGV2_DEBUG(21862, 1, "No need to move any chunk");
                    _balancedLastTime = 0;
                } else {
                    Timer migrationTimer;
                    _balancedLastTime = _moveChunks(opCtx.get(), candidateChunks);
                    const Milliseconds migrationTimeMillis{migrationTimer.millis()};

                    roundDetails.setSucceeded(static_cast<int>(candidateChunks.size()),
                                              _balancedLastTime,
                                              selectionTimeMillis,
                                              migrationTimeMillis);

                    ShardingLogging::get(opCtx.get())
                        ->logAction(opCtx.get(), "balancer.round", "", roundDetails.toBSON())
                        .ignore();
                }

                LOGV2_DEBUG(21863, 1, "End balancing round");
            }

            Milliseconds balancerInterval = _balancedLastTime
                ? Milliseconds(balancerMigrationsThrottlingMs.load())
                : kBalanceRoundDefaultInterval;

            overrideBalanceRoundInterval.execute([&](const BSONObj& data) {
                balancerInterval = Milliseconds(data["intervalMs"].numberInt());
                LOGV2(21864,
                      "overrideBalanceRoundInterval: using shorter balancing interval: "
                      "{balancerInterval}",
                      "overrideBalanceRoundInterval: using shorter balancing interval",
                      "balancerInterval"_attr = balancerInterval);
            });

            _endRound(opCtx.get(), balancerInterval);
        } catch (const DBException& e) {
            LOGV2(21865,
                  "caught exception while doing balance: {error}",
                  "Error while doing balance",
                  "error"_attr = e);

            // Just to match the opening statement if in log level 1
            LOGV2_DEBUG(21866, 1, "End balancing round");

            // This round failed, tell the world!
            roundDetails.setFailed(e.what());

            ShardingLogging::get(opCtx.get())
                ->logAction(opCtx.get(), "balancer.round", "", roundDetails.toBSON())
                .ignore();

            // Sleep a fair amount before retrying because of the error
            _endRound(opCtx.get(), kBalanceRoundDefaultInterval);
        }
    }

    {
        stdx::lock_guard<Latch> scopedLock(_mutex);
        invariant(_state == kStopping);
        invariant(_migrationManagerInterruptThread.joinable());
    }

    _migrationManagerInterruptThread.join();
    _migrationManager.drainActiveMigrations();

    {
        stdx::lock_guard<Latch> scopedLock(_mutex);
        _migrationManagerInterruptThread = {};
        _threadOperationContext = nullptr;
    }

    LOGV2(21867, "CSRS balancer is now stopped");
}

void Balancer::_addPauseRequest() {
    stdx::unique_lock<Latch> scopedLock(_mutex);
    ++_numPauseRequests;
}

void Balancer::_removePauseRequest() {
    stdx::unique_lock<Latch> scopedLock(_mutex);
    invariant(_numPauseRequests > 0);
    --_numPauseRequests;
}

bool Balancer::_stopRequested() {
    stdx::lock_guard<Latch> scopedLock(_mutex);
    return (_state != kRunning);
}

bool Balancer::_stopOrPauseRequested() {
    stdx::lock_guard<Latch> scopedLock(_mutex);
    return (_state != kRunning || _numPauseRequests > 0);
}

void Balancer::_beginRound(OperationContext* opCtx) {
    stdx::unique_lock<Latch> lock(_mutex);
    _inBalancerRound = true;
    _condVar.notify_all();
}

void Balancer::_endRound(OperationContext* opCtx, Milliseconds waitTimeout) {
    {
        stdx::lock_guard<Latch> lock(_mutex);
        _inBalancerRound = false;
        _numBalancerRounds++;
        _condVar.notify_all();
    }

    MONGO_IDLE_THREAD_BLOCK;
    _sleepFor(opCtx, waitTimeout);
}

void Balancer::_sleepFor(OperationContext* opCtx, Milliseconds waitTimeout) {
    stdx::unique_lock<Latch> lock(_mutex);
    _condVar.wait_for(lock, waitTimeout.toSystemDuration(), [&] { return _state != kRunning; });
}

bool Balancer::_checkOIDs(OperationContext* opCtx) {
    auto shardingContext = Grid::get(opCtx);

    const auto all = shardingContext->shardRegistry()->getAllShardIdsNoReload();

    // map of OID machine ID => shardId
    map<int, ShardId> oids;

    for (const ShardId& shardId : all) {
        if (_stopRequested()) {
            return false;
        }

        auto shardStatus = shardingContext->shardRegistry()->getShard(opCtx, shardId);
        if (!shardStatus.isOK()) {
            continue;
        }
        const auto s = shardStatus.getValue();

        auto result = uassertStatusOK(
            s->runCommandWithFixedRetryAttempts(opCtx,
                                                ReadPreferenceSetting{ReadPreference::PrimaryOnly},
                                                "admin",
                                                BSON("features" << 1),
                                                Seconds(30),
                                                Shard::RetryPolicy::kIdempotent));
        uassertStatusOK(result.commandStatus);
        BSONObj f = std::move(result.response);

        if (f["oidMachine"].isNumber()) {
            int x = f["oidMachine"].numberInt();
            if (oids.count(x) == 0) {
                oids[x] = shardId;
            } else {
                LOGV2(21868,
                      "error: 2 machines have {oidMachine} as oid machine piece: {firstShardId} "
                      "and {secondShardId}",
                      "Two machines have the same oidMachine value",
                      "oidMachine"_attr = x,
                      "firstShardId"_attr = shardId,
                      "secondShardId"_attr = oids[x]);

                result = uassertStatusOK(s->runCommandWithFixedRetryAttempts(
                    opCtx,
                    ReadPreferenceSetting{ReadPreference::PrimaryOnly},
                    "admin",
                    BSON("features" << 1 << "oidReset" << 1),
                    Seconds(30),
                    Shard::RetryPolicy::kIdempotent));
                uassertStatusOK(result.commandStatus);

                auto otherShardStatus = shardingContext->shardRegistry()->getShard(opCtx, oids[x]);
                if (otherShardStatus.isOK()) {
                    result = uassertStatusOK(
                        otherShardStatus.getValue()->runCommandWithFixedRetryAttempts(
                            opCtx,
                            ReadPreferenceSetting{ReadPreference::PrimaryOnly},
                            "admin",
                            BSON("features" << 1 << "oidReset" << 1),
                            Seconds(30),
                            Shard::RetryPolicy::kIdempotent));
                    uassertStatusOK(result.commandStatus);
                }

                return false;
            }
        } else {
            LOGV2(21869,
                  "warning: oidMachine not set on: {shard}",
                  "warning: oidMachine not set on shard",
                  "shard"_attr = s->toString());
        }
    }

    return true;
}

Status Balancer::_splitChunksIfNeeded(OperationContext* opCtx) {
    auto chunksToSplitStatus = _chunkSelectionPolicy->selectChunksToSplit(opCtx);
    if (!chunksToSplitStatus.isOK()) {
        return chunksToSplitStatus.getStatus();
    }

    for (const auto& splitInfo : chunksToSplitStatus.getValue()) {
        auto routingInfoStatus =
            Grid::get(opCtx)->catalogCache()->getShardedCollectionRoutingInfoWithRefresh(
                opCtx, splitInfo.nss);
        if (!routingInfoStatus.isOK()) {
            return routingInfoStatus.getStatus();
        }

        const auto& cm = routingInfoStatus.getValue();

        auto splitStatus =
            shardutil::splitChunkAtMultiplePoints(opCtx,
                                                  splitInfo.shardId,
                                                  splitInfo.nss,
                                                  cm.getShardKeyPattern(),
                                                  splitInfo.collectionVersion,
                                                  ChunkRange(splitInfo.minKey, splitInfo.maxKey),
                                                  splitInfo.splitKeys);
        if (!splitStatus.isOK()) {
            LOGV2_WARNING(21879,
                          "Failed to split chunk {splitInfo} {error}",
                          "Failed to split chunk",
                          "splitInfo"_attr = redact(splitInfo.toString()),
                          "error"_attr = redact(splitStatus.getStatus()));
        }
    }

    return Status::OK();
}

int Balancer::_moveChunks(OperationContext* opCtx,
                          const BalancerChunkSelectionPolicy::MigrateInfoVector& candidateChunks) {
    auto balancerConfig = Grid::get(opCtx)->getBalancerConfiguration();

    // If the balancer was disabled since we started this round, don't start new chunk moves
    if (_stopOrPauseRequested() || !balancerConfig->shouldBalance()) {
        LOGV2_DEBUG(21870, 1, "Skipping balancing round because balancer was stopped");
        return 0;
    }

    auto migrationStatuses =
        _migrationManager.executeMigrationsForAutoBalance(opCtx,
                                                          candidateChunks,
                                                          balancerConfig->getMaxChunkSizeBytes(),
                                                          balancerConfig->getSecondaryThrottle(),
                                                          balancerConfig->waitForDelete());

    int numChunksProcessed = 0;

    for (const auto& migrationStatusEntry : migrationStatuses) {
        const Status& status = migrationStatusEntry.second;
        if (status.isOK()) {
            numChunksProcessed++;
            continue;
        }

        const MigrationIdentifier& migrationId = migrationStatusEntry.first;

        const auto requestIt = std::find_if(candidateChunks.begin(),
                                            candidateChunks.end(),
                                            [&migrationId](const MigrateInfo& migrateInfo) {
                                                return migrateInfo.getName() == migrationId;
                                            });
        invariant(requestIt != candidateChunks.end());

        // ChunkTooBig is returned by the source shard during the cloning phase if the migration
        // manager finds that the chunk is larger than some calculated size, the source shard is
        // *not* in draining mode, and the 'forceJumbo' balancer setting is 'kDoNotForce'.
        // ExceededMemoryLimit is returned when the transfer mods queue surpasses 500MB regardless
        // of whether the source shard is in draining mode or the value if the 'froceJumbo' balancer
        // setting.
        if (status == ErrorCodes::ChunkTooBig || status == ErrorCodes::ExceededMemoryLimit) {
            numChunksProcessed++;

            LOGV2(21871,
                  "Migration {migrateInfo} failed with {error}, going to try splitting the chunk",
                  "Migration failed, going to try splitting the chunk",
                  "migrateInfo"_attr = redact(requestIt->toString()),
                  "error"_attr = redact(status));

            ShardingCatalogManager::get(opCtx)->splitOrMarkJumbo(
                opCtx, requestIt->nss, requestIt->minKey);
            continue;
        }

        if (status == ErrorCodes::IndexNotFound &&
            gFeatureFlagShardKeyIndexOptionalHashedSharding.isEnabled(
                serverGlobalParams.featureCompatibility)) {

            const auto cm = uassertStatusOK(
                Grid::get(opCtx)->catalogCache()->getCollectionRoutingInfoWithRefresh(
                    opCtx, requestIt->nss));

            if (cm.getShardKeyPattern().isHashedPattern()) {
                LOGV2(78252,
                      "Turning off balancing for hashed collection because migration failed due to "
                      "missing shardkey index",
                      "migrateInfo"_attr = redact(requestIt->toString()),
                      "error"_attr = redact(status),
                      "collection"_attr = requestIt->nss);

                // Write to config.collections to turn off the balancer.
                _disableBalancer(opCtx, requestIt->nss);
                continue;
            }
        }

        LOGV2(21872,
              "Migration {migrateInfo} failed with {error}",
              "Migration failed",
              "migrateInfo"_attr = redact(requestIt->toString()),
              "error"_attr = redact(status));
    }

    return numChunksProcessed;
}

void Balancer::notifyPersistedBalancerSettingsChanged() {
    stdx::unique_lock<Latch> lock(_mutex);
    _condVar.notify_all();
}

void Balancer::_disableBalancer(OperationContext* opCtx, NamespaceString nss) {
    const auto configShard = Grid::get(opCtx)->shardRegistry()->getConfigShard();

    BatchedCommandRequest updateRequest([&]() {
        write_ops::UpdateCommandRequest updateOp(CollectionType::ConfigNS);
        updateOp.setUpdates({[&] {
            write_ops::UpdateOpEntry entry;
            entry.setQ(BSON(CollectionType::kNssFieldName << nss.ns()));
            entry.setU(write_ops::UpdateModification::parseFromClassicUpdate(
                BSON("$set" << BSON("noBalance" << true))));
            entry.setMulti(false);
            entry.setUpsert(false);
            return entry;
        }()});
        return updateOp;
    }());

    updateRequest.setWriteConcern(ShardingCatalogClient::kMajorityWriteConcern.toBSON());

    auto response = configShard->runBatchWriteCommand(
        opCtx, Shard::kDefaultConfigCommandTimeout, updateRequest, Shard::RetryPolicy::kIdempotent);
    uassertStatusOK(response.toStatus());
}

Balancer::BalancerStatus Balancer::getBalancerStatusForNs(OperationContext* opCtx,
                                                          const NamespaceString& ns) {
    auto splitChunks = uassertStatusOK(_chunkSelectionPolicy->selectChunksToSplit(opCtx, ns));
    if (!splitChunks.empty()) {
        return {false, kBalancerPolicyStatusZoneViolation.toString()};
    }
    auto chunksToMove = uassertStatusOK(_chunkSelectionPolicy->selectChunksToMove(opCtx, ns));
    if (chunksToMove.empty()) {
        return {true, boost::none};
    }
    const auto& migrationInfo = chunksToMove.front();

    switch (migrationInfo.reason) {
        case MigrateInfo::drain:
            return {false, kBalancerPolicyStatusDraining.toString()};
        case MigrateInfo::zoneViolation:
            return {false, kBalancerPolicyStatusZoneViolation.toString()};
        case MigrateInfo::chunksImbalance:
            return {false, kBalancerPolicyStatusChunksImbalance.toString()};
    }

    return {true, boost::none};
}

}  // namespace mongo
