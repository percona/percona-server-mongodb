/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2026-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/db/recycle_bin/recycle_bin.h"

#include "mongo/db/client.h"
#include "mongo/db/namespace_string_util.h"
#include "mongo/db/recycle_bin/recycle_bin_gen.h"
#include "mongo/db/repl/replication_coordinator.h"
#include "mongo/db/replication_state_transition_lock_guard.h"
#include "mongo/db/shard_role/shard_catalog/collection_catalog.h"
#include "mongo/db/shard_role/shard_catalog/drop_collection.h"
#include "mongo/db/shard_role/shard_catalog/rename_collection.h"
#include "mongo/logv2/log.h"
#include "mongo/util/duration.h"
#include "mongo/util/periodic_runner.h"

#include <fmt/format.h>
#include <regex>

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kCommand

namespace mongo {

namespace {

constexpr Milliseconds kPurgeCheckInterval{Seconds{60}};

struct RecycleBinPurgerState {
    std::shared_ptr<PeriodicJobAnchor> anchor;
};

const auto recycleBinPurgerDecoration =
    ServiceContext::declareDecoration<RecycleBinPurgerState>();

bool isExcludedFromRecycleBin(const NamespaceString& nss) {
    return nss.isSystem() || nss.isLocalDB() || nss.isOnInternalDb() || nss.isOplog();
}

void purgeExpiredEntries(Client* client) {
    try {
        auto opCtx = client->makeOperationContext();

        if (!recycleBinEnabled.load()) {
            return;
        }

        auto replCoord = repl::ReplicationCoordinator::get(opCtx.get());
        if (replCoord) {
            repl::ReplicationStateTransitionLockGuard rstl(opCtx.get(), MODE_IX);
            if (!replCoord->canAcceptWritesForDatabase(
                    opCtx.get(), DatabaseName::kAdmin)) {
                return;
            }
        }

        auto now = opCtx->getServiceContext()->getFastClockSource()->now();
        auto nowSecs = durationCount<Seconds>(now.toDurationSinceEpoch());
        auto retentionSecs = recycleBinRetentionSeconds.load();

        // Collect expired entries first, then drop them in a separate pass
        // to avoid invalidating the catalog snapshot while iterating.
        std::vector<NamespaceString> toPurge;
        {
            auto catalog = CollectionCatalog::get(opCtx.get());
            auto allDbs = catalog->getAllDbNames();
            for (const auto& dbName : allDbs) {
                auto collections =
                    catalog->establishConsistentCollections(opCtx.get(), dbName);
                for (const auto& coll : collections) {
                    if (!coll->ns().isRecycleBinCollection()) {
                        continue;
                    }
                    auto parsed = parseRecycleBinNss(coll->ns());
                    if (!parsed) {
                        continue;
                    }
                    if (nowSecs - parsed->dropTimeSecs > retentionSecs) {
                        toPurge.push_back(coll->ns());
                    }
                }
            }
        }

        for (const auto& nss : toPurge) {
            LOGV2(9900001,
                  "Purging expired recycle bin entry",
                  "ns"_attr = nss);

            DropReply unusedReply;
            auto status = dropCollection(
                opCtx.get(),
                nss,
                &unusedReply,
                DropCollectionSystemCollectionMode::kAllowSystemCollectionDrops);
            if (!status.isOK()) {
                LOGV2_WARNING(9900002,
                              "Failed to purge recycle bin entry",
                              "ns"_attr = nss,
                              "error"_attr = status);
            }
        }
    } catch (const ExceptionFor<ErrorCategory::CancellationError>& ex) {
        LOGV2_DEBUG(9900003, 2, "Recycle bin purger canceled", "reason"_attr = ex.reason());
    } catch (const ExceptionFor<ErrorCategory::Interruption>& ex) {
        LOGV2_DEBUG(9900004, 2, "Recycle bin purger interrupted", "reason"_attr = ex.reason());
    } catch (const DBException& ex) {
        LOGV2_WARNING(
            9900005, "Recycle bin purger encountered an error", "error"_attr = ex.toStatus());
    }
}

}  // namespace

NamespaceString makeRecycleBinNss(const NamespaceString& originalNss,
                                  long long dropTimeSecs,
                                  const boost::optional<UUID>& collUuid) {
    std::string recycleBinColl;
    if (collUuid) {
        recycleBinColl = fmt::format("system.recycle_bin.{}.{}.{}",
                                     originalNss.coll(),
                                     dropTimeSecs,
                                     collUuid->toString().substr(0, 8));
    } else {
        recycleBinColl =
            fmt::format("system.recycle_bin.{}.{}", originalNss.coll(), dropTimeSecs);
    }

    return NamespaceStringUtil::deserialize(originalNss.dbName(), recycleBinColl);
}

boost::optional<RecycleBinEntryInfo> parseRecycleBinNss(const NamespaceString& nss) {
    auto collStr = nss.coll();
    if (!collStr.starts_with(kRecycleBinPrefix)) {
        return boost::none;
    }

    auto remainder = std::string(collStr.substr(kRecycleBinPrefix.size()));

    // Format with UUID suffix: <original_coll>.<timestamp>.<8-char hex uuid prefix>
    // Format without UUID:     <original_coll>.<timestamp>
    // Try UUID format first to avoid ambiguity when UUID prefix is all digits.
    static const std::regex kWithUuid(R"((.+)\.(\d+)\.[0-9a-f]{8})");
    static const std::regex kWithoutUuid(R"((.+)\.(\d+))");

    std::smatch match;
    if (!std::regex_match(remainder, match, kWithUuid) &&
        !std::regex_match(remainder, match, kWithoutUuid)) {
        return boost::none;
    }

    auto originalColl = match[1].str();
    long long timestamp = 0;
    try {
        timestamp = std::stoll(match[2].str());
    } catch (...) {
        return boost::none;
    }

    if (originalColl.empty() || timestamp <= 0) {
        return boost::none;
    }

    RecycleBinEntryInfo info;
    info.recycleBinNss = nss;
    info.originalCollection = originalColl;
    info.db = toStringForLogging(nss.dbName());
    info.dropTimeSecs = timestamp;
    return info;
}

bool recycleBinInterceptDrop(OperationContext* opCtx,
                             const NamespaceString& nss,
                             const boost::optional<UUID>& expectedUUID,
                             DropReply* reply) {
    if (!recycleBinEnabled.load()) {
        return false;
    }

    if (isExcludedFromRecycleBin(nss)) {
        return false;
    }

    auto catalog = CollectionCatalog::get(opCtx);
    auto coll = catalog->lookupCollectionByNamespace(opCtx, nss);
    if (!coll) {
        return false;
    }

    if (expectedUUID && coll->uuid() != *expectedUUID) {
        return false;
    }

    auto now = opCtx->getServiceContext()->getFastClockSource()->now();
    auto nowSecs = durationCount<Seconds>(now.toDurationSinceEpoch());

    auto targetNss = makeRecycleBinNss(nss, nowSecs);

    // Check if the target already exists; if so, add UUID suffix for uniqueness
    if (catalog->lookupCollectionByNamespace(opCtx, targetNss)) {
        targetNss = makeRecycleBinNss(nss, nowSecs, coll->uuid());
    }

    LOGV2(9900006,
          "Intercepting collection drop, moving to recycle bin",
          "source"_attr = nss,
          "target"_attr = targetNss);

    RenameCollectionOptions renameOpts;
    auto status = renameCollection(opCtx, nss, targetNss, renameOpts);
    if (!status.isOK()) {
        LOGV2_WARNING(9900007,
                      "Failed to move collection to recycle bin, falling back to real drop",
                      "ns"_attr = nss,
                      "error"_attr = status);
        return false;
    }

    reply->setNs(nss);
    reply->setInfo("collection moved to recycle bin"_sd);
    return true;
}

StatusWith<NamespaceString> recycleBinRestore(OperationContext* opCtx,
                                              const NamespaceString& recycleBinNss,
                                              const boost::optional<NamespaceString>& restoreAs) {
    auto parsed = parseRecycleBinNss(recycleBinNss);
    if (!parsed) {
        return Status(ErrorCodes::InvalidNamespace,
                      fmt::format("'{}' is not a valid recycle bin namespace",
                                  recycleBinNss.toStringForErrorMsg()));
    }

    NamespaceString targetNss;
    if (restoreAs) {
        targetNss = *restoreAs;
    } else {
        targetNss = NamespaceStringUtil::deserialize(recycleBinNss.dbName(),
                                                     parsed->originalCollection);
    }

    auto catalog = CollectionCatalog::get(opCtx);
    if (catalog->lookupCollectionByNamespace(opCtx, targetNss)) {
        return Status(ErrorCodes::NamespaceExists,
                      fmt::format("Cannot restore: namespace '{}' already exists",
                                  targetNss.toStringForErrorMsg()));
    }

    if (!catalog->lookupCollectionByNamespace(opCtx, recycleBinNss)) {
        return Status(ErrorCodes::NamespaceNotFound,
                      fmt::format("Recycle bin entry '{}' not found",
                                  recycleBinNss.toStringForErrorMsg()));
    }

    LOGV2(9900008,
          "Restoring collection from recycle bin",
          "source"_attr = recycleBinNss,
          "target"_attr = targetNss);

    RenameCollectionOptions renameOpts;
    auto status = renameCollection(opCtx, recycleBinNss, targetNss, renameOpts);
    if (!status.isOK()) {
        return status;
    }
    return targetNss;
}

std::vector<RecycleBinEntryInfo> recycleBinList(OperationContext* opCtx,
                                                const DatabaseName& dbName) {
    std::vector<RecycleBinEntryInfo> result;
    auto catalog = CollectionCatalog::get(opCtx);

    std::vector<DatabaseName> dbNames;
    if (dbName.isEmpty()) {
        dbNames = catalog->getAllDbNames();
    } else {
        dbNames.push_back(dbName);
    }

    for (const auto& db : dbNames) {
        auto collections = catalog->establishConsistentCollections(opCtx, db);
        for (const auto& coll : collections) {
            if (!coll->ns().isRecycleBinCollection()) {
                continue;
            }
            auto parsed = parseRecycleBinNss(coll->ns());
            if (parsed) {
                result.push_back(std::move(*parsed));
            }
        }
    }

    return result;
}

void startRecycleBinPurger(ServiceContext* serviceContext) {
    auto periodicRunner = serviceContext->getPeriodicRunner();
    if (!periodicRunner) {
        LOGV2_WARNING(9900009,
                      "Cannot start recycle bin purger: periodic runner is not available");
        return;
    }

    PeriodicRunner::PeriodicJob job(
        "recycleBinPurger", purgeExpiredEntries, kPurgeCheckInterval, true);

    auto& state = recycleBinPurgerDecoration(serviceContext);
    state.anchor =
        std::make_shared<PeriodicJobAnchor>(periodicRunner->makeJob(std::move(job)));
    state.anchor->start();
}

void shutdownRecycleBinPurger(ServiceContext* serviceContext) {
    auto& state = recycleBinPurgerDecoration(serviceContext);
    if (state.anchor) {
        state.anchor->stop();
    }
}

}  // namespace mongo
