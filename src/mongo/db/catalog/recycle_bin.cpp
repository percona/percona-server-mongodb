/**
 *    Copyright (C) 2018-present MongoDB, Inc.
 */

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kStorage

#include "mongo/platform/basic.h"

#include "mongo/db/catalog/recycle_bin.h"

#include "mongo/db/catalog/collection_catalog.h"
#include "mongo/db/catalog/drop_collection.h"
#include "mongo/db/catalog/recycle_bin_parameters_gen.h"
#include "mongo/db/concurrency/d_concurrency.h"
#include "mongo/db/database_name.h"
#include "mongo/db/repl/replication_coordinator.h"
#include "mongo/db/s/collection_sharding_state.h"
#include "mongo/db/service_context.h"
#include "mongo/db/storage/storage_engine.h"
#include "mongo/logv2/log.h"
#include "mongo/logv2/redaction.h"
#include "mongo/util/time_support.h"

namespace mongo {
namespace recycle_bin {

namespace {

long long wallClockSeconds(OperationContext* opCtx) {
    return durationCount<Seconds>(
        opCtx->getServiceContext()->getFastClockSource()->now().toDurationSinceEpoch());
}

}  // namespace

bool shouldInterceptDropForRecycleBin(OperationContext* opCtx,
                                      const NamespaceString& nss,
                                      const Collection* collection,
                                      bool markFromMigrate,
                                      const repl::OpTime& dropOpTime) {
    if (!gCollectionRecycleBin.load()) {
        return false;
    }
    if (markFromMigrate || !dropOpTime.isNull()) {
        return false;
    }
    if (!opCtx->getServiceContext()->getStorageEngine()->supportsPendingDrops()) {
        return false;
    }
    if (!opCtx->writesAreReplicated()) {
        return false;
    }
    if (nss.isRecycleBinCollection() || nss.isDropPendingNamespace()) {
        return false;
    }
    if (nss.isAdminDB() || nss.isConfigDB() || nss.isLocalDB()) {
        return false;
    }
    if (nss.isSystem() || nss.isOplog()) {
        return false;
    }
    if (nss.isTimeseriesBucketsCollection()) {
        return false;
    }
    if (collection->getTimeseriesOptions()) {
        return false;
    }
    if (collection->getCollectionOptions().encryptedFieldConfig) {
        return false;
    }
    if (CollectionShardingState::acquire(opCtx, nss)->getCollectionDescription(opCtx).isSharded()) {
        return false;
    }
    return true;
}

StatusWith<NamespaceString> allocateUniqueRecycleNamespace(OperationContext* opCtx,
                                                           const NamespaceString& nss) {
    auto catalog = CollectionCatalog::get(opCtx);
    const long long secs = wallClockSeconds(opCtx);
    for (int attempt = 0; attempt < 8; ++attempt) {
        auto candidate = nss.makeRecycleBinNamespace(secs, UUID::gen());
        if (!catalog->lookupCollectionByNamespace(opCtx, candidate)) {
            return candidate;
        }
    }
    return Status(ErrorCodes::NamespaceExists,
                  "Could not allocate a unique recycle-bin namespace after several attempts");
}

void purgeExpiredCollections(OperationContext* opCtx) {
    if (!gCollectionRecycleBin.load()) {
        return;
    }
    const int retention = gCollectionRecycleBinRetentionSeconds.load();
    const long long nowSec = wallClockSeconds(opCtx);
    auto catalog = CollectionCatalog::get(opCtx);
    auto replCoord = repl::ReplicationCoordinator::get(opCtx);

    for (const auto& dbName : catalog->getAllDbNames()) {
        if (dbName == DatabaseName::kAdmin || dbName == DatabaseName::kConfig ||
            dbName == DatabaseName::kLocal) {
            continue;
        }

        std::vector<NamespaceString> toDrop;
        {
            Lock::DBLock dbLock(opCtx, dbName, MODE_S);
            for (const auto& nss : catalog->getAllCollectionNamesFromDb(opCtx, dbName)) {
                if (!nss.isRecycleBinCollection()) {
                    continue;
                }
                auto sw = nss.getRecycleBinDropWallSeconds();
                if (!sw.isOK()) {
                    continue;
                }
                if (nowSec < sw.getValue() + retention) {
                    continue;
                }
                if (!replCoord->canAcceptWritesFor(opCtx, nss)) {
                    continue;
                }
                toDrop.push_back(nss);
            }
        }

        for (const auto& nss : toDrop) {
            try {
                DropReply unused;
                uassertStatusOK(dropCollection(
                    opCtx,
                    nss,
                    &unused,
                    DropCollectionSystemCollectionMode::kDisallowSystemCollectionDrops,
                    false /* fromMigrate */));
            } catch (const DBException& ex) {
                LOGV2_WARNING(9876500,
                              "Recycle bin purge failed for namespace",
                              "namespace"_attr = nss,
                              "error"_attr = redact(ex.toStatus()));
            }
        }
    }
}

}  // namespace recycle_bin
}  // namespace mongo
