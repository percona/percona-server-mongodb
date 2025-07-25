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


#include "mongo/db/storage/storage_engine_impl.h"

#include <absl/container/node_hash_map.h>
#include <absl/meta/type_traits.h>
#include <algorithm>
#include <boost/container/vector.hpp>
#include <boost/move/utility_core.hpp>
#include <map>
#include <mutex>

#include <boost/none.hpp>
#include <boost/optional/optional.hpp>

#include "mongo/base/error_codes.h"
#include "mongo/bson/bsonelement.h"
#include "mongo/db/admission/execution_admission_context.h"
#include "mongo/db/audit.h"
#include "mongo/db/catalog/catalog_control.h"
#include "mongo/db/catalog/clustered_collection_options_gen.h"
#include "mongo/db/catalog/clustered_collection_util.h"
#include "mongo/db/catalog/collection.h"
#include "mongo/db/catalog/collection_catalog.h"
#include "mongo/db/catalog/collection_catalog_helper.h"
#include "mongo/db/catalog/collection_options.h"
#include "mongo/db/catalog/historical_catalogid_tracker.h"
#include "mongo/db/catalog/index_builds.h"
#include "mongo/db/catalog/index_catalog.h"
#include "mongo/db/catalog/index_catalog_entry.h"
#include "mongo/db/catalog_raii.h"
#include "mongo/db/client.h"
#include "mongo/db/concurrency/d_concurrency.h"
#include "mongo/db/concurrency/lock_manager_defs.h"
#include "mongo/db/global_settings.h"
#include "mongo/db/index/multikey_paths.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/repl/repl_settings.h"
#include "mongo/db/resumable_index_builds_gen.h"
#include "mongo/db/storage/bson_collection_catalog_entry.h"
#include "mongo/db/storage/deferred_drop_record_store.h"
#include "mongo/db/storage/durable_catalog.h"
#include "mongo/db/storage/durable_catalog_entry.h"
#include "mongo/db/storage/durable_history_pin.h"
#include "mongo/db/storage/kv/kv_engine.h"
#include "mongo/db/storage/record_data.h"
#include "mongo/db/storage/storage_repair_observer.h"
#include "mongo/db/storage/storage_util.h"
#include "mongo/db/storage/write_unit_of_work.h"
#include "mongo/db/transaction_resources.h"
#include "mongo/idl/idl_parser.h"
#include "mongo/logv2/log.h"
#include "mongo/logv2/log_attr.h"
#include "mongo/logv2/log_component.h"
#include "mongo/logv2/log_severity.h"
#include "mongo/platform/compiler.h"
#include "mongo/stdx/unordered_set.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/database_name_util.h"
#include "mongo/util/duration.h"
#include "mongo/util/fail_point.h"
#include "mongo/util/str.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kStorage


#define LOGV2_FOR_RECOVERY(ID, DLEVEL, MESSAGE, ...) \
    LOGV2_DEBUG_OPTIONS(ID, DLEVEL, {logv2::LogComponent::kStorageRecovery}, MESSAGE, ##__VA_ARGS__)

namespace mongo {

using std::string;
using std::vector;

MONGO_FAIL_POINT_DEFINE(failToParseResumeIndexInfo);
MONGO_FAIL_POINT_DEFINE(pauseTimestampMonitor);
MONGO_FAIL_POINT_DEFINE(setMinVisibleForAllCollectionsToOldestOnStartup);

namespace {
const std::string kCatalogInfo = DatabaseName::kMdbCatalog.db(omitTenant).toString();
const NamespaceString kCatalogInfoNamespace = NamespaceString(DatabaseName::kMdbCatalog);
const auto kCatalogLogLevel = logv2::LogSeverity::Debug(2);
}  // namespace

Status StorageEngineImpl::hotBackup(OperationContext* opCtx, const std::string& path) {
    return _engine->hotBackup(opCtx, path);
}

Status StorageEngineImpl::hotBackupTar(OperationContext* opCtx, const std::string& path) {
    return _engine->hotBackupTar(opCtx, path);
}

Status StorageEngineImpl::hotBackup(OperationContext* opCtx, const percona::S3BackupParameters& s3params) {
    return _engine->hotBackup(opCtx, s3params);
}

void StorageEngineImpl::keydbDropDatabase(const DatabaseName& dbName) {
    _engine->keydbDropDatabase(dbName);
}

StorageEngineImpl::StorageEngineImpl(OperationContext* opCtx,
                                     std::unique_ptr<KVEngine> engine,
                                     StorageEngineOptions options)
    : _engine(std::move(engine)),
      _options(std::move(options)),
      _dropPendingIdentReaper(_engine.get()),
      _minOfCheckpointAndOldestTimestampListener(
          TimestampMonitor::TimestampType::kMinOfCheckpointAndOldest,
          [this](OperationContext* opCtx, Timestamp timestamp) {
              _onMinOfCheckpointAndOldestTimestampChanged(opCtx, timestamp);
          }),
      _collectionCatalogCleanupTimestampListener(
          TimestampMonitor::TimestampType::kOldest,
          [](OperationContext* opCtx, Timestamp timestamp) {
              Lock::GlobalLock lk{
                  opCtx,
                  MODE_IX,
                  Date_t::max(),
                  Lock::InterruptBehavior::kThrow,
                  Lock::GlobalLockSkipOptions{.skipFlowControlTicket = true, .skipRSTLLock = true}};

              if (CollectionCatalog::latest(opCtx)->catalogIdTracker().dirty(timestamp)) {
                  CollectionCatalog::write(opCtx, [timestamp](CollectionCatalog& catalog) {
                      catalog.catalogIdTracker().cleanup(timestamp);
                  });
              }
          }),
      _supportsCappedCollections(_engine->supportsCappedCollections()) {
    uassert(28601,
            "Storage engine does not support --directoryperdb",
            !(_options.directoryPerDB && !_engine->supportsDirectoryPerDB()));

    // Replace the noop recovery unit for the startup operation context now that the storage engine
    // has been initialized. This is needed because at the time of startup, when the operation
    // context gets created, the storage engine initialization has not yet begun and so it gets
    // assigned a noop recovery unit. See the StorageClientObserver class.
    invariant(shard_role_details::getRecoveryUnit(opCtx)->isNoop());
    shard_role_details::setRecoveryUnit(opCtx,
                                        std::unique_ptr<RecoveryUnit>(_engine->newRecoveryUnit()),
                                        WriteUnitOfWork::RecoveryUnitState::kNotInUnitOfWork);

    // If we are loading the catalog after an unclean shutdown, it's possible that there are
    // collections in the catalog that are unknown to the storage engine. We should attempt to
    // recover these orphaned idents.
    // Allowing locking in write mode as reinitializeStorageEngine will be called while holding the
    // global lock in exclusive mode.
    invariant(!shard_role_details::getLocker(opCtx)->isLocked() ||
              shard_role_details::getLocker(opCtx)->isW());
    Lock::GlobalWrite globalLk(opCtx);
    loadCatalog(opCtx,
                _engine->getRecoveryTimestamp(),
                _options.lockFileCreatedByUncleanShutdown ? LastShutdownState::kUnclean
                                                          : LastShutdownState::kClean);
}

void StorageEngineImpl::loadCatalog(OperationContext* opCtx,
                                    boost::optional<Timestamp> stableTs,
                                    LastShutdownState lastShutdownState) {
    bool catalogExists = _engine->hasIdent(opCtx, kCatalogInfo);
    if (_options.forRepair && catalogExists) {
        auto repairObserver = StorageRepairObserver::get(getGlobalServiceContext());
        invariant(repairObserver->isIncomplete());

        LOGV2(22246, "Repairing catalog metadata");
        Status status = _engine->repairIdent(opCtx, kCatalogInfo);

        if (status.code() == ErrorCodes::DataModifiedByRepair) {
            LOGV2_WARNING(22264, "Catalog data modified by repair", "error"_attr = status);
            repairObserver->invalidatingModification(str::stream() << "DurableCatalog repaired: "
                                                                   << status.reason());
        } else {
            fassertNoTrace(50926, status);
        }
    }

    if (!catalogExists) {
        WriteUnitOfWork uow(opCtx);

        auto status = _engine->createRecordStore(
            opCtx, kCatalogInfoNamespace, kCatalogInfo, CollectionOptions());

        // BadValue is usually caused by invalid configuration string.
        // We still fassert() but without a stack trace.
        if (status.code() == ErrorCodes::BadValue) {
            fassertFailedNoTrace(28562);
        }
        fassert(28520, status);
        uow.commit();
    }

    _catalogRecordStore =
        _engine->getRecordStore(opCtx, kCatalogInfoNamespace, kCatalogInfo, CollectionOptions());
    if (shouldLog(::mongo::logv2::LogComponent::kStorageRecovery, kCatalogLogLevel)) {
        LOGV2_FOR_RECOVERY(4615631, kCatalogLogLevel.toInt(), "loadCatalog:");
        _dumpCatalog(opCtx);
    }

    _catalog.reset(new DurableCatalog(
        _catalogRecordStore.get(), _options.directoryPerDB, _options.directoryForIndexes, this));
    _catalog->init(opCtx);

    std::vector<std::string> identsKnownToStorageEngine = _engine->getAllIdents(opCtx);
    std::sort(identsKnownToStorageEngine.begin(), identsKnownToStorageEngine.end());

    std::vector<DurableCatalog::EntryIdentifier> catalogEntries =
        _catalog->getAllCatalogEntries(opCtx);

    // Perform a read on the catalog at the `oldestTimestamp` and record the record stores (via
    // their catalogId) that existed.
    std::set<RecordId> existedAtOldestTs;
    if (!_engine->getOldestTimestamp().isNull()) {
        ReadSourceScope snapshotScope(
            opCtx, RecoveryUnit::ReadSource::kProvided, _engine->getOldestTimestamp());
        auto entriesAtOldest = _catalog->getAllCatalogEntries(opCtx);
        LOGV2_FOR_RECOVERY(5380110,
                           kCatalogLogLevel.toInt(),
                           "Catalog entries at the oldest timestamp",
                           "oldestTimestamp"_attr = _engine->getOldestTimestamp());
        for (const auto& entry : entriesAtOldest) {
            existedAtOldestTs.insert(entry.catalogId);
            LOGV2_FOR_RECOVERY(5380109,
                               kCatalogLogLevel.toInt(),
                               "Historical entry",
                               "catalogId"_attr = entry.catalogId,
                               "ident"_attr = entry.ident,
                               logAttrs(entry.nss));
        }
    }

    if (_options.forRepair) {
        // It's possible that there are collection files on disk that are unknown to the catalog. In
        // a repair context, if we can't find an ident in the catalog, we generate a catalog entry
        // 'local.orphan.xxxxx' for it. However, in a nonrepair context, the orphaned idents
        // will be dropped in reconcileCatalogAndIdents().
        for (const auto& ident : identsKnownToStorageEngine) {
            if (DurableCatalog::isCollectionIdent(ident)) {
                bool isOrphan = !std::any_of(catalogEntries.begin(),
                                             catalogEntries.end(),
                                             [this, &ident](DurableCatalog::EntryIdentifier entry) {
                                                 return entry.ident == ident;
                                             });
                if (isOrphan) {
                    // If the catalog does not have information about this
                    // collection, we create an new entry for it.
                    WriteUnitOfWork wuow(opCtx);

                    auto keyFormat = _engine->getKeyFormat(opCtx, ident);
                    bool isClustered = keyFormat == KeyFormat::String;
                    CollectionOptions optionsWithUUID;
                    optionsWithUUID.uuid.emplace(UUID::gen());
                    if (isClustered) {
                        optionsWithUUID.clusteredIndex =
                            clustered_util::makeDefaultClusteredIdIndex();
                    }

                    StatusWith<std::string> statusWithNs =
                        _catalog->newOrphanedIdent(opCtx, ident, optionsWithUUID);

                    if (statusWithNs.isOK()) {
                        wuow.commit();
                        auto orphanCollNs = statusWithNs.getValue();
                        LOGV2(22247,
                              "Successfully created an entry in the catalog for orphaned "
                              "collection",
                              "namespace"_attr = orphanCollNs,
                              "options"_attr = optionsWithUUID);

                        if (!isClustered) {
                            // The _id index is already implicitly created on collections clustered
                            // by _id.
                            LOGV2_WARNING(22265,
                                          "Collection does not have an _id index. Please manually "
                                          "build the index",
                                          "namespace"_attr = orphanCollNs);
                        }
                        StorageRepairObserver::get(getGlobalServiceContext())
                            ->benignModification(str::stream() << "Orphan collection created: "
                                                               << statusWithNs.getValue());

                    } else {
                        // Log an error message if we cannot create the entry.
                        // reconcileCatalogAndIdents() will later drop this ident.
                        LOGV2_ERROR(
                            22268,
                            "Cannot create an entry in the catalog for orphaned ident. Restarting "
                            "the server will remove this ident",
                            "ident"_attr = ident,
                            "error"_attr = statusWithNs.getStatus());
                    }
                }
            }
        }
    }

    bool setMinVisibleToOldestFailpointSet = false;
    if (MONGO_unlikely(setMinVisibleForAllCollectionsToOldestOnStartup.shouldFail())) {
        // Failpoint is intended to apply to all collections. Additionally, we want to leverage
        // nTimes to execute the failpoint for a single 'loadCatalog' call.
        LOGV2(9106700, "setMinVisibleForAllCollectionsToOldestOnStartup failpoint is set");
        setMinVisibleToOldestFailpointSet = true;
    }

    const auto loadingFromUncleanShutdownOrRepair =
        lastShutdownState == LastShutdownState::kUnclean || _options.forRepair;
    // Use the stable timestamp as minValid. We know for a fact that the collection exist at
    // this point and is in sync. If we use an earlier timestamp than replication rollback we
    // may be out-of-order for the collection catalog managing this namespace.
    const Timestamp minValidTs = stableTs ? *stableTs : Timestamp::min();
    CollectionCatalog::write(opCtx, [&minValidTs](CollectionCatalog& catalog) {
        // Let the CollectionCatalog know that we are maintaining timestamps from minValidTs
        catalog.catalogIdTracker().rollback(minValidTs);
    });
    for (DurableCatalog::EntryIdentifier entry : catalogEntries) {
        if (_options.forRestore) {
            // When restoring a subset of user collections from a backup, the collections not
            // restored are in the catalog but are unknown to the storage engine. The catalog
            // entries for these collections will be removed.
            const auto collectionIdent = entry.ident;
            bool restoredIdent = std::binary_search(identsKnownToStorageEngine.begin(),
                                                    identsKnownToStorageEngine.end(),
                                                    collectionIdent);

            if (!restoredIdent) {
                LOGV2(6260800,
                      "Removing catalog entry for collection not restored",
                      logAttrs(entry.nss),
                      "ident"_attr = collectionIdent);

                WriteUnitOfWork wuow(opCtx);
                fassert(6260801, _catalog->_removeEntry(opCtx, entry.catalogId));
                wuow.commit();

                continue;
            }

            // A collection being restored needs to also restore all of its indexes.
            _checkForIndexFiles(opCtx, entry, identsKnownToStorageEngine);
        }

        if (loadingFromUncleanShutdownOrRepair) {
            // If we are loading the catalog after an unclean shutdown or during repair, it's
            // possible that there are collections in the catalog that are unknown to the storage
            // engine. If we can't find a table in the list of storage engine idents, either
            // attempt to recover the ident or drop it.
            const auto collectionIdent = entry.ident;
            bool orphan = !std::binary_search(identsKnownToStorageEngine.begin(),
                                              identsKnownToStorageEngine.end(),
                                              collectionIdent);
            // If the storage engine is missing a collection and is unable to create a new record
            // store, drop it from the catalog and skip initializing it by continuing past the
            // following logic.
            if (orphan) {
                auto status =
                    _recoverOrphanedCollection(opCtx, entry.catalogId, entry.nss, collectionIdent);
                if (!status.isOK()) {
                    LOGV2_WARNING(22266,
                                  "Failed to recover orphaned data file for collection",
                                  logAttrs(entry.nss),
                                  "error"_attr = status);
                    WriteUnitOfWork wuow(opCtx);
                    fassert(50716, _catalog->_removeEntry(opCtx, entry.catalogId));

                    if (_options.forRepair) {
                        StorageRepairObserver::get(getGlobalServiceContext())
                            ->invalidatingModification(
                                str::stream() << "Collection " << entry.nss.toStringForErrorMsg()
                                              << " dropped: " << status.reason());
                    }
                    wuow.commit();
                    continue;
                }
            }
        }

        if (!entry.nss.isReplicated() &&
            !std::binary_search(identsKnownToStorageEngine.begin(),
                                identsKnownToStorageEngine.end(),
                                entry.ident)) {
            // All collection drops are non-transactional and unreplicated collections are dropped
            // immediately as they do not use two-phase drops. It's possible to run into a situation
            // where there are collections in the catalog that are unknown to the storage engine
            // after restoring from backed up data files. See SERVER-55552.
            WriteUnitOfWork wuow(opCtx);
            fassert(5555200, _catalog->_removeEntry(opCtx, entry.catalogId));
            wuow.commit();

            LOGV2_INFO(5555201,
                       "Removed unknown unreplicated collection from the catalog",
                       "catalogId"_attr = entry.catalogId,
                       logAttrs(entry.nss),
                       "ident"_attr = entry.ident);
            continue;
        }

        // If there's no recovery timestamp, every collection is available.
        auto collectionMinValidTs = minValidTs;
        if (MONGO_unlikely(stableTs && setMinVisibleToOldestFailpointSet)) {
            // This failpoint is useful for tests which want to exercise atClusterTime reads across
            // server starts (e.g. resharding). It is only safe for tests which can guarantee the
            // collection always exists for the atClusterTime value(s) and have not changed (i.e. no
            // DDL operations have run on them).
            //
            // Despite its name, the setMinVisibleForAllCollectionsToOldestOnStartup failpoint
            // controls the minValidTs in MongoDB Server versions with a point-in-time
            // CollectionCatalog but had controlled the minVisibleTs in older MongoDB Server
            // versions. We haven't renamed it to avoid issues in multiversion testing.
            auto shouldSetMinVisibleToOldest = [&]() {
                // We only do this for collections that existed at the oldest timestamp or after
                // startup when we aren't sure if it existed or not.
                const auto catalog = CollectionCatalog::latest(opCtx);
                const auto& tracker = catalog->catalogIdTracker();
                auto oldestTs = _engine->getOldestTimestamp();
                auto lookup = tracker.lookup(entry.nss, oldestTs);
                return lookup.result !=
                    HistoricalCatalogIdTracker::LookupResult::Existence::kNotExists;
            }();

            if (shouldSetMinVisibleToOldest) {
                auto oldestTs = _engine->getOldestTimestamp();
                if (collectionMinValidTs > oldestTs)
                    collectionMinValidTs = oldestTs;
            }
        }

        _initCollection(
            opCtx, entry.catalogId, entry.nss, _options.forRepair, collectionMinValidTs);

        if (entry.nss.isOrphanCollection()) {
            LOGV2(22248, "Orphaned collection found", logAttrs(entry.nss));
        }
    }

    shard_role_details::getRecoveryUnit(opCtx)->abandonSnapshot();
}

void StorageEngineImpl::_initCollection(OperationContext* opCtx,
                                        RecordId catalogId,
                                        const NamespaceString& nss,
                                        bool forRepair,
                                        Timestamp minValidTs) {
    const auto catalogEntry = _catalog->getParsedCatalogEntry(opCtx, catalogId);
    const auto md = catalogEntry->metadata;
    uassert(ErrorCodes::MustDowngrade,
            str::stream() << "Collection does not have UUID in KVCatalog. Collection: "
                          << nss.toStringForErrorMsg(),
            md->options.uuid);

    auto ident = _catalog->getEntry(catalogId).ident;

    std::unique_ptr<RecordStore> rs;
    if (forRepair) {
        // Using a NULL rs since we don't want to open this record store before it has been
        // repaired. This also ensures that if we try to use it, it will blow up.
        rs = nullptr;
    } else {
        rs = _engine->getRecordStore(opCtx, nss, ident, md->options);
        invariant(rs);
    }

    auto collectionFactory = Collection::Factory::get(getGlobalServiceContext());
    auto collection = collectionFactory->make(opCtx, nss, catalogId, md, std::move(rs));

    CollectionCatalog::write(opCtx, [&](CollectionCatalog& catalog) {
        catalog.registerCollection(opCtx, std::move(collection), /*commitTime*/ minValidTs);
    });
}

void StorageEngineImpl::closeCatalog(OperationContext* opCtx) {
    dassert(shard_role_details::getLocker(opCtx)->isLocked());
    if (shouldLog(::mongo::logv2::LogComponent::kStorageRecovery, kCatalogLogLevel)) {
        LOGV2_FOR_RECOVERY(4615632, kCatalogLogLevel.toInt(), "closeCatalog:");
        _dumpCatalog(opCtx);
    }

    CollectionCatalog::write(opCtx, [opCtx](CollectionCatalog& catalog) {
        catalog.deregisterAllCollectionsAndViews(opCtx->getServiceContext());
    });

    _catalog.reset();
    _catalogRecordStore.reset();
}

Status StorageEngineImpl::_recoverOrphanedCollection(OperationContext* opCtx,
                                                     RecordId catalogId,
                                                     const NamespaceString& collectionName,
                                                     StringData collectionIdent) {
    if (!_options.forRepair) {
        return {ErrorCodes::IllegalOperation, "Orphan recovery only supported in repair"};
    }
    LOGV2(22249,
          "Storage engine is missing collection from its metadata. Attempting to locate and "
          "recover the data",
          logAttrs(collectionName),
          "ident"_attr = collectionIdent);

    WriteUnitOfWork wuow(opCtx);
    const auto catalogEntry = _catalog->getParsedCatalogEntry(opCtx, catalogId);
    const auto md = catalogEntry->metadata;
    Status status =
        _engine->recoverOrphanedIdent(opCtx, collectionName, collectionIdent, md->options);

    bool dataModified = status.code() == ErrorCodes::DataModifiedByRepair;
    if (!status.isOK() && !dataModified) {
        return status;
    }
    if (dataModified) {
        StorageRepairObserver::get(getGlobalServiceContext())
            ->invalidatingModification(str::stream()
                                       << "Collection " << collectionName.toStringForErrorMsg()
                                       << " recovered: " << status.reason());
    }
    wuow.commit();
    return Status::OK();
}

void StorageEngineImpl::_checkForIndexFiles(
    OperationContext* opCtx,
    const DurableCatalog::EntryIdentifier& entry,
    std::vector<std::string>& identsKnownToStorageEngine) const {
    std::vector<std::string> indexIdents = _catalog->getIndexIdents(opCtx, entry.catalogId);
    for (const std::string& indexIdent : indexIdents) {
        bool restoredIndexIdent = std::binary_search(
            identsKnownToStorageEngine.begin(), identsKnownToStorageEngine.end(), indexIdent);

        if (restoredIndexIdent) {
            continue;
        }

        LOGV2_FATAL_NOTRACE(6261000,
                            "Collection is missing an index file",
                            logAttrs(entry.nss),
                            "collectionIdent"_attr = entry.ident,
                            "missingIndexIdent"_attr = indexIdent);
    }
}

bool StorageEngineImpl::_handleInternalIdent(OperationContext* opCtx,
                                             const std::string& ident,
                                             LastShutdownState lastShutdownState,
                                             ReconcileResult* reconcileResult,
                                             std::set<std::string>* internalIdentsToKeep,
                                             std::set<std::string>* allInternalIdents) {
    if (!DurableCatalog::isInternalIdent(ident)) {
        return false;
    }

    allInternalIdents->insert(ident);

    // When starting up after an unclean shutdown, we do not attempt to recover any state from the
    // internal idents. Thus, we drop them in this case.
    if (lastShutdownState == LastShutdownState::kUnclean) {
        return true;
    }

    if (!DurableCatalog::isResumableIndexBuildIdent(ident)) {
        return false;
    }

    // When starting up after a clean shutdown and resumable index builds are supported, find the
    // internal idents that contain the relevant information to resume each index build and recover
    // the state.
    auto rs = _engine->getRecordStore(opCtx, NamespaceString::kEmpty, ident, CollectionOptions());

    auto cursor = rs->getCursor(opCtx);
    auto record = cursor->next();
    if (record) {
        auto doc = record.value().data.toBson();

        // Parse the documents here so that we can restart the build if the document doesn't
        // contain all the necessary information to be able to resume building the index.
        ResumeIndexInfo resumeInfo;
        try {
            if (MONGO_unlikely(failToParseResumeIndexInfo.shouldFail())) {
                uasserted(ErrorCodes::FailPointEnabled,
                          "failToParseResumeIndexInfo fail point is enabled");
            }

            resumeInfo = ResumeIndexInfo::parse(IDLParserContext("ResumeIndexInfo"), doc);
        } catch (const DBException& e) {
            LOGV2(4916300, "Failed to parse resumable index info", "error"_attr = e.toStatus());

            // Ignore the error so that we can restart the index build instead of resume it. We
            // should drop the internal ident if we failed to parse.
            return true;
        }

        LOGV2(4916301,
              "Found unfinished index build to resume",
              "buildUUID"_attr = resumeInfo.getBuildUUID(),
              "collectionUUID"_attr = resumeInfo.getCollectionUUID(),
              "phase"_attr = IndexBuildPhase_serializer(resumeInfo.getPhase()));

        // Keep the tables that are needed to rebuild this index.
        // Note: the table that stores the rebuild metadata itself (i.e. |ident|) isn't kept.
        for (const mongo::IndexStateInfo& idx : resumeInfo.getIndexes()) {
            internalIdentsToKeep->insert(idx.getSideWritesTable().toString());
            if (idx.getDuplicateKeyTrackerTable()) {
                internalIdentsToKeep->insert(idx.getDuplicateKeyTrackerTable()->toString());
            }
            if (idx.getSkippedRecordTrackerTable()) {
                internalIdentsToKeep->insert(idx.getSkippedRecordTrackerTable()->toString());
            }
        }

        reconcileResult->indexBuildsToResume.push_back(std::move(resumeInfo));

        return true;
    }
    return false;
}

/**
 * This method reconciles differences between idents the KVEngine is aware of and the
 * DurableCatalog. There are three differences to consider:
 *
 * First, a KVEngine may know of an ident that the DurableCatalog does not. This method will drop
 * the ident from the KVEngine.
 *
 * Second, a DurableCatalog may have a collection ident that the KVEngine does not. This is an
 * illegal state and this method fasserts.
 *
 * Third, a DurableCatalog may have an index ident that the KVEngine does not. This method will
 * rebuild the index.
 */
StatusWith<StorageEngine::ReconcileResult> StorageEngineImpl::reconcileCatalogAndIdents(
    OperationContext* opCtx, Timestamp stableTs, LastShutdownState lastShutdownState) {
    // Gather all tables known to the storage engine and drop those that aren't cross-referenced
    // in the _mdb_catalog. This can happen for two reasons.
    //
    // First, collection creation and deletion happen in two steps. First the storage engine
    // creates/deletes the table, followed by the change to the _mdb_catalog. It's not assumed a
    // storage engine can make these steps atomic.
    //
    // Second, a replica set node in 3.6+ on supported storage engines will only persist "stable"
    // data to disk. That is data which replication guarantees won't be rolled back. The
    // _mdb_catalog will reflect the "stable" set of collections/indexes. However, it's not
    // expected for a storage engine's ability to persist stable data to extend to "stable
    // tables".
    std::set<std::string> engineIdents;
    {
        std::vector<std::string> vec = _engine->getAllIdents(opCtx);
        engineIdents.insert(vec.begin(), vec.end());
        engineIdents.erase(kCatalogInfo);
    }

    LOGV2_FOR_RECOVERY(4615633, 2, "Reconciling collection and index idents.");
    std::set<std::string> catalogIdents;
    {
        std::vector<std::string> vec = _catalog->getAllIdents(opCtx);
        catalogIdents.insert(vec.begin(), vec.end());
    }
    std::set<std::string> internalIdentsToKeep;
    std::set<std::string> allInternalIdents;

    auto dropPendingIdents = _dropPendingIdentReaper.getAllIdentNames();

    // Drop all idents in the storage engine that are not known to the catalog. This can happen in
    // the case of a collection or index creation being rolled back.
    StorageEngine::ReconcileResult reconcileResult;
    for (const auto& it : engineIdents) {
        if (catalogIdents.find(it) != catalogIdents.end()) {
            continue;
        }

        if (_handleInternalIdent(opCtx,
                                 it,
                                 lastShutdownState,
                                 &reconcileResult,
                                 &internalIdentsToKeep,
                                 &allInternalIdents)) {
            continue;
        }

        if (!DurableCatalog::isUserDataIdent(it)) {
            continue;
        }

        // In repair context, any orphaned collection idents from the engine should already be
        // recovered in the catalog in loadCatalog().
        invariant(!(DurableCatalog::isCollectionIdent(it) && _options.forRepair));

        // Leave drop-pending idents alone.
        // These idents have to be retained as long as the corresponding drops are not part of a
        // checkpoint.
        if (dropPendingIdents.find(it) != dropPendingIdents.cend()) {
            LOGV2(22250,
                  "Not removing ident for uncheckpointed collection or index drop",
                  "ident"_attr = it);
            continue;
        }

        const auto& toRemove = it;
        const Timestamp identDropTs = stableTs;
        LOGV2(22251, "Dropping unknown ident", "ident"_attr = toRemove, "ts"_attr = identDropTs);
        if (!identDropTs.isNull()) {
            addDropPendingIdent(identDropTs, std::make_shared<Ident>(toRemove), /*onDrop=*/nullptr);
        } else {
            WriteUnitOfWork wuow(opCtx);
            Status status =
                _engine->dropIdent(shard_role_details::getRecoveryUnit(opCtx), toRemove);
            if (!status.isOK()) {
                // A concurrent operation, such as a checkpoint could be holding an open data handle
                // on the ident. Handoff the ident drop to the ident reaper to retry later.
                addDropPendingIdent(
                    identDropTs, std::make_shared<Ident>(toRemove), /*onDrop=*/nullptr);
            }
            wuow.commit();
        }
    }

    // Scan all collections in the catalog and make sure their ident is known to the storage
    // engine. An omission here is fatal. A missing ident could mean a collection drop was rolled
    // back. Note that startup already attempts to open tables; this should only catch errors in
    // other contexts such as `recoverToStableTimestamp`.
    std::vector<DurableCatalog::EntryIdentifier> catalogEntries =
        _catalog->getAllCatalogEntries(opCtx);
    if (!_options.forRepair) {
        for (const DurableCatalog::EntryIdentifier& entry : catalogEntries) {
            if (engineIdents.find(entry.ident) == engineIdents.end()) {
                return {ErrorCodes::UnrecoverableRollbackError,
                        str::stream()
                            << "Expected collection does not exist. Collection: "
                            << entry.nss.toStringForErrorMsg() << " Ident: " << entry.ident};
            }
        }
    }

    // Scan all indexes and return those in the catalog where the storage engine does not have the
    // corresponding ident. The caller is expected to rebuild these indexes.
    //
    // Also, remove unfinished builds except those that were background index builds started on a
    // secondary.
    for (const DurableCatalog::EntryIdentifier& entry : catalogEntries) {
        const auto catalogEntry = _catalog->getParsedCatalogEntry(opCtx, entry.catalogId);
        auto md = catalogEntry->metadata;

        // Batch up the indexes to remove them from `metaData` outside of the iterator.
        std::vector<std::string> indexesToDrop;
        for (const auto& indexMetaData : md->indexes) {
            auto indexName = indexMetaData.nameStringData();
            auto indexIdent = _catalog->getIndexIdent(opCtx, entry.catalogId, indexName);

            // Warn in case of incorrect "multikeyPath" information in catalog documents. This is
            // the result of a concurrency bug which has since been fixed, but may persist in
            // certain catalog documents. See https://jira.mongodb.org/browse/SERVER-43074
            const bool hasMultiKeyPaths =
                std::any_of(indexMetaData.multikeyPaths.begin(),
                            indexMetaData.multikeyPaths.end(),
                            [](auto& pathSet) { return pathSet.size() > 0; });
            if (!indexMetaData.multikey && hasMultiKeyPaths) {
                LOGV2_WARNING(
                    22267,
                    "The 'multikey' field for index was false with non-empty 'multikeyPaths'. This "
                    "indicates corruption of the catalog. Consider either dropping and recreating "
                    "the index, or rerunning with the --repair option. See "
                    "http://dochub.mongodb.org/core/repair for more information",
                    "index"_attr = indexName,
                    logAttrs(md->nss));
            }

            if (!engineIdents.count(indexIdent)) {
                // There are cetain cases where the catalog entry may reference an index ident which
                // is no longer present. One example of this is when an unclean shutdown occurs
                // before a checkpoint is taken during startup recovery. Since we drop the index
                // ident without a timestamp when restarting the index build for startup recovery,
                // the subsequent startup recovery can see the now-dropped ident referenced by the
                // old index catalog entry.
                LOGV2(6386500,
                      "Index catalog entry ident not found",
                      "ident"_attr = indexIdent,
                      "entry"_attr = indexMetaData.spec,
                      logAttrs(md->nss));
            }

            // Any index build with a UUID is an unfinished two-phase build and must be restarted.
            // There are no special cases to handle on primaries or secondaries. An index build may
            // be associated with multiple indexes. We should only restart an index build if we
            // aren't going to resume it.
            if (indexMetaData.buildUUID) {
                invariant(!indexMetaData.ready);

                auto collUUID = md->options.uuid;
                invariant(collUUID);
                auto buildUUID = *indexMetaData.buildUUID;

                LOGV2(22253,
                      "Found index from unfinished build",
                      logAttrs(md->nss),
                      "uuid"_attr = *collUUID,
                      "index"_attr = indexName,
                      "buildUUID"_attr = buildUUID);

                // Insert in the map if a build has not already been registered.
                auto existingIt = reconcileResult.indexBuildsToRestart.find(buildUUID);
                if (existingIt == reconcileResult.indexBuildsToRestart.end()) {
                    reconcileResult.indexBuildsToRestart.insert(
                        {buildUUID, IndexBuildDetails(*collUUID)});
                    existingIt = reconcileResult.indexBuildsToRestart.find(buildUUID);
                }

                existingIt->second.indexSpecs.emplace_back(indexMetaData.spec);
                continue;
            }

            // If the index was kicked off as a background secondary index build, replication
            // recovery will not run into the oplog entry to recreate the index. If the index build
            // did not successfully complete, this code will return the index to be rebuilt.
            if (indexMetaData.isBackgroundSecondaryBuild && !indexMetaData.ready) {
                LOGV2(22255,
                      "Expected background index build did not complete, rebuilding in foreground "
                      "- see SERVER-43097",
                      logAttrs(md->nss),
                      "index"_attr = indexName);
                reconcileResult.indexesToRebuild.push_back(
                    {entry.catalogId, md->nss, indexName.toString()});
                continue;
            }

            // The last anomaly is when the index build did not complete. This implies the index
            // build was on:
            // (1) a standalone and the `createIndexes` command never successfully returned, or
            // (2) an initial syncing node bulk building indexes during a collection clone.
            // In both cases the index entry in the catalog should be dropped.
            if (!indexMetaData.ready) {
                invariant(!indexMetaData.isBackgroundSecondaryBuild);

                LOGV2(22256,
                      "Dropping unfinished index",
                      logAttrs(md->nss),
                      "index"_attr = indexName);
                // Ensure the `ident` is dropped while we have the `indexIdent` value.
                Status status =
                    _engine->dropIdent(shard_role_details::getRecoveryUnit(opCtx), indexIdent);
                if (!status.isOK()) {
                    // A concurrent operation, such as a checkpoint could be holding an open data
                    // handle on the ident. Handoff the ident drop to the ident reaper to retry
                    // later.
                    addDropPendingIdent(
                        Timestamp::min(), std::make_shared<Ident>(indexIdent), /*onDrop=*/nullptr);
                }
                indexesToDrop.push_back(indexName.toString());
                continue;
            }
        }

        for (auto&& indexName : indexesToDrop) {
            invariant(md->eraseIndex(indexName),
                      str::stream() << "Index is missing. Collection: "
                                    << md->nss.toStringForErrorMsg() << " Index: " << indexName);
        }
        if (indexesToDrop.size() > 0) {
            WriteUnitOfWork wuow(opCtx);
            auto collection =
                CollectionCatalog::get(opCtx)->lookupCollectionByNamespaceForMetadataWrite(
                    opCtx, entry.nss);
            invariant(collection->getCatalogId() == entry.catalogId);
            collection->replaceMetadata(opCtx, std::move(md));
            wuow.commit();
        }
    }

    // Drop any internal ident that we won't need.
    for (auto&& temp : allInternalIdents) {
        if (internalIdentsToKeep.contains(temp)) {
            continue;
        }
        LOGV2(22257, "Dropping internal ident", "ident"_attr = temp);
        WriteUnitOfWork wuow(opCtx);
        Status status = _engine->dropIdent(shard_role_details::getRecoveryUnit(opCtx), temp);
        if (!status.isOK()) {
            // A concurrent operation, such as a checkpoint could be holding an open data handle on
            // the ident. Handoff the ident drop to the ident reaper to retry later.
            addDropPendingIdent(
                Timestamp::min(), std::make_shared<Ident>(temp), /*onDrop=*/nullptr);
        }
        wuow.commit();
    }

    return reconcileResult;
}

std::string StorageEngineImpl::getFilesystemPathForDb(const DatabaseName& dbName) const {
    return _catalog->getFilesystemPathForDb(dbName);
}

void StorageEngineImpl::cleanShutdown(ServiceContext* svcCtx) {
    _timestampMonitor.reset();

    CollectionCatalog::write(svcCtx, [svcCtx](CollectionCatalog& catalog) {
        catalog.onCloseCatalog();
        catalog.deregisterAllCollectionsAndViews(svcCtx);
    });

    _catalog.reset();
    _catalogRecordStore.reset();

    _engine->cleanShutdown();
    // intentionally not deleting _engine
}

StorageEngineImpl::~StorageEngineImpl() {}

void StorageEngineImpl::startTimestampMonitor() {
    // Unless explicitly disabled, all storage engines should create a TimestampMonitor for
    // drop-pending internal idents, even if they do not support pending drops for collections
    // and indexes.
    _timestampMonitor = std::make_unique<TimestampMonitor>(
        _engine.get(), getGlobalServiceContext()->getPeriodicRunner());

    _timestampMonitor->addListener(&_minOfCheckpointAndOldestTimestampListener);
    _timestampMonitor->addListener(&_collectionCatalogCleanupTimestampListener);
}

void StorageEngineImpl::notifyStorageStartupRecoveryComplete() {
    _engine->notifyStorageStartupRecoveryComplete();
}

void StorageEngineImpl::notifyReplStartupRecoveryComplete(OperationContext* opCtx) {
    _engine->notifyReplStartupRecoveryComplete(opCtx);
}

RecoveryUnit* StorageEngineImpl::newRecoveryUnit() {
    if (!_engine) {
        // shutdown
        return nullptr;
    }
    return _engine->newRecoveryUnit();
}

std::vector<DatabaseName> StorageEngineImpl::listDatabases(
    boost::optional<TenantId> tenantId) const {
    auto res = tenantId
        ? CollectionCatalog::latest(getGlobalServiceContext())->getAllDbNamesForTenant(tenantId)
        : CollectionCatalog::latest(getGlobalServiceContext())->getAllDbNames();
    return res;
}

Status StorageEngineImpl::dropDatabase(OperationContext* opCtx, const DatabaseName& dbName) {
    return dropCollectionsWithPrefix(opCtx, dbName, "" /*collectionNamePrefix*/);
}

Status StorageEngineImpl::dropCollectionsWithPrefix(OperationContext* opCtx,
                                                    const DatabaseName& dbName,
                                                    const std::string& collectionNamePrefix) {
    auto catalog = CollectionCatalog::get(opCtx);
    {
        auto dbNames = catalog->getAllDbNames();
        if (std::count(dbNames.begin(), dbNames.end(), dbName) == 0) {
            return Status(ErrorCodes::NamespaceNotFound, "db not found to drop");
        }
    }

    std::vector<UUID> toDrop = catalog->getAllCollectionUUIDsFromDb(dbName);

    auto status = _dropCollections(opCtx, toDrop, collectionNamePrefix);

    // If all collections were dropped successfully then drop database's encryption key
    if (status.isOK()) {
        keydbDropDatabase(dbName);
    }

    return status;
}

/**
 * Returns the first `dropCollection` error that this method encounters. This method will attempt
 * to drop all collections, regardless of the error status. This method will attempt to drop all
 * collections matching the prefix 'collectionNamePrefix'. To drop all collections regardless of
 * prefix, use an empty string.
 */
Status StorageEngineImpl::_dropCollections(OperationContext* opCtx,
                                           const std::vector<UUID>& toDrop,
                                           const std::string& collectionNamePrefix) {
    Status firstError = Status::OK();
    WriteUnitOfWork wuow(opCtx);
    auto collectionCatalog = CollectionCatalog::get(opCtx);
    for (auto& uuid : toDrop) {
        auto coll = collectionCatalog->lookupCollectionByUUIDForMetadataWrite(opCtx, uuid);
        if (coll->ns().coll().startsWith(collectionNamePrefix)) {
            // Drop all indexes in the collection.
            coll->getIndexCatalog()->dropAllIndexes(
                opCtx, coll, /*includingIdIndex=*/true, /*onDropFn=*/{});

            audit::logDropCollection(opCtx->getClient(), coll->ns());

            if (auto sharedIdent = coll->getSharedIdent()) {
                Status result =
                    catalog::dropCollection(opCtx, coll->ns(), coll->getCatalogId(), sharedIdent);
                if (!result.isOK() && firstError.isOK()) {
                    firstError = result;
                }
            }

            CollectionCatalog::get(opCtx)->dropCollection(opCtx, coll, true /*isDropPending*/);
        }
    }

    wuow.commit();
    return firstError;
}

void StorageEngineImpl::flushAllFiles(OperationContext* opCtx, bool callerHoldsReadLock) {
    _engine->flushAllFiles(opCtx, callerHoldsReadLock);
}

Status StorageEngineImpl::beginBackup(OperationContext* opCtx) {
    // We should not proceed if we are already in backup mode
    if (_inBackupMode)
        return Status(ErrorCodes::BadValue, "Already in Backup Mode");
    Status status = _engine->beginBackup(opCtx);
    if (status.isOK())
        _inBackupMode = true;
    return status;
}

void StorageEngineImpl::endBackup(OperationContext* opCtx) {
    // We should never reach here if we aren't already in backup mode
    invariant(_inBackupMode);
    _engine->endBackup(opCtx);
    _inBackupMode = false;
}

Status StorageEngineImpl::disableIncrementalBackup(OperationContext* opCtx) {
    return _engine->disableIncrementalBackup(opCtx);
}

StatusWith<std::unique_ptr<StorageEngine::StreamingCursor>>
StorageEngineImpl::beginNonBlockingBackup(OperationContext* opCtx,
                                          const StorageEngine::BackupOptions& options) {
    return _engine->beginNonBlockingBackup(opCtx, options);
}

void StorageEngineImpl::endNonBlockingBackup(OperationContext* opCtx) {
    return _engine->endNonBlockingBackup(opCtx);
}

StatusWith<std::deque<std::string>> StorageEngineImpl::extendBackupCursor(OperationContext* opCtx) {
    return _engine->extendBackupCursor(opCtx);
}

bool StorageEngineImpl::supportsCheckpoints() const {
    return _engine->supportsCheckpoints();
}

bool StorageEngineImpl::isEphemeral() const {
    return _engine->isEphemeral();
}

SnapshotManager* StorageEngineImpl::getSnapshotManager() const {
    return _engine->getSnapshotManager();
}

Status StorageEngineImpl::repairRecordStore(OperationContext* opCtx,
                                            RecordId catalogId,
                                            const NamespaceString& nss) {
    auto repairObserver = StorageRepairObserver::get(getGlobalServiceContext());
    invariant(repairObserver->isIncomplete());

    Status status = _engine->repairIdent(opCtx, _catalog->getEntry(catalogId).ident);
    bool dataModified = status.code() == ErrorCodes::DataModifiedByRepair;
    if (!status.isOK() && !dataModified) {
        return status;
    }

    if (dataModified) {
        repairObserver->invalidatingModification(
            str::stream() << "Collection " << nss.toStringForErrorMsg() << ": " << status.reason());
    }

    // After repairing, re-initialize the collection with a valid RecordStore.
    CollectionCatalog::write(opCtx, [&](CollectionCatalog& catalog) {
        auto uuid = catalog.lookupUUIDByNSS(opCtx, nss).value();
        catalog.deregisterCollection(
            opCtx, uuid, /*isDropPending=*/false, /*commitTime*/ boost::none);
    });

    // When repairing a record store, keep the existing behavior of not installing a minimum visible
    // timestamp.
    _initCollection(opCtx, catalogId, nss, false, Timestamp::min());

    return status;
}

std::unique_ptr<TemporaryRecordStore> StorageEngineImpl::makeTemporaryRecordStore(
    OperationContext* opCtx, KeyFormat keyFormat) {
    std::unique_ptr<RecordStore> rs =
        _engine->makeTemporaryRecordStore(opCtx, _catalog->newInternalIdent(), keyFormat);
    LOGV2_DEBUG(22258, 1, "Created temporary record store", "ident"_attr = rs->getIdent());
    return std::make_unique<DeferredDropRecordStore>(std::move(rs), this);
}

std::unique_ptr<TemporaryRecordStore>
StorageEngineImpl::makeTemporaryRecordStoreForResumableIndexBuild(OperationContext* opCtx,
                                                                  KeyFormat keyFormat) {
    std::unique_ptr<RecordStore> rs = _engine->makeTemporaryRecordStore(
        opCtx, _catalog->newInternalResumableIndexBuildIdent(), keyFormat);
    LOGV2_DEBUG(4921500,
                1,
                "Created temporary record store for resumable index build",
                "ident"_attr = rs->getIdent());
    return std::make_unique<DeferredDropRecordStore>(std::move(rs), this);
}

std::unique_ptr<TemporaryRecordStore> StorageEngineImpl::makeTemporaryRecordStoreFromExistingIdent(
    OperationContext* opCtx, StringData ident, KeyFormat keyFormat) {
    auto rs = _engine->getTemporaryRecordStore(opCtx, ident, keyFormat);
    return std::make_unique<DeferredDropRecordStore>(std::move(rs), this);
}

void StorageEngineImpl::setJournalListener(JournalListener* jl) {
    _engine->setJournalListener(jl);
}

void StorageEngineImpl::setStableTimestamp(Timestamp stableTimestamp, bool force) {
    _engine->setStableTimestamp(stableTimestamp, force);
}

Timestamp StorageEngineImpl::getStableTimestamp() const {
    return _engine->getStableTimestamp();
}

void StorageEngineImpl::setInitialDataTimestamp(Timestamp initialDataTimestamp) {
    _engine->setInitialDataTimestamp(initialDataTimestamp);
}

Timestamp StorageEngineImpl::getInitialDataTimestamp() const {
    return _engine->getInitialDataTimestamp();
}

void StorageEngineImpl::setOldestTimestampFromStable() {
    _engine->setOldestTimestampFromStable();
}

void StorageEngineImpl::setOldestTimestamp(Timestamp newOldestTimestamp, bool force) {
    _engine->setOldestTimestamp(newOldestTimestamp, force);
}

Timestamp StorageEngineImpl::getOldestTimestamp() const {
    return _engine->getOldestTimestamp();
};

void StorageEngineImpl::setOldestActiveTransactionTimestampCallback(
    StorageEngine::OldestActiveTransactionTimestampCallback callback) {
    _engine->setOldestActiveTransactionTimestampCallback(callback);
}

bool StorageEngineImpl::supportsRecoverToStableTimestamp() const {
    return _engine->supportsRecoverToStableTimestamp();
}

bool StorageEngineImpl::supportsRecoveryTimestamp() const {
    return _engine->supportsRecoveryTimestamp();
}

StatusWith<Timestamp> StorageEngineImpl::recoverToStableTimestamp(OperationContext* opCtx) {
    invariant(shard_role_details::getLocker(opCtx)->isW());

    auto state = catalog::closeCatalog(opCtx);

    // SERVER-58311: Reset the recovery unit to unposition storage engine cursors. This allows WT to
    // assert it has sole access when performing rollback_to_stable().
    shard_role_details::replaceRecoveryUnit(opCtx);

    StatusWith<Timestamp> swTimestamp = _engine->recoverToStableTimestamp(opCtx);
    if (!swTimestamp.isOK()) {
        return swTimestamp;
    }

    catalog::openCatalog(opCtx, state, swTimestamp.getValue());
    DurableHistoryRegistry::get(opCtx)->reconcilePins(opCtx);

    LOGV2(22259,
          "recoverToStableTimestamp successful",
          "stableTimestamp"_attr = swTimestamp.getValue());
    return {swTimestamp.getValue()};
}

boost::optional<Timestamp> StorageEngineImpl::getRecoveryTimestamp() const {
    return _engine->getRecoveryTimestamp();
}

boost::optional<Timestamp> StorageEngineImpl::getLastStableRecoveryTimestamp() const {
    return _engine->getLastStableRecoveryTimestamp();
}

bool StorageEngineImpl::supportsReadConcernSnapshot() const {
    return _engine->supportsReadConcernSnapshot();
}

bool StorageEngineImpl::supportsOplogTruncateMarkers() const {
    return _engine->supportsOplogTruncateMarkers();
}

void StorageEngineImpl::clearDropPendingState(OperationContext* opCtx) {
    _dropPendingIdentReaper.clearDropPendingState(opCtx);
}

Timestamp StorageEngineImpl::getAllDurableTimestamp() const {
    return _engine->getAllDurableTimestamp();
}

boost::optional<Timestamp> StorageEngineImpl::getOplogNeededForCrashRecovery() const {
    return _engine->getOplogNeededForCrashRecovery();
}

void StorageEngineImpl::_dumpCatalog(OperationContext* opCtx) {
    auto catalogRs = _catalogRecordStore.get();
    auto cursor = catalogRs->getCursor(opCtx);
    boost::optional<Record> rec = cursor->next();
    stdx::unordered_set<std::string> nsMap;
    while (rec) {
        // This should only be called by a parent that's done an appropriate `shouldLog` check. Do
        // not duplicate the log level policy.
        LOGV2_FOR_RECOVERY(4615634,
                           kCatalogLogLevel.toInt(),
                           "Catalog entry",
                           "catalogId"_attr = rec->id,
                           "value"_attr = rec->data.toBson());
        auto valueBson = rec->data.toBson();
        if (valueBson.hasField("md")) {
            std::string ns = valueBson.getField("md").Obj().getField("ns").String();
            invariant(!nsMap.count(ns), str::stream() << "Found duplicate namespace: " << ns);
            nsMap.insert(ns);
        }
        rec = cursor->next();
    }
    shard_role_details::getRecoveryUnit(opCtx)->abandonSnapshot();
}

void StorageEngineImpl::addDropPendingIdent(
    const std::variant<Timestamp, StorageEngine::CheckpointIteration>& dropTime,
    std::shared_ptr<Ident> ident,
    DropIdentCallback&& onDrop) {
    _dropPendingIdentReaper.addDropPendingIdent(dropTime, ident, std::move(onDrop));
}

void StorageEngineImpl::dropIdentsOlderThan(OperationContext* opCtx, const Timestamp& ts) {
    _dropPendingIdentReaper.dropIdentsOlderThan(opCtx, ts);
}

std::shared_ptr<Ident> StorageEngineImpl::markIdentInUse(StringData ident) {
    return _dropPendingIdentReaper.markIdentInUse(ident);
}

void StorageEngineImpl::checkpoint() {
    _engine->checkpoint();
}

StorageEngine::CheckpointIteration StorageEngineImpl::getCheckpointIteration() const {
    return _engine->getCheckpointIteration();
}

bool StorageEngineImpl::hasDataBeenCheckpointed(
    StorageEngine::CheckpointIteration checkpointIteration) const {
    return _engine->hasDataBeenCheckpointed(checkpointIteration);
}

void StorageEngineImpl::_onMinOfCheckpointAndOldestTimestampChanged(OperationContext* opCtx,
                                                                    const Timestamp& timestamp) {
    if (_dropPendingIdentReaper.hasExpiredIdents(timestamp)) {
        LOGV2(22260,
              "Removing drop-pending idents with drop timestamps before timestamp",
              "timestamp"_attr = timestamp);

        _dropPendingIdentReaper.dropIdentsOlderThan(opCtx, timestamp);
    } else {
        LOGV2_DEBUG(8097401,
                    1,
                    "No drop-pending idents have expired",
                    "timestamp"_attr = timestamp,
                    "pendingIdentsCount"_attr = _dropPendingIdentReaper.getNumIdents());
    }
}

StorageEngineImpl::TimestampMonitor::TimestampMonitor(KVEngine* engine, PeriodicRunner* runner)
    : _engine(engine), _periodicRunner(runner) {
    _startup();
}

StorageEngineImpl::TimestampMonitor::~TimestampMonitor() {
    LOGV2(22261, "Timestamp monitor shutting down");
}

void StorageEngineImpl::TimestampMonitor::_startup() {
    invariant(!_running);

    LOGV2(22262, "Timestamp monitor starting");
    PeriodicRunner::PeriodicJob job(
        "TimestampMonitor",
        [&](Client* client) {
            if (MONGO_unlikely(pauseTimestampMonitor.shouldFail())) {
                LOGV2(6321800,
                      "Pausing the timestamp monitor due to the pauseTimestampMonitor fail point");
                pauseTimestampMonitor.pauseWhileSet();
            }

            {
                stdx::lock_guard<Latch> lock(_monitorMutex);
                if (_listeners.empty()) {
                    return;
                }
            }

            try {
                auto uniqueOpCtx = client->makeOperationContext();
                auto opCtx = uniqueOpCtx.get();

                // The TimestampMonitor is an important background cleanup task for the storage
                // engine and needs to be able to make progress to free up resources.
                ScopedAdmissionPriority<ExecutionAdmissionContext> immediatePriority(
                    opCtx, AdmissionContext::Priority::kExempt);

                Timestamp checkpoint;
                Timestamp oldest;
                Timestamp stable;
                Timestamp minOfCheckpointAndOldest;

                {
                    // Take a global lock in MODE_IS while fetching timestamps to guarantee that
                    // rollback-to-stable isn't running concurrently.
                    Lock::GlobalLock lock(opCtx, MODE_IS);

                    // The checkpoint timestamp is not cached in mongod and needs to be fetched with
                    // a call into WiredTiger, all the other timestamps are cached in mongod.
                    checkpoint = _engine->getCheckpointTimestamp();
                    oldest = _engine->getOldestTimestamp();
                    stable = _engine->getStableTimestamp();
                    minOfCheckpointAndOldest =
                        (checkpoint.isNull() || (checkpoint > oldest)) ? oldest : checkpoint;
                }

                {
                    stdx::lock_guard<Latch> lock(_monitorMutex);
                    for (const auto& listener : _listeners) {
                        if (listener->getType() == TimestampType::kCheckpoint) {
                            listener->notify(opCtx, checkpoint);
                        } else if (listener->getType() == TimestampType::kOldest) {
                            listener->notify(opCtx, oldest);
                        } else if (listener->getType() == TimestampType::kStable) {
                            listener->notify(opCtx, stable);
                        } else if (listener->getType() ==
                                   TimestampType::kMinOfCheckpointAndOldest) {
                            listener->notify(opCtx, minOfCheckpointAndOldest);
                        } else if (stable == Timestamp::min()) {
                            // Special case notification of all listeners when writes do not have
                            // timestamps. This handles standalone mode and storage engines that
                            // don't support timestamps.
                            listener->notify(opCtx, Timestamp::min());
                        }
                    }
                }

            } catch (const ExceptionFor<ErrorCodes::Interrupted>&) {
                LOGV2(6183600, "Timestamp monitor got interrupted, retrying");
                return;
            } catch (const ExceptionFor<ErrorCodes::InterruptedDueToReplStateChange>&) {
                LOGV2(6183601,
                      "Timestamp monitor got interrupted due to repl state change, retrying");
                return;
            } catch (const ExceptionFor<ErrorCodes::InterruptedAtShutdown>& ex) {
                if (_shuttingDown) {
                    return;
                }
                _shuttingDown = true;
                LOGV2(22263, "Timestamp monitor is stopping", "error"_attr = ex);
            } catch (const ExceptionForCat<ErrorCategory::CancellationError>&) {
                return;
            } catch (const DBException& ex) {
                // Logs and rethrows the exceptions of other types.
                LOGV2_ERROR(5802500, "Timestamp monitor threw an exception", "error"_attr = ex);
                throw;
            }
        },
        Seconds(1),
        true /*isKillableByStepdown*/);

    _job = _periodicRunner->makeJob(std::move(job));
    _job.start();
    _running = true;
}

void StorageEngineImpl::TimestampMonitor::addListener(TimestampListener* listener) {
    stdx::lock_guard<Latch> lock(_monitorMutex);
    if (std::find(_listeners.begin(), _listeners.end(), listener) != _listeners.end()) {
        bool listenerAlreadyRegistered = true;
        invariant(!listenerAlreadyRegistered);
    }
    _listeners.push_back(listener);
}

void StorageEngineImpl::TimestampMonitor::removeListener(TimestampListener* listener) {
    stdx::lock_guard<Latch> lock(_monitorMutex);
    if (auto it = std::find(_listeners.begin(), _listeners.end(), listener);
        it != _listeners.end()) {
        _listeners.erase(it);
    }
}

int64_t StorageEngineImpl::sizeOnDiskForDb(OperationContext* opCtx, const DatabaseName& dbName) {
    int64_t size = 0;

    auto perCollectionWork = [&](const Collection* collection) {
        size += collection->getRecordStore()->storageSize(opCtx);

        auto it = collection->getIndexCatalog()->getIndexIterator(
            opCtx,
            IndexCatalog::InclusionPolicy::kReady | IndexCatalog::InclusionPolicy::kUnfinished);
        while (it->more()) {
            size += _engine->getIdentSize(opCtx, it->next()->getIdent());
        }

        return true;
    };

    if (opCtx->isLockFreeReadsOp()) {
        auto collectionCatalog = CollectionCatalog::get(opCtx);
        for (auto&& coll : collectionCatalog->range(dbName)) {
            perCollectionWork(coll);
        }
    } else {
        catalog::forEachCollectionFromDb(opCtx, dbName, MODE_IS, perCollectionWork);
    };

    return size;
}

StatusWith<Timestamp> StorageEngineImpl::pinOldestTimestamp(
    OperationContext* opCtx,
    const std::string& requestingServiceName,
    Timestamp requestedTimestamp,
    bool roundUpIfTooOld) {
    return _engine->pinOldestTimestamp(
        opCtx, requestingServiceName, requestedTimestamp, roundUpIfTooOld);
}

void StorageEngineImpl::unpinOldestTimestamp(const std::string& requestingServiceName) {
    _engine->unpinOldestTimestamp(requestingServiceName);
}

void StorageEngineImpl::setPinnedOplogTimestamp(const Timestamp& pinnedTimestamp) {
    _engine->setPinnedOplogTimestamp(pinnedTimestamp);
}

Status StorageEngineImpl::oplogDiskLocRegister(OperationContext* opCtx,
                                               RecordStore* oplogRecordStore,
                                               const Timestamp& opTime,
                                               bool orderedCommit) {
    return _engine->oplogDiskLocRegister(opCtx, oplogRecordStore, opTime, orderedCommit);
}

void StorageEngineImpl::waitForAllEarlierOplogWritesToBeVisible(
    OperationContext* opCtx, RecordStore* oplogRecordStore) const {
    _engine->waitForAllEarlierOplogWritesToBeVisible(opCtx, oplogRecordStore);
}

DurableCatalog* StorageEngineImpl::getCatalog() {
    return _catalog.get();
}

const DurableCatalog* StorageEngineImpl::getCatalog() const {
    return _catalog.get();
}

BSONObj StorageEngineImpl::getSanitizedStorageOptionsForSecondaryReplication(
    const BSONObj& options) const {
    return _engine->getSanitizedStorageOptionsForSecondaryReplication(options);
}

void StorageEngineImpl::dump() const {
    _engine->dump();
}

Status StorageEngineImpl::autoCompact(OperationContext* opCtx, const AutoCompactOptions& options) {
    return _engine->autoCompact(opCtx, options);
}

}  // namespace mongo
