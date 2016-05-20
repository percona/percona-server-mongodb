// kv_engine_impl.cpp

/*======
This file is part of Percona Server for MongoDB.

Copyright (c) 2006, 2015, Percona and/or its affiliates. All rights reserved.

    Percona Server for MongoDB is free software: you can redistribute
    it and/or modify it under the terms of the GNU Affero General
    Public License, version 3, as published by the Free Software
    Foundation.

    Percona Server for MongoDB is distributed in the hope that it will
    be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public
    License along with Percona Server for MongoDB.  If not, see
    <http://www.gnu.org/licenses/>.
======= */

#include <boost/thread/mutex.hpp>

#include "mongo/db/index/index_descriptor.h"
#include "mongo/db/operation_context_noop.h"
#include "mongo/db/storage/kv/dictionary/kv_engine_impl.h"
#include "mongo/db/storage/kv/dictionary/kv_dictionary.h"
#include "mongo/db/storage/kv/dictionary/kv_record_store.h"
#include "mongo/db/storage/kv/dictionary/kv_record_store_capped.h"
#include "mongo/db/storage/kv/dictionary/kv_record_store_partitioned.h"
#include "mongo/db/storage/kv/dictionary/kv_sorted_data_impl.h"
#include "mongo/db/storage/kv/dictionary/kv_sorted_data_partitioned.h"
#include "mongo/db/storage/kv/kv_partition_utils.h"

namespace mongo {

    KVSizeStorer *KVEngineImpl::getSizeStorer(OperationContext *opCtx) {
        if (_sizeStorer) {
            return _sizeStorer.get();
        }
        static boost::mutex mutex;
        boost::mutex::scoped_lock lk(mutex);
        if (_sizeStorer) {
            return _sizeStorer.get();
        }
        std::auto_ptr<KVSizeStorer> sizeStorer(new KVSizeStorer(getMetadataDictionary(), newRecoveryUnit()));
        sizeStorer->loadFromDict(opCtx);
        _sizeStorer.reset(sizeStorer.release());
        return _sizeStorer.get();
    }

    /**
     * @param ident Ident is a one time use string. It is used for this instance
     *              and never again.
     */
    Status KVEngineImpl::createRecordStore( OperationContext* opCtx,
                                            const StringData& ns,
                                            const StringData& ident,
                                            const CollectionOptions& options ) {
        // For partitioned collections this is delayed
        if (options.partitioned)
            return Status::OK();
        // Creating a record store is as simple as creating one with the given `ident'
        return createKVDictionary(opCtx, ident, KVDictionary::Encoding::forRecordStore(),
                                  options.storageEngine);
    }

    /**
     * Caller takes ownership
     * Having multiple out for the same ns is a rules violation;
     * Calling on a non-created ident is invalid and may crash.
     */
    RecordStore* KVEngineImpl::getRecordStore( OperationContext* opCtx,
                                               const StringData& ns,
                                               const StringData& ident,
                                               const CollectionOptions& options ) {
        std::auto_ptr<RecordStore> rs;
        KVSizeStorer *sizeStorer = (persistDictionaryStats()
                                    ? getSizeStorer(opCtx)
                                    : NULL);
        if (options.partitioned) {
            rs.reset(new KVRecordStorePartitioned(opCtx, this, ns, ident, options, sizeStorer));
        } else {
            std::auto_ptr<KVDictionary> db(getKVDictionary(opCtx, ident, KVDictionary::Encoding::forRecordStore(),
                                                      options.storageEngine));
            // We separated the implementations of capped / non-capped record stores for readability.
            if (options.capped) {
                rs.reset(new KVRecordStoreCapped(db.release(), opCtx, ns, ident, options, sizeStorer, supportsDocLocking()));
            } else {
                rs.reset(new KVRecordStore(db.release(), opCtx, ns, ident, options, sizeStorer, options.partitionId));
            }
        }
        return rs.release();
    }

    Status KVEngineImpl::dropIdent( OperationContext* opCtx,
                                    const StringData& ident ) {
        return dropKVDictionary(opCtx, ident);
    }

    // --------

    Status KVEngineImpl::createSortedDataInterface(OperationContext* opCtx,
                                                   const StringData& ident,
                                                   const IndexDescriptor* desc) {
        // Creating a sorted data impl is as simple as creating one with the given `ident'
        const BSONObj keyPattern = desc ? desc->keyPattern() : BSONObj();
        const BSONObj options = desc ? desc->infoObj().getObjectField("storageEngine") : BSONObj();
        // For partitioned collections create dictionary per partition
        if (desc->isPartitioned()) {
            return desc->forEachPartition(opCtx,
                std::function<Status (BSONObj const&)>(
                    [&, this, opCtx](BSONObj const& pmd) {
                        const int64_t id = pmd["_id"].numberLong();
                        return createKVDictionary(opCtx,
                                          getPartitionName(ident, id),
                                          KVDictionary::Encoding::forIndex(Ordering::make(keyPattern)),
                                          options);
                    }
                )
            );
        }
        return createKVDictionary(opCtx, ident, KVDictionary::Encoding::forIndex(Ordering::make(keyPattern)),
                                  options);

    }

    SortedDataInterface* KVEngineImpl::getSortedDataInterface(OperationContext* opCtx,
                                                              const StringData& ident,
                                                              const IndexDescriptor* desc) {
        if (desc->isPartitioned())
            return new KVSortedDataPartitioned(opCtx, this, ident, desc);
        const BSONObj keyPattern = desc ? desc->keyPattern() : BSONObj();
        const BSONObj options = desc ? desc->infoObj().getObjectField("storageEngine") : BSONObj();
        std::auto_ptr<KVDictionary> db(getKVDictionary(opCtx, ident, KVDictionary::Encoding::forIndex(Ordering::make(keyPattern)),
                                                  options));
        return new KVSortedDataImpl(db.release(), opCtx, desc);
    }

    Status KVEngineImpl::okToRename( OperationContext* opCtx,
                                     const StringData& fromNS,
                                     const StringData& toNS,
                                     const StringData& ident,
                                     const RecordStore* originalRecordStore ) const {
        if (_sizeStorer) {
            _sizeStorer->store(NULL, ident,
                               originalRecordStore->numRecords(opCtx),
                               originalRecordStore->dataSize(opCtx));
            _sizeStorer->storeIntoDict(opCtx);
        }
        return Status::OK();
    }

    void KVEngineImpl::cleanShutdown() {
        if (_sizeStorer) {
            OperationContextNoop opCtx(newRecoveryUnit());
            _sizeStorer->storeIntoDict(&opCtx);
            _sizeStorer.reset();
        }
        cleanShutdownImpl();
    }

}
