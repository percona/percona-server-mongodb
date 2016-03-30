/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
// vim: ft=cpp:expandtab:ts=8:sw=4:softtabstop=4:
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

#define MONGO_LOG_DEFAULT_COMPONENT ::mongo::logger::LogComponent::kStorage

#include "mongo/platform/basic.h"

#include "mongo/db/catalog/partitioned_collection.h"

#include "mongo/base/counter.h"
#include "mongo/base/owned_pointer_map.h"
#include "mongo/client/dbclientinterface.h"  //for genIndexName
#include "mongo/db/curop.h"
#include "mongo/db/catalog/collection_catalog_entry.h"
#include "mongo/db/index/index_access_method.h"
#include "mongo/db/repl/replication_coordinator_global.h"
#include "mongo/db/storage/mmap_v1/mmap_v1_options.h"
#include "mongo/db/storage/kv/dictionary/kv_record_store_partitioned.h"

#include "mongo/util/log.h"

namespace mongo {

using boost::scoped_ptr;
using std::endl;
using std::string;
using std::vector;

using logger::LogComponent;

PartitionedCollection::PartitionedCollection(OperationContext* txn,
                                             const StringData& fullNS,
                                             CollectionCatalogEntry* cce,
                                             RecordStore* recordStore,
                                             DatabaseCatalogEntry* dbce)
    : Collection(txn, fullNS, cce, recordStore, dbce, true),
      _recordStore(recordStore->as<KVRecordStorePartitioned>()) {
    invariant(!isCapped());

    // init _pkPattern
    auto opts = _details->getCollectionOptions(txn);
    if (opts.primaryKey.isEmpty())
        _pkPattern = BSON("_id" << 1);
    else
        _pkPattern = opts.primaryKey;

    // Create partitions from metadata
    Status status = _details->forEachPMDWS(txn, [this, txn](BSONObj const& pmd){return loadPartition(txn, pmd);});
    invariant(status.isOK());
}

Status PartitionedCollection::initOnCreate(OperationContext* txn) {
    return createPartition(txn);
}

Status PartitionedCollection::createPkIndexOnEmptyCollection(OperationContext* txn) {
    // if _pkPattern equals standard Id index then no need to create another one
    if (_pkPattern == BSON("_id" << 1))
        return Status::OK();

    BSONObjBuilder b;
    b.append("name", DBClientWithCommands::genIndexName(_pkPattern));
    b.append("ns", ns().ns());
    b.append("key", _pkPattern);

    return _indexCatalog.createIndexOnEmptyCollection(txn, b.obj());
}

PartitionedCollection::~PartitionedCollection() {
}


BSONObj PartitionedCollection::getPK(const BSONObj& doc) const {
    BSONObjBuilder result(64);
    BSONObjIterator pkIT(_pkPattern);
    while (pkIT.more()) {
        BSONElement field = doc[(*pkIT).fieldName()];
        if (field.eoo())
            result.appendNull((*pkIT).fieldName());
        else
            result.append(field);
        pkIT.next();
    }
    return result.obj();
}

bool PartitionedCollection::getMaxPKForPartitionCap(OperationContext* txn, BSONObj &result) const {
    auto desc = _indexCatalog.findIndexByKeyPattern(txn, _pkPattern);
    invariant(desc);
    auto iam = _indexCatalog.getIndex(desc);
    invariant(iam);
    return iam->getMaxKeyFromLastPartition(txn, result);
}

static BSONObj fillPKWithFieldsWithPattern(const BSONObj &pk, const BSONObj &pkPattern) {
    BSONObjBuilder result(64);
    BSONObjIterator patternIT(pkPattern);
    BSONObjIterator pkIT(pk);
    while (pkIT.more()) {
        BSONElement pkElement = *pkIT;
        result.appendAs(pkElement, (*patternIT).fieldName());
        patternIT.next();
        pkIT.next();
    }
    massert(19191, str::stream() << "There should be no more PK fields available for pk " << pk, !pkIT.more());
    return result.obj();
}

Status PartitionedCollection::createPartition(OperationContext* txn) {
    BSONObj maxpkforprev;
    if (_partitions.size() > 0) {
        // get maxpkforprev from last partition
        bool foundLast = getMaxPKForPartitionCap(txn, maxpkforprev);
        uassert(19189, "can only cap a partition with no pivot if it is non-empty", foundLast);
        maxpkforprev = fillPKWithFieldsWithPattern(maxpkforprev, _pkPattern);
    }
    return createPartitionInternal(txn, maxpkforprev, BSONObj());
}

Status PartitionedCollection::createPartition(OperationContext*txn, const BSONObj& maxpkforprev, const BSONObj &partitionInfo) {
    BSONObj minnewpk;
    bool ret = getMaxPKForPartitionCap(txn, minnewpk);
    if (ret) {
        // if there are any records in the last partition
        // then maxpkforprev should be greater or equal than maximum existing pk
        uassert(19192, "newMax value should be greater or equal than any existing key in the collection",
                maxpkforprev.woCompare(fillPKWithFieldsWithPattern(minnewpk, _pkPattern), _pkPattern) >= 0);
    }
    else if (_partitions.size() > 1) {
        // if there are penultimate partition
        // then maxpkforprev should be greater than its maxpk value
        // fill result with penultimate partition's pivot
        uassert(19193, "newMax value should be greater than penultimate partition's max value",
                maxpkforprev.woCompare((_partitions.crbegin() + 1)->maxpk, _pkPattern) > 0);
    }
    return createPartitionInternal(txn, maxpkforprev, partitionInfo);
}

Status PartitionedCollection::createPartitionInternal(OperationContext*txn, const BSONObj& maxpkforprev, const BSONObj &partitionInfo) {
    if (partitionInfo.isEmpty()) {
        int64_t id = 0;
        if (_partitions.size() > 0) {
            id = _partitions.back().id + 1;
            id &= 0x7fffff;
            // check if we reached maximum partitions limit
            uassert(19177, "Cannot create partition. Too many partitions already exist.",
                    id != _partitions.front().id);
        }
        Status status = _recordStore->createPartition(txn, id);
        if (!status.isOK())
            return status;

        // add indexes to the new partition
        IndexCatalog::IndexIterator ii = _indexCatalog.getIndexIterator(txn, true);
        while (ii.more()) {
            IndexDescriptor* descriptor = ii.next();
            IndexAccessMethod* iam = _indexCatalog.getIndex(descriptor);
            iam->createPartition(txn, id);
        }

        // update partition metadata structures
        if (_partitions.size() > 0) {
            _partitions.back().maxpk = maxpkforprev.copy();
        }
        _partitions.emplace_back(id, getUpperBound());
        _details->storeNewPartitionMetadata(txn, maxpkforprev, id, _partitions.back().maxpk);
    }
    else {
        //TODO: implement
        // following code is from tokumx but the call to cloneBSONWithFieldChanged looks useless
        // because BSONObj o is not used
        //BSONObj o = cloneBSONWithFieldChanged(partitionInfo, "max", getValidatedPKFromObject(partitionInfo["max"].Obj()), false);
        //appendPartition(partitionInfo);
    }
    return Status::OK();
}

// Input: BSONObj with partition metadata
// - partition Id
// - maximim value of PK
Status PartitionedCollection::loadPartition(OperationContext* txn, BSONObj const& pmd) {
    const int64_t id = pmd["_id"].numberLong();
    Status status = _recordStore->loadPartition(txn, id);
    if (!status.isOK())
        return status;
    _partitions.emplace_back(id, pmd["max"]);
    return Status::OK();
}

void PartitionedCollection::dropPartitionInternal(OperationContext* txn, int64_t id) {
    for (auto it = _partitions.begin(); it != _partitions.end(); ++it) {
        if (it->id == id) {
            _partitions.erase(it);
            break;
        }
    }
    _details->dropPartitionMetadata(txn, id);

    IndexCatalog::IndexIterator ii = _indexCatalog.getIndexIterator(txn, true);
    while (ii.more()) {
        IndexDescriptor* descriptor = ii.next();
        IndexAccessMethod* iam = _indexCatalog.getIndex(descriptor);
        iam->dropPartition(txn, id);
    }

    _recordStore->dropPartition(txn, id);
}

void PartitionedCollection::dropPartition(OperationContext* txn, int64_t id) {
    uassert(19188, "cannot drop partition if only one exists", numPartitions() > 1);
    dropPartitionInternal(txn, id);
}

BSONObj PartitionedCollection::getValidatedPKFromObject(OperationContext* txn, const BSONObj &obj) {
    auto desc = _indexCatalog.findIndexByKeyPattern(txn, _pkPattern);
    invariant(desc);
    auto iam = _indexCatalog.getIndex(desc);
    invariant(iam);
    BSONObjSet keys;
    iam->getKeys(obj, &keys);
    const BSONObj pk = keys.begin()->getOwned();
    return pk;
}

void PartitionedCollection::dropPartitionsLEQ(OperationContext* txn, const BSONObj &pivot) {
    BSONObj key = getPK(pivot);
    while (numPartitions() > 1 &&
           key.woCompare(_partitions[0].maxpk, _pkPattern) >= 0) {
        dropPartition(txn, _partitions[0].id);
    }
}

uint64_t PartitionedCollection::numPartitions() const {
    return _partitions.size();
}

StatusWith<RecordId> PartitionedCollection::insertDocument(OperationContext* txn,
                                                           const BSONObj& doc,
                                                           bool enforceQuota) {
    txn->getPartitionOffset = [this](const char* data) {
        return getPartitionOffset(data);
    };
    return Collection::insertDocument(txn, doc, enforceQuota);
}

StatusWith<RecordId> PartitionedCollection::insertDocument(OperationContext* txn,
                                                           const DocWriter* doc,
                                                           bool enforceQuota) {
    txn->getPartitionOffset = [this](const char* data) {
        return getPartitionOffset(data);
    };
    return Collection::insertDocument(txn, doc, enforceQuota);
}

StatusWith<RecordId> PartitionedCollection::insertDocument(OperationContext* txn,
                                                           const BSONObj& doc,
                                                           MultiIndexBlock* indexBlock,
                                                           bool enforceQuota) {
    txn->getPartitionOffset = [this](const char* data) {
        return getPartitionOffset(data);
    };
    return Collection::insertDocument(txn, doc, indexBlock, enforceQuota);
}

StatusWith<RecordId> PartitionedCollection::updateDocument(OperationContext* txn,
                                                           const RecordId& oldLocation,
                                                           const Snapshotted<BSONObj>& objOld,
                                                           const BSONObj& objNew,
                                                           bool enforceQuota,
                                                           bool indexesAffected,
                                                           OpDebug* debug) {
    invariant(oldLocation.partitionId() == _partitions[getPartitionOffset(objOld.value())].id);
    const PartitionData& pd = _partitions[getPartitionOffset(objNew)];

    // if document is not moved then just call Collection::updateDocument
    if (oldLocation.partitionId() == pd.id)
        return Collection::updateDocument(txn, oldLocation, objOld, objNew, enforceQuota,
                                          indexesAffected, debug);

    // otherwise remove old document and insert new document
    deleteDocument(txn, oldLocation);
    return insertDocument(txn, objNew, enforceQuota);
}

size_t PartitionedCollection::getPartitionOffset(const BSONObj& doc) const {
    // if there is one partition, then the answer is easy
    if (_partitions.size() == 1) {
        return 0;
    }
    // get PK
    BSONObj pk = getPK(doc);
    // first check the last partition, as we expect many inserts and
    // queries to go there
    if (_partitions[_partitions.size()-2].maxpk.woCompare(pk, _pkPattern) < 0) {
        return _partitions.size()-1;
    }
    // search through the whole list
    auto low = std::lower_bound(_partitions.begin(), _partitions.end(), pk,
                                [this](const PartitionData& pd, const BSONObj& pk){
                                    return pd.maxpk.woCompare(pk, _pkPattern) < 0;});
    return low - _partitions.begin();
}

size_t PartitionedCollection::getPartitionOffset(const char* data) const {
    return getPartitionOffset(BSONObj(data));
}

BSONObj PartitionedCollection::getUpperBound() const {
    BSONObjBuilder c(64);
    BSONObjIterator pkIter( _pkPattern );
    while( pkIter.more() ){
        BSONElement elt = pkIter.next();
        int order = elt.isNumber() ? elt.numberInt() : 1;
        if( order > 0 ){
            c.appendMaxKey( elt.fieldName() );
        }
        else {
            c.appendMinKey( elt.fieldName() );
        }
    }
    return c.obj();
}

}
