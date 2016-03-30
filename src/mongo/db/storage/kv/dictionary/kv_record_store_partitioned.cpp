// kv_record_store_partitioned.cpp

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

#include <boost/scoped_ptr.hpp>

#include "mongo/db/storage/kv/dictionary/kv_record_store_partitioned.h"
#include "mongo/db/storage/kv/dictionary/kv_engine_impl.h"
#include "mongo/db/storage/kv/kv_partition_utils.h"

#include "mongo/util/log.h"

namespace mongo {

    KVRecordStorePartitioned::KVRecordStorePartitioned(OperationContext* opCtx,
                                                       KVEngineImpl* kvEngine,
                                                       const StringData& ns,
                                                       const StringData& ident,
                                                       const CollectionOptions& options,
                                                       KVSizeStorer *sizeStorer)
        : RecordStore(ns),
          _kvEngine(kvEngine),
          _partitionOptions(options),
          _ident(ident.toString()),
          _sizeStorer(sizeStorer)
    {
        // partition options
        _partitionOptions.partitioned = false;
    }

    Status KVRecordStorePartitioned::createPartition(OperationContext* txn, int64_t id) {
        _partitionOptions.partitionId = id;
        std::string const partIdent = getPartitionName(_ident, id);
        Status status = _kvEngine->createRecordStore(txn, ns(), partIdent, _partitionOptions);
        if (!status.isOK())
            return status;
        RecordStore* rs = _kvEngine->getRecordStore(txn, ns(), partIdent, _partitionOptions);
        invariant(rs);
        _partitionIDs.push_back(id);
        _partitions.push_back(rs);
        //TODO: do we need to registerChange here (see KVDatabaseCatalogEntry::createCollection)
        return Status::OK();
    }

    Status KVRecordStorePartitioned::loadPartition(OperationContext* txn, int64_t id) {
        _partitionOptions.partitionId = id;
        std::string const partIdent = getPartitionName(_ident, id);
        RecordStore* rs = _kvEngine->getRecordStore(txn, ns(), partIdent, _partitionOptions);
        invariant(rs);
        _partitionIDs.push_back(id);
        _partitions.push_back(rs);
        return Status::OK();
    }

    class KVRecordStorePartitioned::DropPartitionChange : public RecoveryUnit::Change {
    public:
        DropPartitionChange(OperationContext* txn,
                          KVEngineImpl* kvEngine,
                          const std::string& ident)
            : _txn(txn), _kvEngine(kvEngine), _ident(ident) {}

        virtual void rollback() override {}
        virtual void commit() override {
            _kvEngine->dropIdent(_txn, _ident);
        }

        OperationContext* const _txn;
        KVEngineImpl* _kvEngine;
        const std::string _ident;
    };

    void KVRecordStorePartitioned::dropPartition(OperationContext* txn, int64_t id) {
        for (auto i = _partitionIDs.begin(); i != _partitionIDs.end(); ++i)
        {
            if (*i == id) {
                auto prs = _partitions.begin() + (i - _partitionIDs.begin());
                delete *prs;
                _partitions.erase(prs);
                _partitionIDs.erase(i);
                txn->recoveryUnit()->registerChange(new DropPartitionChange(txn, _kvEngine, getPartitionName(_ident, id)));
                break;
            }
        }
    }

    KVRecordStorePartitioned::~KVRecordStorePartitioned() {
        for (RecordStore* rs: _partitions) {
            delete rs;
        }
    }

    long long KVRecordStorePartitioned::dataSize( OperationContext* txn ) const {
        long long result = 0;
        for (RecordStore* rs: _partitions) {
            result += rs->dataSize(txn);
        }
        return result;
    }

    long long KVRecordStorePartitioned::numRecords( OperationContext* txn ) const {
        long long result = 0;
        for (RecordStore* rs: _partitions) {
            result += rs->numRecords(txn);
        }
        return result;
    }

    int64_t KVRecordStorePartitioned::storageSize( OperationContext* txn,
                                                   BSONObjBuilder* extraInfo,
                                                   int infoLevel) const {
        int64_t result = 0;
        for (RecordStore* rs: _partitions) {
            result += rs->storageSize(txn, extraInfo, infoLevel);
        }
        return result;
    }

    RecordData KVRecordStorePartitioned::dataFor( OperationContext* txn, const RecordId& loc ) const {
        return rsForRecordId(loc)->dataFor(txn, loc);
    }

    bool KVRecordStorePartitioned::findRecord( OperationContext* txn,
                                               const RecordId& loc,
                                               RecordData* out,
                                               bool skipPessimisticLocking) const {
        return rsForRecordId(loc)->findRecord(txn, loc, out, skipPessimisticLocking);
    }

    void KVRecordStorePartitioned::deleteRecord( OperationContext* txn, const RecordId& dl ) {
        rsForRecordId(dl)->deleteRecord(txn, dl);
    }

    StatusWith<RecordId> KVRecordStorePartitioned::insertRecord( OperationContext* txn,
                                                                 const char* data,
                                                                 int len,
                                                                 bool enforceQuota ) {
        invariant(bool(txn->getPartitionOffset));
        return _partitions[txn->getPartitionOffset(data)]->insertRecord(txn, data, len, enforceQuota);
    }

    StatusWith<RecordId> KVRecordStorePartitioned::insertRecord( OperationContext* txn,
                                                                 const DocWriter* doc,
                                                                 bool enforceQuota ) {
        Slice value(doc->documentSize());
        doc->writeDocument(value.mutableData());
        return insertRecord(txn, value.data(), value.size(), enforceQuota);
    }

    StatusWith<RecordId> KVRecordStorePartitioned::updateRecord( OperationContext* txn,
                                                                 const RecordId& oldLocation,
                                                                 const char* data,
                                                                 int len,
                                                                 bool enforceQuota,
                                                                 UpdateNotifier* notifier ) {
        // PartitionedCollection::updateDocument ensures that this is only called when
        // modified document stays in the same partition
        return rsForRecordId(oldLocation)->updateRecord(txn, oldLocation, data, len, enforceQuota,
                                                        notifier);
    }

    Status KVRecordStorePartitioned::updateWithDamages( OperationContext* txn,
                                                        const RecordId& loc,
                                                        const RecordData& oldRec,
                                                        const char* damageSource,
                                                        const mutablebson::DamageVector& damages ) {
        // according to comments in upstream 3.0 code updateWithDamages cannot move document
        // and cannot change its size and also cannot change indexes
        // that is it cannot move document to another partition
        // thus implementation here is simple
        return rsForRecordId(loc)->updateWithDamages(txn, loc, oldRec, damageSource, damages);
    }

    RecordIterator* KVRecordStorePartitioned::getIterator( OperationContext* txn,
                                                           const RecordId& start,
                                                           const CollectionScanParams::Direction& dir) const {
        if (dir == CollectionScanParams::FORWARD)
            return new KVRecordIteratorPartitionedForward(*this, txn, start);
        return new KVRecordIteratorPartitionedBackward(*this, txn, start);
    }

    std::vector<RecordIterator *> KVRecordStorePartitioned::getManyIterators( OperationContext* txn ) const {
        std::vector<RecordIterator *> result;
        for (RecordStore* rs: _partitions) {
            std::vector<RecordIterator *> tmp = rs->getManyIterators(txn);
            result.insert(result.end(), tmp.begin(), tmp.end());
        }
        return result;
    }

    Status KVRecordStorePartitioned::truncate( OperationContext* txn ) {
        // KVRecordStore::truncate always returns Status::OK()
        // So this implementation does the same
        for (RecordStore* rs: _partitions) {
            rs->truncate(txn);
        }
        return Status::OK();
    }

    Status KVRecordStorePartitioned::validate( OperationContext* txn,
                                               bool full, bool scanData,
                                               ValidateAdaptor* adaptor,
                                               ValidateResults* results, BSONObjBuilder* output ) {
        // copy of KVRecordStore::validate
        bool invalidObject = false;
        long long numRecords = 0;
        long long dataSizeTotal = 0;
        for (boost::scoped_ptr<RecordIterator> iter( getIterator( txn ) );
             !iter->isEOF(); ) {
            numRecords++;
            if (scanData) {
                RecordData data = dataFor( txn, iter->curr() );
                size_t dataSize;
                if (full) {
                    const Status status = adaptor->validate( data, &dataSize );
                    if (!status.isOK()) {
                        results->valid = false;
                        if ( invalidObject ) {
                            results->errors.push_back("invalid object detected (see logs)");
                        }
                        invalidObject = true;
                        log() << "Invalid object detected in " << _ns << ": " << status.reason();
                    }
                    dataSizeTotal += static_cast<long long>(dataSize);
                }
            }
            iter->getNext();
        }

        if (_sizeStorer && full && scanData && results->valid) {
            if (numRecords != _numRecords.load() || dataSizeTotal != _dataSize.load()) {
                warning() << ns() << ": Existing record and data size counters ("
                          << _numRecords.load() << " records " << _dataSize.load() << " bytes) "
                          << "are inconsistent with full validation results ("
                          << numRecords << " records " << dataSizeTotal << " bytes). "
                          << "Updating counters with new values.";
            }

            _numRecords.store(numRecords);
            _dataSize.store(dataSizeTotal);

            long long oldNumRecords;
            long long oldDataSize;
            _sizeStorer->load(_ident, &oldNumRecords, &oldDataSize);
            if (numRecords != oldNumRecords || dataSizeTotal != oldDataSize) {
                warning() << ns() << ": Existing data in size storer ("
                          << oldNumRecords << " records " << oldDataSize << " bytes) "
                          << "is inconsistent with full validation results ("
                          << numRecords << " records " << dataSizeTotal << " bytes). "
                          << "Updating size storer with new values.";
            }

            _sizeStorer->store(this, _ident, numRecords, dataSizeTotal);
        }

        output->appendNumber("nrecords", numRecords);

        return Status::OK();
    }

    void KVRecordStorePartitioned::appendCustomStats( OperationContext* txn,
                                                      BSONObjBuilder* result,
                                                      double scale ) const {
        result->appendBool("capped", false);
        result->appendBool("partitioned", true);
        BSONArrayBuilder ab(result->subarrayStart("partitions"));
        auto idit = _partitionIDs.cbegin();
        for (RecordStore* rs: _partitions) {
            BSONObjBuilder b(ab.subobjStart());
            b.appendNumber("_id", static_cast<long long>(*idit++));
            long long size = rs->dataSize(txn) / scale;
            long long numRecords = rs->numRecords(txn);
            b.appendNumber("count", numRecords);
            b.appendNumber("size", size);
            if (numRecords)
                b.append("avgObjSize", static_cast<int>(size / numRecords));

            b.appendNumber("storageSize",
                           static_cast<long long>(rs->storageSize(txn, &b, 1)) / scale);

            rs->appendCustomStats(txn, &b, scale);
            b.doneFast();
        }
        ab.doneFast();
    }

    void KVRecordStorePartitioned::updateStatsAfterRepair(OperationContext* txn,
                                                          long long numRecords,
                                                          long long dataSize) {
        if (_sizeStorer) {
            _numRecords.store(numRecords);
            _dataSize.store(dataSize);
            _sizeStorer->store(this, _ident, numRecords, dataSize);
            _sizeStorer->storeIntoDict(txn);
        }
    }

    RecordStore* KVRecordStorePartitioned::rsForRecordId(const RecordId& loc) const {
        // get partition ID from RecordID
        const int64_t partitionID = loc.partitionId();
        // if there is one partition, then the answer is easy
        if (_partitions.size() == 1) {
            invariant(partitionID == _partitionIDs[0]);
            return _partitions[0];
        }
        // first check the last partition, as we expect many inserts and
        //queries to go there
        if (partitionID == _partitionIDs.back()) {
            return _partitions.back();
        }
        // search through the whole list
        auto low = std::lower_bound(
            _partitionIDs.begin(),
            _partitionIDs.end(),
            partitionID);
        return _partitions[low - _partitionIDs.begin()];
    }

    std::deque<RecordStore*>::const_iterator
    KVRecordStorePartitioned::_getForwardPartitionIterator(int64_t partitionID) const {
        if (_partitions.size() == 1) {
            invariant(partitionID == _partitionIDs[0]);
            return _partitions.cbegin();
        }
        if (partitionID == _partitionIDs.back()) {
            return --_partitions.cend();
        }
        auto low = std::lower_bound(
            _partitionIDs.cbegin(),
            _partitionIDs.cend(),
            partitionID);
        invariant(partitionID == *low);
        return _partitions.cbegin() + (low - _partitionIDs.cbegin());
    }

    std::deque<RecordStore*>::const_reverse_iterator
    KVRecordStorePartitioned::_getBackwardPartitionIterator(int64_t partitionID) const {
        if (_partitions.size() == 1 || partitionID == _partitionIDs.back()) {
            invariant(partitionID == _partitionIDs.back());
            return _partitions.crbegin();
        }
        auto low = std::lower_bound(
            _partitionIDs.cbegin(),
            _partitionIDs.cend(),
            partitionID);
        invariant(partitionID == *low);
        return _partitions.crbegin() + (_partitions.size() - (low - _partitionIDs.cbegin()) - 1);
    }

    // ---------------------------------------------------------------------- //

    KVRecordStorePartitioned::KVRecordIteratorPartitioned::KVRecordIteratorPartitioned(
        const KVRecordStorePartitioned &rs, OperationContext *txn,
        const RecordId &start)
        : _rs(rs),
          _txn(txn),
          _rIt(nullptr) // _rIt can be initialized by descendant classes only
    {
    }

    KVRecordStorePartitioned::KVRecordIteratorPartitioned::~KVRecordIteratorPartitioned() {
        delete _rIt;
    }

    bool KVRecordStorePartitioned::KVRecordIteratorPartitioned::isEOF() {
        invariant((_rIt && !_rIt->isEOF()) || isLastPartition());
        return !_rIt || _rIt->isEOF();
    }

    RecordId KVRecordStorePartitioned::KVRecordIteratorPartitioned::curr() {
        if (isEOF()) {
            return RecordId();
        }

        return _rIt->curr();
    }

    void KVRecordStorePartitioned::KVRecordIteratorPartitioned::_saveLocAndVal() {
        invariant(_rIt);
        if (!isEOF()) {
            _savedLoc = curr();
            _savedVal = _rIt->dataFor(_savedLoc);
            dassert(_savedLoc.isNormal());
        } else {
            _savedLoc = RecordId();
            _savedVal = RecordData();
        }
    }

    RecordId KVRecordStorePartitioned::KVRecordIteratorPartitioned::getNext() {
        RecordId result;

        // return RecordId() if isEOF
        if (_rIt->isEOF() && isLastPartition())
            return result;

        // if this is not last partition then isEOF must be false
        invariant(!_rIt->isEOF());

        // We need valid copies of _savedLoc / _savedVal since we are
        // about to advance the underlying cursor.
        _saveLocAndVal();

        // otherwise return the RecordId that the iterator points at
        result = _rIt->getNext();

        // and move the iterator to the next item from the collection
        advancePartition();
        return result;
    }

    void KVRecordStorePartitioned::KVRecordIteratorPartitioned::invalidate(const RecordId& loc) {
        // this only gets called to invalidate potentially buffered
        // `loc' results between saveState() and restoreState(). since
        // we dropped our cursor and have no buffered rows, we do nothing.
    }

    void KVRecordStorePartitioned::KVRecordIteratorPartitioned::saveState() {
        // we need to drop the current cursor because it was created with
        // an operation context that the caller intends to close after
        // this function finishes (and before restoreState() is called,
        // which will give us a new operation context)
        _saveLocAndVal();
        delete _rIt;
        _rIt = nullptr;
        _txn = nullptr;
    }

    bool KVRecordStorePartitioned::KVRecordIteratorPartitioned::restoreState(OperationContext* txn) {
        invariant(!_txn && !_rIt);
        _txn = txn;
        if (!_savedLoc.isNull()) {
            RecordId saved = _savedLoc;
            setLocation(_savedLoc);
        } else {
            // We had saved state when the cursor was at EOF, so the savedLoc
            // was null - therefore we must restoreState to EOF as well.
            //
            // Assert that this is indeed the case.
            invariant(isEOF());
        }

        // `true' means the collection still exists, which is always the case
        // because this cursor would have been deleted by higher layers if
        // the collection were to indeed be dropped.
        return true;
    }

    RecordData KVRecordStorePartitioned::KVRecordIteratorPartitioned::dataFor(const RecordId& loc) const {
        invariant(_txn);

        // Kind-of tricky:
        //
        // We save the last loc and val that we were pointing to before a call
        // to getNext(). We know that our caller intends to call dataFor() on
        // each loc read this way, so if the given loc is equal to the last
        // loc, then we can return the last value read, which we own and now
        // pass to the caller with a shared pointer.
        if (!_savedLoc.isNull() && _savedLoc == loc) {
            return _savedVal;
        } else {
            // .. otherwise something strange happened and the caller actually
            // wants some other data entirely. we should probably never execute
            // this code that often because it is slow to descend the dictionary
            // for every value we want to read..
            return _rs.dataFor(_txn, loc);
        }
    }

} // namespace mongo
