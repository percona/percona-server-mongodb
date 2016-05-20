// kv_sorted_data_partitioned.cpp

/*======
This file is part of Percona Server for MongoDB.

Copyright (c) 2006, 2016, Percona and/or its affiliates. All rights reserved.

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

#include "mongo/base/checked_cast.h"
#include "mongo/db/index/index_descriptor.h"
#include "mongo/db/storage/index_entry_comparison.h"
#include "mongo/db/storage/kv/dictionary/kv_engine_impl.h"
#include "mongo/db/storage/kv/dictionary/kv_sorted_data_impl.h"
#include "mongo/db/storage/kv/dictionary/kv_sorted_data_partitioned.h"
#include "mongo/db/storage/kv/kv_partition_utils.h"

namespace mongo {

    KVSortedDataPartitioned::KVSortedDataPartitioned(OperationContext* opCtx,
                                                     KVEngineImpl* kvEngine,
                                                     const StringData& ident,
                                                     const IndexDescriptor* desc)
        : _ordering(Ordering::make(desc ? desc->keyPattern() : BSONObj())),
          _kvEngine(kvEngine),
          _desc(desc),
          _keyPattern(desc ? desc->keyPattern() : BSONObj()),
          _options(desc ? desc->infoObj().getObjectField("storageEngine") : BSONObj()),
          _ident(ident.toString())
    {
        desc->forEachPartition(opCtx, [&, this, opCtx, desc](BSONObj const& pmd) {
            const int64_t id = pmd["_id"].numberLong();
            std::auto_ptr<KVDictionary>
                db(_kvEngine->getKVDictionary(opCtx,
                                              getPartitionName(_ident, id),
                                              KVDictionary::Encoding::forIndex(Ordering::make(_keyPattern)),
                                              _options));
            _partitions.push_back(new KVSortedDataImpl(db.release(), opCtx, desc));
            _partitionIDs.push_back(id);
        });
    }

    KVSortedDataPartitioned::~KVSortedDataPartitioned() {
        for (SortedDataInterface* sdi: _partitions) {
            delete sdi;
        }
    }

    SortedDataBuilderInterface* KVSortedDataPartitioned::getBulkBuilder(OperationContext* txn,
                                                                        bool dupsAllowed) {
        return new KVSortedDataBuilder(this, txn, dupsAllowed);
    }

    Status KVSortedDataPartitioned::insert(OperationContext* txn,
                                           const BSONObj& key,
                                           const RecordId& loc,
                                           bool dupsAllowed) {
        return ptnForRecordId(loc)->insert(txn, key, loc, dupsAllowed);
    }

    void KVSortedDataPartitioned::unindex(OperationContext* txn,
                                          const BSONObj& key,
                                          const RecordId& loc,
                                          bool dupsAllowed) {
        ptnForRecordId(loc)->unindex(txn, key, loc, dupsAllowed);
    }

    Status KVSortedDataPartitioned::dupKeyCheck(OperationContext* txn,
                                                const BSONObj& key,
                                                const RecordId& loc) {
        for (SortedDataInterface* sdi: _partitions) {
            Status s = sdi->dupKeyCheck(txn, key, loc);
            if (!s.isOK())
                return s;
        }
        return Status::OK();
    }

    void KVSortedDataPartitioned::fullValidate(OperationContext* txn, bool full, long long* numKeysOut,
                                               BSONObjBuilder* output) const {
        // output is not used in KVSortedDataImpl::fullValidate
        // so it is ignored here too
        // if numKeysOut is nullptr then KVSortedDataImpl::fullValidate is no-op
        // mimic this here
        if (numKeysOut) {
            *numKeysOut = 0;
            for (SortedDataInterface const* sdi: _partitions) {
                long long numKeys = 0;
                sdi->fullValidate(txn, full, &numKeys, output);
                *numKeysOut += numKeys;
            }
        }
    }

    bool KVSortedDataPartitioned::isEmpty(OperationContext* txn) {
        for (SortedDataInterface* sdi: _partitions) {
            if (!sdi->isEmpty(txn))
                return false;
        }
        return true;
    }

    long long KVSortedDataPartitioned::numEntries(OperationContext* txn) const {
        long long numKeys = 0;
        for (SortedDataInterface const* sdi: _partitions) {
            numKeys += sdi->numEntries(txn);
        }
        return numKeys;
    }

    Status KVSortedDataPartitioned::initAsEmpty(OperationContext* txn) {
        // no-op in KVSortedDataImpl so no-op here too
        return Status::OK();
    }

    long long KVSortedDataPartitioned::getSpaceUsedBytes(OperationContext* txn) const {
        long long bytes = 0;
        for (SortedDataInterface const* sdi: _partitions) {
            bytes += sdi->getSpaceUsedBytes(txn);
        }
        return bytes;
    }

    bool KVSortedDataPartitioned::appendCustomStats(OperationContext* txn,
                                                    BSONObjBuilder* output,
                                                    double scale) const {
        BSONArrayBuilder ab(output->subarrayStart("partitions"));
        auto idit = _partitionIDs.cbegin();
        for (SortedDataInterface* sdi: _partitions) {
            BSONObjBuilder b(ab.subobjStart());
            b.appendNumber("_id", static_cast<long long>(*idit++));
            sdi->appendCustomStats(txn, &b, scale);
            b.doneFast();
        }
        ab.doneFast();
        return true;
    }

    bool KVSortedDataPartitioned::getMaxKeyFromLastPartition(OperationContext* txn, BSONObj &result) const {
        boost::scoped_ptr<SortedDataInterface::Cursor> cursor(_partitions.back()->newCursor(txn, -1));
        if (cursor->isEOF())
            return false;
        result = cursor->getKey();
        return true;
    }

    void KVSortedDataPartitioned::createPartition(OperationContext* txn, int64_t id) {
        // KVEngineImpl::createSortedDataInterface
        Status status =
            _kvEngine->createKVDictionary(txn, getPartitionName(_ident, id),
                                          KVDictionary::Encoding::forIndex(Ordering::make(_keyPattern)),
                                          _options);
        invariant(status.isOK());
        // KVEngineImpl::getSortedDataInterface
        std::auto_ptr<KVDictionary>
            db(_kvEngine->getKVDictionary(txn, getPartitionName(_ident, id),
                                          KVDictionary::Encoding::forIndex(Ordering::make(_keyPattern)),
                                          _options));
        _partitions.push_back(new KVSortedDataImpl(db.release(), txn, _desc));
        _partitionIDs.push_back(id);
    }

    class KVSortedDataPartitioned::DropPartitionChange : public RecoveryUnit::Change {
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

    void KVSortedDataPartitioned::dropPartition(OperationContext* txn, int64_t id) {
        for (auto i = _partitionIDs.begin(); i != _partitionIDs.end(); ++i)
        {
            if (*i == id) {
                auto sdi = _partitions.begin() + (i - _partitionIDs.begin());
                delete *sdi;
                _partitions.erase(sdi);
                _partitionIDs.erase(i);
                txn->recoveryUnit()->registerChange(new DropPartitionChange(txn, _kvEngine, getPartitionName(_ident, id)));
                break;
            }
        }
    }

    SortedDataInterface* KVSortedDataPartitioned::ptnForRecordId(const RecordId& loc) const {
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

    // ---------------------------------------------------------------------- //

    class KVSDIPartitionedCursor : public SortedDataInterface::Cursor {
    protected:
        const KVSortedDataPartitioned &_sdi;
        const int _dir;
        OperationContext *_txn;
        const Ordering &_ordering;
        const IndexEntryComparison _idx_compare;

        // saved state
        BSONObj _savedKey;
        RecordId _savedLoc;

        // current state: current partition's cursor
        mutable std::deque<SortedDataInterface::Cursor*> _heap;
        // cursor with current location (nullptr at EOF)
        mutable SortedDataInterface::Cursor* _currcur;
        // comparator lambda function depending on direction
        std::function<bool(SortedDataInterface::Cursor*, SortedDataInterface::Cursor*)> comparator;

        mutable bool _initialized;

        void _clear_heap() {
            if (!_initialized) {
                return;
            }
            _initialized = false;
            _currcur = nullptr;
            for (SortedDataInterface::Cursor*cursor: _heap) {
                delete cursor;
            }
            _heap.clear();
        }

        void _init_heap(std::function<void(SortedDataInterface::Cursor*)> injection) const {
            _initialized = true;
            for (SortedDataInterface *p: _sdi._partitions) {
                auto cursor = p->newCursor(_txn, _dir);
                injection(cursor);
                if (!cursor->isEOF())
                    _heap.push_back(cursor);
                else
                    delete cursor;
            }
            std::make_heap(_heap.begin(), _heap.end(), comparator);
            if (!isEOF())
                _currcur = _heap.front();
        }

        void _initialize() const {
            if (_initialized) {
                return;
            }
            _init_heap([](SortedDataInterface::Cursor*){});
        }

    public:
        KVSDIPartitionedCursor(const KVSortedDataPartitioned &sdi, OperationContext *txn,
                               int direction, const Ordering &ordering)
            : _sdi(sdi),
              _dir(direction),
              _txn(txn),
              _ordering(ordering),
              _idx_compare(ordering),
              _currcur(nullptr),
              _initialized(false)
        {
            if (_dir == 1) {
                comparator = [this] (SortedDataInterface::Cursor* a, SortedDataInterface::Cursor* b) -> bool {
                    // return true if b < a
                    return _idx_compare(IndexKeyEntry(b->getKey(), b->getRecordId()),
                                        IndexKeyEntry(a->getKey(), a->getRecordId()));
                };
            }
            else {
                comparator = [this] (SortedDataInterface::Cursor* a, SortedDataInterface::Cursor* b) -> bool {
                    // return true if a < b
                    return _idx_compare(IndexKeyEntry(a->getKey(), a->getRecordId()),
                                        IndexKeyEntry(b->getKey(), b->getRecordId()));
                };
            }
        }

        virtual ~KVSDIPartitionedCursor() override {
            _clear_heap();
        }

        int getDirection() const {
            return _dir;
        }

        bool isEOF() const {
            _initialize();
            return _heap.empty();
        }

        bool pointsToSamePlaceAs(const Cursor& genOther) const {
            _initialize();
            const KVSDIPartitionedCursor& other =
                checked_cast<const KVSDIPartitionedCursor&>(genOther);
            if (isEOF() && other.isEOF()) {
                return true;
            }
            if (isEOF() || other.isEOF()) {
                return false;
            }
            return _currcur->pointsToSamePlaceAs(*other._currcur);
        }

        bool locate(const BSONObj& key, const RecordId& origId) {
            _clear_heap();
            bool result = false;
            _init_heap([&](SortedDataInterface::Cursor *cursor){
                if (cursor->locate(key, origId))
                    result = true;
            });
            return result;
        }

        void advanceTo(const BSONObj &keyBegin,
                       int keyBeginLen,
                       bool afterKey,
                       const std::vector<const BSONElement*>& keyEnd,
                       const std::vector<bool>& keyEndInclusive) {
            _clear_heap();
            _init_heap([&](SortedDataInterface::Cursor *cursor){
                cursor->advanceTo(keyBegin, keyBeginLen, afterKey, keyEnd, keyEndInclusive);
            });
        }

        void customLocate(const BSONObj& keyBegin,
                          int keyBeginLen,
                          bool afterVersion,
                          const std::vector<const BSONElement*>& keyEnd,
                          const std::vector<bool>& keyEndInclusive) {
            // The rocks engine has this to say:
            // XXX I think these do the same thing????
            advanceTo( keyBegin, keyBeginLen, afterVersion, keyEnd, keyEndInclusive );
        }

        BSONObj getKey() const {
            _initialize();
            if (isEOF()) {
                return BSONObj();
            }
            return _currcur->getKey();
        }

        RecordId getRecordId() const {
            _initialize();
            if (isEOF()) {
                return RecordId();
            }
            return _currcur->getRecordId();
        }

        void advance() {
            _initialize();
            if (!isEOF()) {
                invariant(_currcur);
                std::pop_heap(_heap.begin(), _heap.end(), comparator);
                _currcur->advance();
                if (_currcur->isEOF()) {
                    _heap.pop_back();
                    delete _currcur;
                    _currcur = nullptr;
                }
                else {
                    std::push_heap(_heap.begin(), _heap.end(), comparator);
                }
                // can become EOF if previous _currcur was not reinserted into the heap
                if (!isEOF()) {
                    _currcur = _heap.front();
                }
            }
        }

        void savePosition() {
            _initialize();
            _savedKey = getKey();
            _savedLoc = getRecordId();
            _clear_heap();
            _txn = nullptr;
        }

        void restorePosition(OperationContext* txn) {
            invariant(!_txn && !_initialized);
            _txn = txn;
            if (!_savedLoc.isNull()) {
                locate(_savedKey, _savedLoc);
            } else {
                _initialized = true;
                invariant(isEOF()); // this is the whole point!
            }
        }
    };

    SortedDataInterface::Cursor* KVSortedDataPartitioned::newCursor(OperationContext* txn,
                                                                    int direction) const {
        return new KVSDIPartitionedCursor(*this, txn, direction, _ordering);
    }

} // namespace mongo
