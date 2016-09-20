// kv_record_store.cpp

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

#include <algorithm>
#include <climits>
#include <boost/scoped_ptr.hpp>
#include <boost/static_assert.hpp>

#include "mongo/db/catalog/collection_options.h"
#include "mongo/db/concurrency/write_conflict_exception.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/storage/key_string.h"
#include "mongo/db/storage/kv/dictionary/kv_dictionary_update.h"
#include "mongo/db/storage/kv/dictionary/kv_record_store.h"
#include "mongo/db/storage/kv/dictionary/kv_size_storer.h"
#include "mongo/db/storage/kv/dictionary/visible_id_tracker.h"
#include "mongo/db/storage/kv/slice.h"

#include "mongo/platform/endian.h"
#include "mongo/util/log.h"

namespace mongo {

    namespace {

        const long long kScanOnCollectionCreateThreshold = 10000;

    }

    KVRecordStore::KVRecordStore( KVDictionary *db,
                                  OperationContext* opCtx,
                                  StringData ns,
                                  StringData ident,
                                  const CollectionOptions& options,
                                  KVSizeStorer *sizeStorer )
        : RecordStore(ns),
          _db(db),
          _ident(ident.toString()),
          _sizeStorer(sizeStorer)
    {
        invariant(_db != NULL);

        // Get the next id, which is one greater than the greatest stored.
        const bool FORWARD = false;
        boost::scoped_ptr<KVRecordCursor> iter(getKVCursor(opCtx, FORWARD));//RecordId(), CollectionScanParams::BACKWARD));
        if (!iter->isEOF()) {
            const RecordId lastId = iter->curr();
            invariant(lastId.isNormal());
            _nextIdNum.store(lastId.repr() + 1);
        } else {
            // Need to start at 1 so we are within bounds of RecordId::isNormal()
            _nextIdNum.store(1);
        }

        if (_sizeStorer) {
            long long numRecords;
            long long dataSize;
            _sizeStorer->load(_ident, &numRecords, &dataSize);

            if (numRecords < kScanOnCollectionCreateThreshold) {
                LOG(1) << "Doing scan of collection " << ns << " to refresh numRecords and dataSize";
                _numRecords.store(0);
                _dataSize.store(0);
                const bool forward = true;
                for (boost::scoped_ptr<KVRecordCursor> iter(getKVCursor(opCtx, forward)); !iter->isEOF(); ) {
                    RecordId loc = iter->getNext();
                    RecordData data = iter->dataFor(loc);
                    _numRecords.fetchAndAdd(1);
                    _dataSize.fetchAndAdd(data.size());
                }

                if (numRecords != _numRecords.load()) {
                    warning() << "Stored value for " << ns << " numRecords was " << numRecords
                              << " but actual value is " << _numRecords.load();
                }
                if (dataSize != _dataSize.load()) {
                    warning() << "Stored value for " << ns << " dataSize was " << dataSize
                              << " but actual value is " << _dataSize.load();
                }
            } else {
                _numRecords.store(numRecords);
                _dataSize.store(dataSize);
            }

            _sizeStorer->onCreate(this, _ident, _numRecords.load(), _dataSize.load());
        }
    }

    KVRecordStore::~KVRecordStore() {
        if (_sizeStorer) {
            _sizeStorer->onDestroy(_ident, _numRecords.load(), _dataSize.load());
        }
    }

#define invariantKVOK(s, expr) massert(28933, expr, s.isOK())

    long long KVRecordStore::dataSize( OperationContext* txn ) const {
        if (_sizeStorer) {
            return _dataSize.load();
        } else {
            return _db->getStats().dataSize;
        }
    }

    long long KVRecordStore::numRecords( OperationContext* txn ) const {
        if (_sizeStorer) {
            return _numRecords.load();
        } else {
            return _db->getStats().numKeys;
        }
    }

    int64_t KVRecordStore::storageSize( OperationContext* txn,
                                        BSONObjBuilder* extraInfo,
                                        int infoLevel ) const {
        return _db->getStats().storageSize;
    }

    class RollbackSizeChange : public RecoveryUnit::Change {
        KVRecordStore *_rs;
        long long _nrDelta;
        long long _dsDelta;
    public:
        RollbackSizeChange(KVRecordStore *rs, long long nrDelta, long long dsDelta)
            : _rs(rs),
              _nrDelta(nrDelta),
              _dsDelta(dsDelta)
        {}

        void commit() {}

        void rollback() {
            _rs->undoUpdateStats(_nrDelta, _dsDelta);
        }
    };

    void KVRecordStore::undoUpdateStats(long long nrDelta, long long dsDelta) {
        invariant(_sizeStorer);
        _numRecords.subtractAndFetch(nrDelta);
        _dataSize.subtractAndFetch(dsDelta);
    }

    void KVRecordStore::_updateStats(OperationContext *txn, long long nrDelta, long long dsDelta) {
        if (_sizeStorer) {
            _numRecords.addAndFetch(nrDelta);
            _dataSize.addAndFetch(dsDelta);
            txn->recoveryUnit()->registerChange(new RollbackSizeChange(this, nrDelta, dsDelta));
        }
    }

    void KVRecordStore::updateStatsAfterRepair(OperationContext* txn, long long numRecords, long long dataSize) {
        if (_sizeStorer) {
            _numRecords.store(numRecords);
            _dataSize.store(dataSize);
            _sizeStorer->store(this, _ident, numRecords, dataSize);
            _sizeStorer->storeIntoDict(txn);
        }
    }

    RecordData KVRecordStore::_getDataFor(const KVDictionary *db, OperationContext* txn, const RecordId& id, bool skipPessimisticLocking) {
        Slice value;
        Status status = db->get(txn, Slice::of(KeyString(id)), value, skipPessimisticLocking);
        if (!status.isOK()) {
            if (status.code() == ErrorCodes::NoSuchKey) {
                return RecordData(nullptr, 0);
            } else {
                log() << "storage engine get() failed, operation will fail: " << status.toString();
                uasserted(28922, status.toString());
            }
        }

        // Return an owned RecordData that uses the SharedBuffer from `value'
        return RecordData(std::move(value.ownedBuf()), value.size());
    }

    RecordData KVRecordStore::dataFor( OperationContext* txn, const RecordId& loc) const {
        RecordData rd;
        bool found = findRecord(txn, loc, &rd);
        massert(28923, "Didn't find RecordId in record store", found);
        return rd;
    }

    bool KVRecordStore::findRecordRelaxed(OperationContext* txn, const RecordId& loc, RecordData* out) const {
        return _findRecord(txn, loc, out, true);
    }

    bool KVRecordStore::findRecord(OperationContext* txn, const RecordId& loc, RecordData* out) const {
        return _findRecord(txn, loc, out, false);
    }

    bool KVRecordStore::_findRecord(OperationContext* txn, const RecordId& loc, RecordData* out,
                                    bool skipPessimisticLocking) const {
        RecordData rd = _getDataFor(_db.get(), txn, loc, skipPessimisticLocking);
        if (rd.data() == NULL) {
            return false;
        }
        *out = rd;
        return true;
    }

    void KVRecordStore::deleteRecord(OperationContext* txn, const RecordId& id) {
        const KeyString key(id);
        Slice val;
        Status s = _db->get(txn, Slice::of(key), val, false);
        invariantKVOK(s, str::stream() << "KVRecordStore: couldn't find record " << id << " for delete: " << s.toString());

        _updateStats(txn, -1, -val.size());

        s = _db->remove(txn, Slice::of(key));
        invariant(s.isOK());
    }

    Status KVRecordStore::_insertRecord(OperationContext *txn,
                                        const RecordId &id,
                                        const Slice &value) {
        const KeyString key(id);
        DEV {
            // Should never overwrite an existing record.
            Slice v;
            const Status status = _db->get(txn, Slice::of(key), v, true);
            invariant(status.code() == ErrorCodes::NoSuchKey);
        }

        Status s = _db->insert(txn, Slice::of(key), value, true);
        if (!s.isOK()) {
            return s;
        }

        _updateStats(txn, 1, value.size());

        return s;
    }

    StatusWith<RecordId> KVRecordStore::insertRecord(OperationContext* txn,
                                                     const char* data,
                                                     int len,
                                                     bool enforceQuota) {
        const RecordId id = _nextId();
        const Slice value(data, len);

        const Status status = _insertRecord(txn, id, value);
        if (!status.isOK()) {
            return StatusWith<RecordId>(status);
        }

        return StatusWith<RecordId>(id);
    }

    StatusWith<RecordId> KVRecordStore::insertRecord(OperationContext* txn,
                                                     const DocWriter* doc,
                                                     bool enforceQuota) {
        Slice value(doc->documentSize());
        doc->writeDocument(value.mutableData());
        return insertRecord(txn, value.data(), value.size(), enforceQuota);
    }

    StatusWith<RecordId> KVRecordStore::updateRecord(OperationContext* txn,
                                                     const RecordId& id,
                                                     const char* data,
                                                     int len,
                                                     bool enforceQuota,
                                                     UpdateNotifier* notifier) {
        return _updateRecord(txn, id, /*unknown length*/ -1, data, len, enforceQuota, notifier);
    }

    StatusWith<RecordId> KVRecordStore::updateRecordEx(OperationContext* txn,
                                                       const RecordId& id,
                                                       int old_length,
                                                       const char* data,
                                                       int len,
                                                       bool enforceQuota,
                                                       UpdateNotifier* notifier) {
        return _updateRecord(txn, id, old_length, data, len, enforceQuota, notifier);
    }

    StatusWith<RecordId> KVRecordStore::_updateRecord(OperationContext* txn,
                                                      const RecordId& id,
                                                      int old_length,
                                                      const char* data,
                                                      int len,
                                                      bool enforceQuota,
                                                      UpdateNotifier* notifier) {
        const KeyString key(id);
        const Slice value(data, len);

        int64_t numRecordsDelta = 0;
        int64_t dataSizeDelta = value.size();

        if (old_length == -1) {
            old_length = 0;

            Slice val;
            Status status = _db->get(txn, Slice::of(key), val, false);
            if (status.code() == ErrorCodes::NoSuchKey) {
                numRecordsDelta += 1;
            } else if (status.isOK()) {
                old_length = val.size();
            } else {
                return StatusWith<RecordId>(status);
            }
        }
        dataSizeDelta -= old_length;

        // An update with a complete new image (data, len) is implemented as an overwrite insert.
        Status status = _db->insert(txn, Slice::of(key), value, false);
        if (!status.isOK()) {
            return StatusWith<RecordId>(status);
        }

        _updateStats(txn, numRecordsDelta, dataSizeDelta);

        return StatusWith<RecordId>(id);
    }

    StatusWith<RecordData> KVRecordStore::updateWithDamages( OperationContext* txn,
                                                             const RecordId& id,
                                                             const RecordData& oldRec,
                                                             const char* damageSource,
                                                             const mutablebson::DamageVector& damages ) {
        const KeyString key(id);

        const Slice oldValue(oldRec.data(), oldRec.size());
        const KVUpdateWithDamagesMessage message(damageSource, damages);

        // updateWithDamages can't change the number or size of records, so we don't need to update
        // stats.

        const Status s = _db->update(txn, Slice::of(key), oldValue, message);
        if (!s.isOK()) {
            return StatusWith<RecordData>(s);
        }

        // We also need to reach in and screw with the old doc's data so that the update system gets
        // the new image, because the update system is assuming mmapv1's behavior.  Sigh.
        for (mutablebson::DamageVector::const_iterator it = damages.begin(); it != damages.end(); it++) {
            const mutablebson::DamageEvent &event = *it;
            invariant(event.targetOffset + event.size < static_cast<uint32_t>(oldRec.size()));
            std::copy(damageSource + event.sourceOffset, damageSource + event.sourceOffset + event.size,
                      /* eek */
                      const_cast<char *>(oldRec.data()) + event.targetOffset);
        }

        return StatusWith<RecordData>(oldRec);
    }

    KVRecordStore::KVRecordCursor* KVRecordStore::getKVCursor(OperationContext* txn,
                                                              bool forward) const {
        return new KVRecordCursor(*this, _db.get(), txn, forward);
    }

    std::unique_ptr<SeekableRecordCursor> KVRecordStore::getCursor(OperationContext* txn,
                                                           bool forward) const {
        KVRecordCursor *c = new KVRecordCursor(*this, _db.get(), txn, forward);
        return std::unique_ptr<KVRecordCursor>(c);
    }

    std::unique_ptr<RecordCursor> KVRecordStore::getCursorForRepair(OperationContext* txn) const {
        const bool isForward = true;
        KVRecordCursor *c = new KVRecordCursor(*this, _db.get(), txn, isForward);
        return std::unique_ptr<KVRecordCursor>(c);
    }

    std::vector<std::unique_ptr<RecordCursor>> KVRecordStore::getManyCursors(OperationContext* txn) const {
        std::vector<std::unique_ptr<RecordCursor> > iterators;
        const bool forward = true;
        iterators.push_back(getCursor(txn, forward));
        return iterators;
    }

    Status KVRecordStore::truncate( OperationContext* txn ) {
        // This is not a very performant implementation of truncate.
        //
        // At the time of this writing, it is only used by 'emptycapped', a test-only command.
        const bool forward = true;
        for (boost::scoped_ptr<KVRecordCursor> iter(getKVCursor(txn, forward));
             !iter->isEOF(); ) {
            RecordId id = iter->getNext();
            deleteRecord(txn, id);
        }

        return Status::OK();
    }

    Status KVRecordStore::compact( OperationContext* txn,
                                   RecordStoreCompactAdaptor* adaptor,
                                   const CompactOptions* options,
                                   CompactStats* stats ) {
        return _db->compact( txn );
    }

    Status KVRecordStore::validate( OperationContext* txn,
                                    bool full,
                                    bool scanData,
                                    ValidateAdaptor* adaptor,
                                    ValidateResults* results,
                                    BSONObjBuilder* output ) {
        bool invalidObject = false;
        long long numRecords = 0;
        long long dataSizeTotal = 0;
        const bool forward = true;
        for (boost::scoped_ptr<KVRecordCursor> iter( getKVCursor(txn, forward) );
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

    void KVRecordStore::appendCustomStats( OperationContext* txn,
                                           BSONObjBuilder* result,
                                           double scale ) const {
        if (!result->hasField("capped")) {
            result->appendBool("capped", false);
        }

        _db->appendCustomStats(txn, result, scale);
    }

    RecordId KVRecordStore::_nextId() {
        return RecordId(_nextIdNum.fetchAndAdd(1));
    }

    // ---------------------------------------------------------------------- //

    boost::optional<Record> KVRecordStore::KVRecordCursor::next() {
        if (isEOF()) {
            return boost::none;
        }

        _saveLocAndVal();
        _cursor->advance(_txn);
        Record r;
        r.id = _savedLoc;
        r.data = dataFor(_savedLoc);
        return r;
    }

    boost::optional<Record> KVRecordStore::KVRecordCursor::seekExact(const RecordId& id) {
        _cursor.reset();
        _setCursor(id);
        return next();
    }

    void KVRecordStore::KVRecordCursor::_setCursor(const RecordId id) {
        // We should no cursor at this point, either because we're getting newly
        // constructed or because we're recovering from saved state (and so
        // the old cursor needed to be dropped).
        invariant(!_cursor);
        _cursor.reset();
        _savedLoc = RecordId();
        _savedVal = Slice();

        // A new iterator with no start position will be either min() or max()
        invariant(id.isNormal() || id == RecordId::min() || id == RecordId::max());
        const int dir = _isForward ? 1 : -1;
        _cursor.reset(_db->getCursor(_txn, Slice::of(KeyString(id)), dir));
    }

    KVRecordStore::KVRecordCursor::KVRecordCursor(const KVRecordStore &rs, KVDictionary *db, OperationContext *txn, const bool isForward)
        : _rs(rs),
          _db(db),
          _savedLoc(),
          _savedVal(),
          _lowestInvisible(),
          _idTracker(NULL),
          _txn(txn),
          _cursor(),
          _isForward(isForward) {
        if (isForward) {
            _setCursor(RecordId::min());
        } else {
            _setCursor(RecordId::max());
        }
    }

    bool KVRecordStore::KVRecordCursor::isEOF() {
        return !_cursor || !_cursor->ok();
    }

    RecordId KVRecordStore::KVRecordCursor::curr() {
        if (isEOF()) {
            return RecordId();
        }

        const Slice &key = _cursor->currKey();
        BufReader br(key.data(), key.size());
        return KeyString::decodeRecordId(&br);
    }

    void KVRecordStore::KVRecordCursor::_saveLocAndVal() {
        if (!isEOF()) {
            _savedLoc = curr();
            _savedVal = _cursor->currVal().owned();
            dassert(_savedLoc.isNormal());
        } else {
            _savedLoc = RecordId();
            _savedVal = Slice();
        }
    }

    RecordId KVRecordStore::KVRecordCursor::getNext() {
        if (isEOF()) {
            return RecordId();
        }

        // We need valid copies of _savedLoc / _savedVal since we are
        // about to advance the underlying cursor.
        _saveLocAndVal();
        _cursor->advance(_txn);

        if (!isEOF()) {
            if (_idTracker) {
                RecordId currentId = curr();
                if (!_lowestInvisible.isNull()) {
                    // oplog
                    if (currentId >= _lowestInvisible) {
                        _cursor.reset();
                    } else if (RecordId(currentId.repr() + 1) == _lowestInvisible && !_idTracker->canReadId(currentId)) {
                        _cursor.reset();
                    }
                } else if (!_idTracker->canReadId(currentId)) {
                    _cursor.reset();
                }
            }
        }

        return _savedLoc;
    }

    void KVRecordStore::KVRecordCursor::invalidate(OperationContext* OpCtx, const RecordId& loc) {
        // this only gets called to invalidate potentially buffered
        // `loc' results between saveState() and restoreState().
        _savedLoc = RecordId();
    }

    void KVRecordStore::KVRecordCursor::saveState() {
        if (!_cursor) return;
        // we need to drop the current cursor because it was created with
        // an operation context that the caller intends to close after
        // this function finishes (and before restoreState() is called,
        // which will give us a new operation context)
        _saveLocAndVal();
        _cursor.reset();
    }

    bool KVRecordStore::KVRecordCursor::restoreState() {
        invariant(!_cursor);
        if (!_savedLoc.isNull()) {
            RecordId saved = _savedLoc;
            _setCursor(_savedLoc);
            if (curr() != saved && _rs.isCapped()) {
                // Doc was deleted either by cappedDeleteAsNeeded() or cappedTruncateAfter()
                _cursor.reset();
                return false;
            }
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

    void KVRecordStore::KVRecordCursor::detachFromOperationContext() {
        invariant(!_cursor);
        _txn = NULL;
    }

    void KVRecordStore::KVRecordCursor::reattachToOperationContext(OperationContext* opCtx) {
        invariant(_txn == NULL);
        _txn = opCtx;
    }

    RecordData KVRecordStore::KVRecordCursor::dataFor(const RecordId& loc) const {
        invariant(_txn);

        // Kind-of tricky:
        //
        // We save the last loc and val that we were pointing to before a call
        // to getNext(). We know that our caller intends to call dataFor() on
        // each loc read this way, so if the given loc is equal to the last 
        // loc, then we can return the last value read, which we own and now
        // pass to the caller with a shared pointer.
        if (!_savedLoc.isNull() && _savedLoc == loc) {
            Slice val = _savedVal;
            invariant(val.mutableData());
            return RecordData(std::move(val.ownedBuf()), val.size());
        } else {
            // .. otherwise something strange happened and the caller actually
            // wants some other data entirely. we should probably never execute
            // this code that often because it is slow to descend the dictionary
            // for every value we want to read..
            return _getDataFor(_db, _txn, loc);
        }
    }

} // namespace mongo
