// kv_sorted_data_impl.cpp

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

#include "mongo/base/checked_cast.h"
#include "mongo/db/concurrency/write_conflict_exception.h"
#include "mongo/db/index/index_descriptor.h"
#include "mongo/db/storage/index_entry_comparison.h"
#include "mongo/db/storage/key_string.h"
#include "mongo/db/storage/kv/dictionary/kv_dictionary.h"
#include "mongo/db/storage/kv/dictionary/kv_sorted_data_impl.h"
#include "mongo/db/storage/kv/slice.h"
#include "mongo/platform/endian.h"
#include "mongo/util/log.h"
#include "mongo/util/mongoutils/str.h"

namespace mongo {

    namespace {

        const int kTempKeyMaxSize = 1024; // this goes away with SERVER-3372

        Status checkKeySize(const BSONObj &key) {
            if (key.objsize() >= kTempKeyMaxSize) {
                StringBuilder sb;
                sb << "KVSortedDataImpl::insert(): key too large to index, failing "
                   << key.objsize() << ' ' << key;
                return Status(ErrorCodes::KeyTooLong, sb.str());
            }
            return Status::OK();
        }

        bool hasFieldNames(const BSONObj& obj) {
            BSONForEach(e, obj) {
                if (e.fieldName()[0])
                    return true;
            }
            return false;
        }

        BSONObj stripFieldNames(const BSONObj& query) {
            if (!hasFieldNames(query))
                return query;

            BSONObjBuilder bb;
            BSONForEach(e, query) {
                bb.appendAs(e, StringData());
            }
            return bb.obj();
        }

        /**
         * Creates an error code message out of a key
         */
        std::string dupKeyError(const BSONObj& key) {
            StringBuilder sb;
            sb << "E11000 duplicate key error ";
            // TODO figure out how to include index name without dangerous casts
            sb << "dup key: " << key.toString();
            return sb.str();
        }

    }  // namespace

    KVSortedDataImpl::KVSortedDataImpl(KVDictionary* db,
                                       OperationContext* opCtx,
                                       const IndexDescriptor* desc)
        : _db(db),
          _ordering(Ordering::make(desc ? desc->keyPattern() : BSONObj())),
          _dupsAllowed(true)
    {
        invariant(_db);
    }

    Status KVSortedDataBuilderImpl::addKey(const BSONObj& key, const RecordId& loc) {
        return _impl->insert(_txn, key, loc, _dupsAllowed);
    }

    SortedDataBuilderInterface* KVSortedDataImpl::getBulkBuilder(OperationContext* txn,
                                                                 bool dupsAllowed) {
      return new KVSortedDataBuilderImpl(this, txn, dupsAllowed);
    }

    BSONObj KVSortedDataImpl::extractKey(const Slice &key, const Slice &val, const Ordering &ordering) {
        BufReader br(val.data(), val.size());
        return extractKey(key, ordering, KeyString::TypeBits::fromBuffer(&br));
    }

    BSONObj KVSortedDataImpl::extractKey(const Slice &key, const Ordering &ordering, const KeyString::TypeBits &typeBits) {
        return KeyString::toBson(key.data(), key.size(), ordering, typeBits);
    }

    RecordId KVSortedDataImpl::extractRecordId(const Slice &s) {
        return KeyString::decodeRecordIdAtEnd(s.data(), s.size());
    }

    Status KVSortedDataImpl::insert(OperationContext* txn,
                                    const BSONObj& key,
                                    const RecordId& loc,
                                    bool dupsAllowed) {
        invariant(loc.isNormal());
        dassert(!hasFieldNames(key));
        Status s = checkKeySize(key);
        if (!s.isOK()) {
            return s;
        }

        if (!dupsAllowed) {
            s = (_db->supportsDupKeyCheck()
                 ? _db->dupKeyCheck(txn,
                                    Slice::of(KeyString(key, _ordering, RecordId::min())),
                                    Slice::of(KeyString(key, _ordering, RecordId::max())),
                                    loc)
                 : dupKeyCheck(txn, key, loc));
            if (s == ErrorCodes::DuplicateKey) {
                // Adjust the message to include the key.
                return Status(ErrorCodes::DuplicateKey, dupKeyError(key));
            }
            if (!s.isOK()) {
                return s;
            }
        }

        KeyString keyString(key, _ordering, loc);
        Slice val;
        if (!keyString.getTypeBits().isAllZeros()) {
            // Gotta love that strong C type system, protecting us from all the important errors...
            val = Slice(reinterpret_cast<const char *>(keyString.getTypeBits().getBuffer()), keyString.getTypeBits().getSize());
        }
        return _db->insert(txn, Slice::of(keyString), val, false);
    }

    void KVSortedDataImpl::unindex(OperationContext* txn,
                                   const BSONObj& key,
                                   const RecordId& loc,
                                   bool dupsAllowed) {
        invariant(loc.isNormal());
        dassert(!hasFieldNames(key));
        _db->remove(txn, Slice::of(KeyString(key, _ordering, loc)));
    }

    void KVSortedDataImpl::fullValidate(OperationContext* txn, bool full, long long* numKeysOut,
                                        BSONObjBuilder* output) const {
        if (numKeysOut) {
            *numKeysOut = 0;
            for (boost::scoped_ptr<KVDictionary::Cursor> cursor(_db->getRangedCursor(txn));
                 cursor->ok(); cursor->advance(txn)) {
                ++(*numKeysOut);
            }
        }
    }

    bool KVSortedDataImpl::isEmpty( OperationContext* txn ) {
        boost::scoped_ptr<KVDictionary::Cursor> cursor(_db->getRangedCursor(txn));
        return !cursor->ok();
    }

    long long KVSortedDataImpl::numEntries(OperationContext* txn) const {
        long long numKeys = 0;
        fullValidate(txn, true, &numKeys, NULL);
        return numKeys;
    }

    Status KVSortedDataImpl::initAsEmpty(OperationContext* txn) {
        // no-op
        return Status::OK();
    }

    long long KVSortedDataImpl::getSpaceUsedBytes( OperationContext* txn ) const {
        KVDictionary::Stats stats = _db->getStats();
        return stats.storageSize;
    }

    bool KVSortedDataImpl::appendCustomStats(OperationContext* txn, BSONObjBuilder* output, double scale) const {
        return _db->appendCustomStats(txn, output, scale);
    }

    // ---------------------------------------------------------------------- //

    class KVSortedDataInterfaceCursor : public SortedDataInterface::Cursor {
    public:

        void setEndPosition(const BSONObj& key, bool inclusive) {
            if (key.isEmpty()) {
                this->unsetEndPosition();
            } else {
                if (inclusive) {
                    this->setInclusiveStoppingPositionForScans(key);
                } else {
                    this->setExclusiveStoppingPositionForScans(key);
                }
            }
        }

        boost::optional<IndexKeyEntry> next(RequestedInfo parts = kKeyAndLoc) {
            this->invalidateCache();
            if (this->wasRestoredToPositionThatNoLongerExists()) {
                this->initializeRestoredState();
            } else {
                this->moveToNextPosition();
            }

            this->removeSavedKey();
            if (this->isEOF()) {
                return boost::none;
            }

            if (this->isPastOrAtEndPosition()) {
                this->unsetEndPosition();
                this->resetUnderlyingCursor();
                return boost::none;
            }

            return { {this->getKey(), this->getRecordId()} };
        }

        boost::optional<IndexKeyEntry> seek(const BSONObj& key,
                                            bool inclusive,
                                            RequestedInfo parts = kKeyAndLoc) {
            this->initializeRestoredState();
            this->removeSavedKey();
            struct IndexSeekResult result;
            const auto discriminator = this->isForward() == inclusive ? KeyString::kExclusiveBefore 
                                                                      : KeyString::kExclusiveAfter;
            KeyString ks;
            ks.resetToKey(stripFieldNames(key), _ordering, discriminator);
            result = this->_seekToKeyString(ks);
            return this->getOptionalKeyUsingSeekResult(result);
        }

        boost::optional<IndexKeyEntry> seek(const IndexSeekPoint& seekPoint,
                                            RequestedInfo parts = kKeyAndLoc) {
            this->initializeRestoredState();
            this->removeSavedKey();
            BSONObj key = IndexEntryComparison::makeQueryObject(seekPoint, this->isForward());
            struct IndexSeekResult result = this->seekUsingDiscriminator(key);
            return this->getOptionalKeyUsingSeekResult(result);
        }

    private:
	bool isForward() {
	    return _dir > 0 ? true : false;
	}

        bool isReverse() {
            return _dir < 0 ? true : false;
        }

        void unsetEndPosition() {
            _endPositionIsSet = false;
        }

        void setInclusiveStoppingPositionForScans(const BSONObj &key) {
            auto discriminator = KeyString::kExclusiveAfter;
            if (this->isReverse()) {
                discriminator = KeyString::kExclusiveBefore;
            }

            _endKeyString.resetToKey(stripFieldNames(key), _ordering, discriminator);
            _endPositionIsSet = true;
        }

        void setExclusiveStoppingPositionForScans(const BSONObj &key) {
            auto discriminator = KeyString::kExclusiveBefore;
            if (this->isReverse()) {
                discriminator = KeyString::kExclusiveAfter;
            }

            _endKeyString.resetToKey(stripFieldNames(key), _ordering, discriminator);
            _endPositionIsSet = true;
        }

        bool wasRestoredToPositionThatNoLongerExists() const {
            return _wasRestored && !_restoredPositionFound;
        }

        void initializeRestoredState() {
            _wasRestored = false;
        }

        void removeSavedKey() {
            _keyStringWasSaved = false;
        }

        void moveToNextPosition() {
            _initialize();
            if (!this->isEOF()) {
                invalidateCache();
                _cursor->advance(_txn);
            }
        }

        void resetUnderlyingCursor() {
            _cursor.reset();
        }

        struct IndexSeekResult {
            bool cursorIsPointingToAKey;
            bool cursorIsPointingToAnExactMatch;
        };

        struct IndexSeekResult _seekToKey(const BSONObj &key) {
            RecordId id = this->isForward() ? RecordId::min() : RecordId::max();
            struct IndexSeekResult result;
            result.cursorIsPointingToAnExactMatch = this->locate(key, id);
            const bool pastEnd = this->isPastOrAtEndPosition();
            result.cursorIsPointingToAKey = !(this->isEOF()) && !pastEnd;
            return result;
        }

        struct IndexSeekResult _seekToKeyString(const KeyString &ks) {
            struct IndexSeekResult result;
            result.cursorIsPointingToAnExactMatch = this->_locate(ks);
            const bool pastEnd = this->isPastOrAtEndPosition();
            result.cursorIsPointingToAKey = !(this->isEOF()) && !pastEnd;
            return result;
        }

        boost::optional<IndexKeyEntry> getOptionalKeyUsingSeekResult(const struct IndexSeekResult result) {
            if (!result.cursorIsPointingToAKey) {
                return boost::none;
            }

            if (this->isPastOrAtEndPosition()) {
                this->unsetEndPosition();
                this->resetUnderlyingCursor();
                return boost::none;
            }

            return { {this->getKey(), this->getRecordId()} };
        }

        struct IndexSeekResult seekUsingDiscriminator(const BSONObj& key) {
            const auto discriminator = this->isForward() ? KeyString::kExclusiveBefore 
                                                         : KeyString::kExclusiveAfter;
            KeyString ks;
            ks.resetToKey(key, _ordering, discriminator);
            return this->_seekToKeyString(ks);
        }

        bool keyStringsAreTheSameLength(const KeyString &left, const KeyString &right) const {
            const int leftKeySize = left.getSize();
            const int rightKeySize = right.getSize();
            return (leftKeySize == rightKeySize);
        }

        int compareKeyStrings(const KeyString &left, const KeyString &right, const int size) const {
            const char* leftKeyBuffer = left.getBuffer();
            const char* rightKeyBuffer = right.getBuffer();
            const int r = memcmp(leftKeyBuffer, rightKeyBuffer, size);
            return r;
        }

	bool cursorPositionMatchesGivenKey(const KeyString &ks) {
            if (!isEOF()) {
                KeyString current;
                current.resetFromBuffer(_cursor->currKey().data(), _cursor->currKey().size());
                if (this->keyStringsAreTheSameLength(ks, current)) {
                    const int r = this->compareKeyStrings(ks, current, ks.getSize());
                    if (r == 0) {
                        return true;
                    }
                }
	    }

	    return false;
	}

        bool endKeyStringIsSurpassedByCurrentKeySting() {
            const int cmp = _keyString.compare(_endKeyString);
            if (this->isForward() && cmp > 0) {
                return true;
            } else if (!this->isForward() && cmp < 0) {
                return true;
            }

            return false;
        }

        bool isPastOrAtEndPosition() {
            if (!isEOF() && _endPositionIsSet) {
                this->loadKeyIfNeeded();
                if (this->endKeyStringIsSurpassedByCurrentKeySting()) {
                    return true;
                }
            }

            return false;
        }

        KVDictionary *_db;
        const int _dir;
        OperationContext *_txn;
        const Ordering &_ordering;

        mutable boost::scoped_ptr<KVDictionary::Cursor> _cursor;

        mutable KeyString _keyString;
        mutable bool _isKeyCurrent;
        mutable BSONObj _keyBson;
        mutable bool _isTypeBitsValid;
        mutable KeyString::TypeBits _typeBits;
        mutable RecordId _savedLoc;

        mutable bool _initialized;
        mutable KeyString _endKeyString;
        mutable bool _endPositionIsSet;
        mutable KeyString _savedKeyString;
        mutable KeyString _savedKeyStringWithoutRecord;
        mutable BSONObj _savedBson;
        mutable bool _wasRestored;
        mutable bool _restoredPositionFound;
        mutable bool _keyStringWasSaved;

        void _initialize() const {
            if (_initialized) {
                return;
            }
            _initialized = true;
            if (_cursor) {
                return;
            }
            _cursor.reset(_db->getRangedCursor(_txn, _dir));
        }

        void invalidateCache() {
            _isKeyCurrent = false;
            _isTypeBitsValid = false;
            _keyBson = BSONObj();
            _savedLoc = RecordId();
        }

        void dassertKeyCacheIsValid() const {
            DEV {
                invariant(_isKeyCurrent);
                Slice key = _cursor->currKey();
                invariant(key.size() == _keyString.getSize());
                invariant(memcmp(key.data(), _keyString.getBuffer(), key.size()) == 0);
            }
        }

        void loadKeyIfNeeded() const {
            if (_isKeyCurrent) {
                dassertKeyCacheIsValid();
                return;
            }
            Slice key = _cursor->currKey();
            _keyString.resetFromBuffer(key.data(), key.size());
            _isKeyCurrent = true;
        }

        const KeyString::TypeBits& getTypeBits() const {
            if (!_isTypeBitsValid) {
                const Slice &val = _cursor->currVal();
                BufReader br(val.data(), val.size());
                _typeBits.resetFromBuffer(&br);
                _isTypeBitsValid = true;
            }
            return _typeBits;
        }

        bool _locateWhilePreservingCache(const KeyString &ks) {
	    KVDictionary::Cursor * c = _db->getCursor(_txn, Slice::of(ks), _dir);
            _cursor.reset(c);
	    const bool result = cursorPositionMatchesGivenKey(ks);
	    return result;
        }

        bool _locate(const KeyString &ks) {
            invalidateCache();
            KVDictionary::Cursor * c = _db->getRangedCursor(_txn, Slice::of(ks), _dir);
            _cursor.reset(c);
	    const bool result = cursorPositionMatchesGivenKey(ks);
	    return result;
        }

        bool _locate(const BSONObj &key, const RecordId &loc) {
            return _locate(KeyString(key, _ordering, loc));
        }

    public:
        mutable bool _dupsAllowed;
        KVSortedDataInterfaceCursor(KVDictionary *db, OperationContext *txn, int direction, const Ordering &ordering)
            : _db(db),
              _dir(direction),
              _txn(txn),
              _ordering(ordering),
              _cursor(),
              _keyString(),
              _isKeyCurrent(false),
              _keyBson(),
              _isTypeBitsValid(false),
              _typeBits(),
              _savedLoc(),
              _initialized(false),
              _endKeyString(),
              _endPositionIsSet(false),
              _savedKeyString(),
              _savedKeyStringWithoutRecord(),
              _savedBson(),
              _wasRestored(false),
              _restoredPositionFound(false),
              _keyStringWasSaved(false),
              _dupsAllowed(true)
        {
            _txn->SetCursorOrdering(&_ordering);
        }

        virtual ~KVSortedDataInterfaceCursor() {}

        int getDirection() const {
            return _dir;
        }

        bool isEOF() const {
            _initialize();
	    const bool cursorIsSet = !!_cursor;
            if (!cursorIsSet) {
                return true;
            }

	    const bool cursorIsOK = _cursor->ok();
	    return !cursorIsOK;
        }

        bool pointsToSamePlaceAs(const Cursor& genOther) const {
            const KVSortedDataInterfaceCursor& other =
                    checked_cast<const KVSortedDataInterfaceCursor&>(genOther);
            if (isEOF() && other.isEOF()) {
                return true;
            } else if (isEOF() || other.isEOF()) {
                return false;
            }

            // We'd like to avoid loading the key into either cursor if we can avoid it, hence the
            // combinatorial massacre below.
            if (_isKeyCurrent && other._isKeyCurrent) {
                if (getRecordId() != other.getRecordId()) {
                    return false;
                }

                return _keyString.getSize() == other._keyString.getSize() &&
                        memcmp(_keyString.getBuffer(), other._keyString.getBuffer(), _keyString.getSize()) == 0;
            } else if (_isKeyCurrent) {
                const Slice &otherKey = other._cursor->currKey();
                if (getRecordId() != KVSortedDataImpl::extractRecordId(otherKey)) {
                    return false;
                }

                return _keyString.getSize() == otherKey.size() &&
                        memcmp(_keyString.getBuffer(), otherKey.data(), _keyString.getSize()) == 0;
            } else if (other._isKeyCurrent) {
                const Slice &key = _cursor->currKey();
                if (KVSortedDataImpl::extractRecordId(key) != other.getRecordId()) {
                    return false;
                }

                return key.size() == other._keyString.getSize() &&
                        memcmp(key.data(), other._keyString.getBuffer(), key.size()) == 0;
            } else {
                const Slice &key = _cursor->currKey();
                const Slice &otherKey = other._cursor->currKey();
                if (KVSortedDataImpl::extractRecordId(key) != KVSortedDataImpl::extractRecordId(otherKey)) {
                    return false;
                }

                return key.size() == otherKey.size() &&
                        memcmp(key.data(), otherKey.data(), key.size()) == 0;
            }
        }

        void aboutToDeleteBucket(const RecordId& bucket) { }

        bool locate(const BSONObj& key, const RecordId& origId) {
            RecordId id = origId;
            if (id.isNull()) {
                id = _dir > 0 ? RecordId::min() : RecordId::max();
            }
            return _locate(stripFieldNames(key), id);
        }

        void advanceTo(const BSONObj &keyBegin,
                       int keyBeginLen,
                       bool afterKey,
                       const std::vector<const BSONElement*>& keyEnd,
                       const std::vector<bool>& keyEndInclusive) {
            // make a key representing the location to which we want to advance.
            BSONObj key = IndexEntryComparison::makeQueryObject(
                                                                keyBegin,
                                                                keyBeginLen,
                                                                afterKey,
                                                                keyEnd,
                                                                keyEndInclusive,
                                                                getDirection() );
            _locate(key, _dir > 0 ? RecordId::min() : RecordId::max());
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
            if (_isKeyCurrent && !_keyBson.isEmpty()) {
                return _keyBson;
            }
            loadKeyIfNeeded();
            _keyBson = KVSortedDataImpl::extractKey(_cursor->currKey(), _ordering, getTypeBits());
            return _keyBson;
        }

        RecordId getRecordId() const {
            _initialize();
            if (isEOF()) {
                return RecordId();
            }
            if (_savedLoc.isNull()) {
                loadKeyIfNeeded();
                _savedLoc = KVSortedDataImpl::extractRecordId(Slice::of(_keyString));
                dassert(!_savedLoc.isNull());
            }
            return _savedLoc;
        }


        void advance() {
            _initialize();
            if (!isEOF()) {
                invalidateCache();
                _cursor->advance(_txn);
            }
        }

        void save() {
            _initialize();
            if (!isEOF() && !_keyStringWasSaved) {
                _savedBson = this->getKey();
                Slice key = _cursor->currKey();
                _savedKeyString.resetFromBuffer(key.data(), key.size());
                _savedKeyStringWithoutRecord.resetToKey(_savedBson, _ordering);
                _keyStringWasSaved = true;
            }

            _savedLoc = getRecordId();
            _cursor.reset();
        }

        void restoreRespectingDuplicates() {
            _restoredPositionFound = this->_locateWhilePreservingCache(_savedKeyString);
        }

        void restoreWithoutDuplicates() {
            KVDictionary::Cursor * c = _db->getCursor(_txn, Slice::of(_savedKeyStringWithoutRecord), _dir);
            _cursor.reset(c);
            invalidateCache();
            BSONObj currentBson = this->getKey();
            _restoredPositionFound = false;
            if (!isEOF()) {
                KeyString old(_savedBson, _ordering);
                KeyString current(currentBson, _ordering);
                if (this->keyStringsAreTheSameLength(old, current)) {
                    const int r = this->compareKeyStrings(old, current, old.getSize());
                    if (r == 0) {
                        _restoredPositionFound = true;
                    }
                }
            }
        }

        void restore() {
            _initialized = true;
            if (_keyStringWasSaved) {
                if (_dupsAllowed) {
                    restoreRespectingDuplicates();
                } else {
                    restoreWithoutDuplicates();
                }

                _wasRestored = true;
            } else {
                invariant(isEOF()); // this is the whole point!
            }
        }

        void detachFromOperationContext() {
            invariant(!_cursor);
            _txn = NULL;
        }

        void reattachToOperationContext(OperationContext* opCtx) {
            invariant(_txn == NULL);
            _txn = opCtx;
        }
    };

    SortedDataInterface::Cursor* KVSortedDataImpl::newCursor(OperationContext* txn,
                                                             int direction) const {
        KVSortedDataInterfaceCursor* c = new KVSortedDataInterfaceCursor(_db.get(), txn, direction, _ordering);
        c->_dupsAllowed = _dupsAllowed;
        return c;
    }

    std::unique_ptr<SortedDataInterface::Cursor>
    KVSortedDataImpl::newCursor(OperationContext* txn, bool isForward) const {
        const int direction = isForward ? 1 : -1;
        KVSortedDataInterfaceCursor *c = NULL;
        c = new KVSortedDataInterfaceCursor(_db.get(), txn, direction, _ordering);
        c->_dupsAllowed = _dupsAllowed;
        return std::unique_ptr<KVSortedDataInterfaceCursor>(c);
    }

    Status KVSortedDataImpl::dupKeyCheck(OperationContext* txn,
                                         const BSONObj& key,
                                         const RecordId& loc) {
	const int direction = 1; // <-- Forward.
	boost::scoped_ptr<KVSortedDataInterfaceCursor>
	    cursor(new KVSortedDataInterfaceCursor(_db.get(), txn, direction, _ordering));
        cursor->locate(key, RecordId());
	if (cursor->isEOF() || cursor->getKey() != key) {
	    return Status::OK();
	} else if (cursor->getRecordId() == loc) {
	    return Status::OK();
	} else {
	    return Status(ErrorCodes::DuplicateKey, dupKeyError(key));
	}

	return Status::OK();
    }
} // namespace mongo
