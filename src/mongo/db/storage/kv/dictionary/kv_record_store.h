// kv_record_store.h

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

#pragma once

#include <string>

#include <boost/scoped_ptr.hpp>

#include "mongo/db/storage/capped_callback.h"
#include "mongo/db/storage/kv/dictionary/kv_dictionary.h"
#include "mongo/db/storage/record_store.h"
#include "mongo/platform/atomic_word.h"
#include "mongo/util/mongoutils/str.h"

namespace mongo {

    class CollectionOptions;
    class KVSizeStorer;
    class VisibleIdTracker;

    class KVRecordStore : public RecordStore {
    public:
        /**
         * Construct a new KVRecordStore. Ownership of `db' is passed to
         * this object.
         *
         * @param db, the KVDictionary interface that will be used to
         *        store records.
         * @param opCtx, the current operation context.
         * @param ns, the namespace the underlying RecordStore is
         *        constructed with
         * @param options, options for the storage engine, if any are
         *        applicable to the implementation.
         */
        KVRecordStore( KVDictionary *db,
                       OperationContext* opCtx,
                       const StringData& ns,
                       const StringData& ident,
                       const CollectionOptions& options,
                       KVSizeStorer *sizeStorer,
                       long long partitionId = 0);

        virtual ~KVRecordStore();

        /**
         * Name of the RecordStore implementation.
         */
        virtual const char* name() const { return _db->name(); }

        /**
         * Total size of each record id key plus the records stored.
         *
         * TODO: Does this have to be exact? Sometimes it doesn't, sometimes
         *       it cannot be without major performance issues.
         */
        virtual long long dataSize( OperationContext* txn ) const;

        /**
         * TODO: Does this have to be exact? Sometimes it doesn't, sometimes
         *       it cannot be without major performance issues.
         */
        virtual long long numRecords( OperationContext* txn ) const;

        /**
         * How much space is used on disk by this record store.
         */
        virtual int64_t storageSize( OperationContext* txn,
                                     BSONObjBuilder* extraInfo = NULL,
                                     int infoLevel = 0 ) const;

        // CRUD related

        virtual RecordData dataFor( OperationContext* txn, const RecordId& loc ) const;

        virtual bool findRecord( OperationContext* txn,
                                 const RecordId& loc,
                                 RecordData* out,
                                 bool skipPessimisticLocking=false ) const;

        virtual void deleteRecord( OperationContext* txn, const RecordId& dl );

        virtual StatusWith<RecordId> insertRecord( OperationContext* txn,
                                                  const char* data,
                                                  int len,
                                                  bool enforceQuota );

        virtual StatusWith<RecordId> insertRecord( OperationContext* txn,
                                                  const DocWriter* doc,
                                                  bool enforceQuota );

        virtual StatusWith<RecordId> updateRecord( OperationContext* txn,
                                                  const RecordId& oldLocation,
                                                  const char* data,
                                                  int len,
                                                  bool enforceQuota,
                                                  UpdateNotifier* notifier );

        virtual bool updateWithDamagesSupported() const {
            return _db->updateSupported();
        }

        virtual Status updateWithDamages( OperationContext* txn,
                                          const RecordId& loc,
                                          const RecordData& oldRec,
                                          const char* damageSource,
                                          const mutablebson::DamageVector& damages );

        virtual RecordIterator* getIterator( OperationContext* txn,
                                             const RecordId& start = RecordId(),
                                             const CollectionScanParams::Direction& dir =
                                             CollectionScanParams::FORWARD ) const;

        virtual std::vector<RecordIterator *> getManyIterators( OperationContext* txn ) const;

        virtual Status truncate( OperationContext* txn );

        virtual bool compactSupported() const { return _db->compactSupported(); }

        virtual bool compactsInPlace() const { return _db->compactsInPlace(); }

        virtual Status compact( OperationContext* txn,
                                RecordStoreCompactAdaptor* adaptor,
                                const CompactOptions* options,
                                CompactStats* stats );

        virtual Status validate( OperationContext* txn,
                                 bool full, bool scanData,
                                 ValidateAdaptor* adaptor,
                                 ValidateResults* results, BSONObjBuilder* output );

        virtual void appendCustomStats( OperationContext* txn,
                                        BSONObjBuilder* result,
                                        double scale ) const;

        // KVRecordStore is not capped, KVRecordStoreCapped is capped.

        virtual bool isCapped() const { return false; }

        virtual void temp_cappedTruncateAfter(OperationContext* txn,
                                              RecordId end,
                                              bool inclusive) {
            invariant(false);
        }

        void setCappedDeleteCallback(CappedDocumentDeleteCallback* cb) {
            invariant(false);
        }

        bool cappedMaxDocs() const { invariant(false); }

        bool cappedMaxSize() const { invariant(false); }

        void undoUpdateStats(long long nrDelta, long long dsDelta);

        virtual void updateStatsAfterRepair(OperationContext* txn,
                                            long long numRecords,
                                            long long dataSize);

        class KVRecordIterator : public RecordIterator {
            const KVRecordStore &_rs;
            KVDictionary *_db;
            const CollectionScanParams::Direction _dir;
            RecordId _savedLoc;
            Slice _savedVal;

            RecordId _lowestInvisible;
            const VisibleIdTracker *_idTracker;

            // May change due to saveState() / restoreState()
            OperationContext *_txn;

            boost::scoped_ptr<KVDictionary::Cursor> _cursor;

            void _setCursor(const RecordId id);

            void _saveLocAndVal();

        public: 
            KVRecordIterator(const KVRecordStore &rs, KVDictionary *db, OperationContext *txn,
                             const RecordId &start,
                             const CollectionScanParams::Direction &dir);

            bool isEOF();

            RecordId curr();

            RecordId getNext();

            void invalidate(const RecordId& loc);

            void saveState();

            bool restoreState(OperationContext* txn);

            RecordData dataFor(const RecordId& loc) const;

            void setLowestInvisible(const RecordId& id) {
                _lowestInvisible = id;
            }

            void setIdTracker(const VisibleIdTracker *tracker) {
                _idTracker = tracker;
            }
        };

    protected:
        Status _insertRecord(OperationContext *txn, const RecordId &id, const Slice &value);

        void _updateStats(OperationContext *txn, long long nrDelta, long long dsDelta);

        // Internal version of dataFor that takes a KVDictionary - used by
        // the RecordIterator to implement dataFor.
        static RecordData _getDataFor(const KVDictionary* db, OperationContext* txn, const RecordId& loc, bool skipPessimisticLocking=false);

        // Generate the next unique RecordId key value for new records stored by this record store.
        RecordId _nextId();

        // An owned KVDictionary interface used to store records.
        // The key is a modified version of RecordId (see KeyString) and
        // the value is the raw record data as provided by insertRecord etc.
        boost::scoped_ptr<KVDictionary> _db;

        // A thread-safe 64 bit integer for generating new unique RecordId keys.
        AtomicInt64 _nextIdNum;

        // Locally cached copies of these counters.
        AtomicInt64 _dataSize;
        AtomicInt64 _numRecords;

        const std::string _ident;

        KVSizeStorer *_sizeStorer;
    };

} // namespace mongo
