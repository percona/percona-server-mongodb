// kv_record_store_partitioned.h

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

#include "mongo/db/catalog/collection_options.h"
#include "mongo/db/storage/kv/dictionary/kv_dictionary.h"
#include "mongo/db/storage/record_store.h"
#include "mongo/db/operation_context.h"

#include <deque>


namespace mongo {

    class CollectionOptions;
    class KVSizeStorer;
    class KVEngineImpl;

    class KVRecordStorePartitioned : public RecordStore {
    public:
        /**
         * Construct a new KVRecordStorePartitioned.
         *
         * @param opCtx, the current operation context.
         * @param ns, the namespace the underlying RecordStore is
         *        constructed with
         * @param options, options for the storage engine, if any are
         *        applicable to the implementation.
         */
        KVRecordStorePartitioned(OperationContext* opCtx,
                                 KVEngineImpl* kvEngine,
                                 const StringData& ns,
                                 const StringData& ident,
                                 const CollectionOptions& options,
                                 KVSizeStorer *sizeStorer);

        virtual ~KVRecordStorePartitioned() override;

        /**
         * Name of the RecordStore implementation.
         */
        virtual const char* name() const override { return _partitions[0]->name(); }

        /**
         * Total size of each record id key plus the records stored.
         *
         * TODO: Does this have to be exact? Sometimes it doesn't, sometimes
         *       it cannot be without major performance issues.
         */
        virtual long long dataSize( OperationContext* txn ) const override;

        /**
         * TODO: Does this have to be exact? Sometimes it doesn't, sometimes
         *       it cannot be without major performance issues.
         */
        virtual long long numRecords( OperationContext* txn ) const override;

        /**
         * How much space is used on disk by this record store.
         */
        virtual int64_t storageSize( OperationContext* txn,
                                     BSONObjBuilder* extraInfo = NULL,
                                     int infoLevel = 0 ) const override;

        virtual RecordData dataFor( OperationContext* txn, const RecordId& loc ) const override;

        virtual bool findRecord( OperationContext* txn,
                                 const RecordId& loc,
                                 RecordData* out,
                                 bool skipPessimisticLocking=false ) const override;

        virtual void deleteRecord( OperationContext* txn, const RecordId& dl ) override;

        virtual StatusWith<RecordId> insertRecord( OperationContext* txn,
                                                  const char* data,
                                                  int len,
                                                  bool enforceQuota ) override;

        virtual StatusWith<RecordId> insertRecord( OperationContext* txn,
                                                  const DocWriter* doc,
                                                  bool enforceQuota ) override;

        virtual StatusWith<RecordId> updateRecord( OperationContext* txn,
                                                  const RecordId& oldLocation,
                                                  const char* data,
                                                  int len,
                                                  bool enforceQuota,
                                                  UpdateNotifier* notifier ) override;

        virtual bool updateWithDamagesSupported() const  override{
            return _partitions[0]->updateWithDamagesSupported();
        }

        virtual Status updateWithDamages( OperationContext* txn,
                                          const RecordId& loc,
                                          const RecordData& oldRec,
                                          const char* damageSource,
                                          const mutablebson::DamageVector& damages ) override;

        virtual RecordIterator* getIterator( OperationContext* txn,
                                             const RecordId& start = RecordId(),
                                             const CollectionScanParams::Direction& dir =
                                             CollectionScanParams::FORWARD ) const override;

        virtual std::vector<RecordIterator *> getManyIterators( OperationContext* txn ) const override;

        virtual Status truncate( OperationContext* txn ) override;

        virtual Status validate( OperationContext* txn,
                                 bool full, bool scanData,
                                 ValidateAdaptor* adaptor,
                                 ValidateResults* results, BSONObjBuilder* output ) override;

        virtual void appendCustomStats( OperationContext* txn,
                                        BSONObjBuilder* result,
                                        double scale ) const override;

        virtual bool isCapped() const override { return false; }

        virtual void temp_cappedTruncateAfter(OperationContext* txn,
                                              RecordId end,
                                              bool inclusive) override {
            invariant(false);
        }

        virtual void updateStatsAfterRepair(OperationContext* txn,
                                            long long numRecords,
                                            long long dataSize) override;

        Status createPartition(OperationContext* txn, int64_t id);

        Status loadPartition(OperationContext* txn, int64_t id);

        void dropPartition(OperationContext* txn, int64_t id);

        class KVRecordIteratorPartitioned : public RecordIterator {
        protected:
            const KVRecordStorePartitioned &_rs;
            RecordId _savedLoc;
            RecordData _savedVal;

            // May change due to saveState() / restoreState()
            OperationContext *_txn;

            // current state: current partition's iterator
            RecordIterator *_rIt;

            void _saveLocAndVal();

            // abstract methods which implementation depends on _dir value
            virtual void setLocation(const RecordId id) = 0;
            virtual void advancePartition(RecordId loc = RecordId()) = 0;
            virtual bool isLastPartition() const = 0;

        public:
            KVRecordIteratorPartitioned(const KVRecordStorePartitioned &rs, OperationContext *txn,
                                        const RecordId &start);
            ~KVRecordIteratorPartitioned();

            bool isEOF();

            RecordId curr();

            RecordId getNext();

            void invalidate(const RecordId& loc);

            void saveState();

            bool restoreState(OperationContext* txn);

            RecordData dataFor(const RecordId& loc) const;

        };

        class KVRecordIteratorPartitionedForward : public KVRecordIteratorPartitioned {
            std::deque<RecordStore*>::const_iterator it;

            std::deque<RecordStore*>::const_iterator _getPartitionIterator(int64_t partitionID) const {
                return _rs._getForwardPartitionIterator(partitionID);
            }

            void setLocation(const RecordId loc) override {
                // This is only called to recover saved state
                // so there should be no record iterator
                invariant(!_rIt);
                // This is only called with non-null locations
                invariant(!loc.isNull());
                it = _getPartitionIterator(loc.partitionId());
                advancePartition(loc);
                _savedLoc = RecordId();
            }

            bool isLastPartition() const override {
                return it == _rs._partitions.cend();
            }

            void advancePartition(RecordId loc = RecordId()) override {
                while ((!_rIt || _rIt->isEOF()) && !isLastPartition()) {
                    delete _rIt;
                    _rIt = (*it)->getIterator(_txn, loc);
                    loc = RecordId();
                    ++it;
                }
            }

        public:
            KVRecordIteratorPartitionedForward(const KVRecordStorePartitioned &rs, OperationContext *txn,
                                               const RecordId &start)
                : KVRecordIteratorPartitioned(rs, txn, start),
                  it(rs._partitions.cbegin()) {
                if (!start.isNull()) {
                    it = _getPartitionIterator(start.partitionId());
                }
                advancePartition(start);
            }

        };

        class KVRecordIteratorPartitionedBackward : public KVRecordIteratorPartitioned {
            std::deque<RecordStore*>::const_reverse_iterator it;

            std::deque<RecordStore*>::const_reverse_iterator _getPartitionIterator(int64_t partitionID) const {
                return _rs._getBackwardPartitionIterator(partitionID);
            }

            void setLocation(const RecordId loc) override {
                // This is only called to recover saved state
                // so there should be no record iterator
                invariant(!_rIt);
                // This is only called with non-null locations
                invariant(!loc.isNull());
                it = _getPartitionIterator(loc.partitionId());
                advancePartition(loc);
                _savedLoc = RecordId();
            }

            bool isLastPartition() const override {
                return it == _rs._partitions.crend();
            }

            void advancePartition(RecordId loc = RecordId()) override {
                while ((!_rIt || _rIt->isEOF()) && !isLastPartition()) {
                    invariant(!isLastPartition());
                    delete _rIt;
                    _rIt = (*it)->getIterator(_txn, loc, CollectionScanParams::BACKWARD);
                    loc = RecordId();
                    ++it;
                }
            }

        public:
            KVRecordIteratorPartitionedBackward(const KVRecordStorePartitioned &rs, OperationContext *txn,
                                               const RecordId &start)
                : KVRecordIteratorPartitioned(rs, txn, start),
                  it(rs._partitions.crbegin()) {
                if (!start.isNull()) {
                    it = _getPartitionIterator(start.partitionId());
                }
                advancePartition(start);
            }

        };

    protected:
        // get RecordStore* for given RecordId
        RecordStore* rsForRecordId(const RecordId& loc) const;

        std::deque<RecordStore*>::const_iterator _getForwardPartitionIterator(int64_t partitionID) const;
        std::deque<RecordStore*>::const_reverse_iterator _getBackwardPartitionIterator(int64_t partitionID) const;

        // Locally cached copies of these counters.
        AtomicInt64 _dataSize;
        AtomicInt64 _numRecords;

        // used to create recorstores for partitions
        KVEngineImpl* _kvEngine;
        CollectionOptions _partitionOptions;

        const std::string _ident;

        KVSizeStorer *_sizeStorer;

        // vector storing the ids of the partitions
        std::vector<int64_t> _partitionIDs;

        // owned instances of KVRecordStore for each partition
        std::deque<RecordStore*> _partitions;

    private:
        class DropPartitionChange;
    };

} // namespace mongo
