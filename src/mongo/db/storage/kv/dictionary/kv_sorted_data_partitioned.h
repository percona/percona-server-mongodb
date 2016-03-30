// kv_sorted_data_partitioned.h

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

#pragma once

#include "mongo/db/storage/sorted_data_interface.h"

namespace mongo {

    class IndexDescriptor;
    class KVEngineImpl;

    /**
     * Dummy implementation for now.  We'd need a KVDictionaryBuilder to
     * do better, let's worry about that later.
     */
    class KVSortedDataBuilder : public SortedDataBuilderInterface {
        SortedDataInterface *_impl;
        OperationContext *_txn;
        WriteUnitOfWork _wuow;
        bool _dupsAllowed;

    public:
        KVSortedDataBuilder(SortedDataInterface *impl, OperationContext *txn, bool dupsAllowed)
            : _impl(impl),
              _txn(txn),
              _wuow(txn),
              _dupsAllowed(dupsAllowed)
        {}
        virtual Status addKey(const BSONObj& key, const RecordId& loc) override {
            return _impl->insert(_txn, key, loc, _dupsAllowed);
        }
        virtual void commit(bool mayInterrupt) override {
            _wuow.commit();
        }
    };

    /**
     * Implementation of SortedDataInterface for partitioned collections
     */
    class KVSortedDataPartitioned : public SortedDataInterface {
        MONGO_DISALLOW_COPYING( KVSortedDataPartitioned );

        friend class KVSDIPartitionedCursor;

    public:
        KVSortedDataPartitioned( OperationContext* opCtx, KVEngineImpl* kvEngine, const StringData& ident, const IndexDescriptor *desc );

        virtual ~KVSortedDataPartitioned() override;

        virtual SortedDataBuilderInterface* getBulkBuilder(OperationContext* txn, bool dupsAllowed) override;

        virtual Status insert(OperationContext* txn,
                              const BSONObj& key,
                              const RecordId& loc,
                              bool dupsAllowed) override;

        virtual void unindex(OperationContext* txn, const BSONObj& key, const RecordId& loc, bool dupsAllowed) override;

        virtual Status dupKeyCheck(OperationContext* txn, const BSONObj& key, const RecordId& loc) override;

        virtual void fullValidate(OperationContext* txn, bool full, long long* numKeysOut,
                                  BSONObjBuilder* output) const override;

        virtual bool isEmpty(OperationContext* txn) override;

        virtual long long numEntries(OperationContext* txn) const override;

        virtual Cursor* newCursor(OperationContext* txn, int direction = 1) const override;

        virtual Status initAsEmpty(OperationContext* txn) override;

        virtual long long getSpaceUsedBytes( OperationContext* txn ) const override;

        virtual bool appendCustomStats(OperationContext* txn, BSONObjBuilder* output, double scale) const override;

        // additional methods for partitoned collections

        bool getMaxKeyFromLastPartition(OperationContext* txn, BSONObj &result) const override;

        void createPartition(OperationContext* txn, int64_t id) override;

        void dropPartition(OperationContext* txn, int64_t id) override;

    private:
        const Ordering _ordering;

        // get SortedDataInterface* for given RecordId
        SortedDataInterface* ptnForRecordId(const RecordId& loc) const;

        // used to create/drop idents
        KVEngineImpl* _kvEngine;
        const IndexDescriptor* _desc;
        const BSONObj _keyPattern;
        const BSONObj _options;

        const std::string _ident;

        // vector storing the ids of the partitions
        std::vector<int64_t> _partitionIDs;

        // owned instances of KVSortedDataImpl for each partition
        std::deque<SortedDataInterface*> _partitions;

    private:
        class DropPartitionChange;
    };

} // namespace mongo
