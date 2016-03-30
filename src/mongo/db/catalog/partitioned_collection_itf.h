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

#pragma once

namespace mongo {

class DocWriter;
class MultiIndexBlock;
class OpDebug;

/**
 * methods which we want to inject into Collection class
 * to support partitioned collections
 */
class PartitionedCollectionItf {
public:
    PartitionedCollectionItf(bool partitioned) : _partitioned(partitioned) {}
    virtual ~PartitionedCollectionItf() {}

    // we need to know if collection is partitioned from functions called from
    // Collection constructor (to decide if we need to create partitioned SDI)
    // This is why isPartititoned is not virtual
    bool isPartitioned() const {
        return _partitioned;
    }

    // initialization

    // called after constructor when collection is created for the first time
    // used to create first partition in partitioned collection
    virtual Status initOnCreate(OperationContext* txn) { return Status::OK(); }

    // called after creating Id index when collection is created for the first time
    // used to create primary key index for partitioned collection
    virtual Status createPkIndexOnEmptyCollection(OperationContext* txn) { return Status::OK(); }

    virtual uint64_t numPartitions() const {
        invariant(false);
        return 0;
    }

    // create new parttiion which never existed before
    virtual Status createPartition(OperationContext* txn) {
        invariant(false);
        return Status(ErrorCodes::InternalError, "createPartition should not be called on non-partitioned collection");
    }
    virtual Status createPartition(OperationContext* txn, const BSONObj& newPivot, const BSONObj &partitionInfo) {
        invariant(false);
        return Status(ErrorCodes::InternalError, "createPartition should not be called on non-partitioned collection");
    }

    // drop partitions
    virtual void dropPartition(OperationContext* txn, int64_t id) {
        invariant(false);
    }
    virtual void dropPartitionsLEQ(OperationContext* txn, const BSONObj &pivot) {
        invariant(false);
    }

    // iterate partition ids (with status)
    virtual Status forEachPartition(const std::function<Status (int64_t id)>& f) const {
        invariant(false);
        return Status(ErrorCodes::InternalError, "forEachPartition should not be called on non-partitioned collection");
    }

    // iterate partition ids (without status)
    virtual void forEachPartition(const std::function<void (int64_t id)>& f) const {
        invariant(false);
    }


    // need to override some methods in PartitionedCollection
    // so here those methods declared as virtual
    virtual StatusWith<RecordId> insertDocument(OperationContext* txn,
                                                const BSONObj& doc,
                                                bool enforceQuota) = 0;

    virtual StatusWith<RecordId> insertDocument(OperationContext* txn,
                                                const DocWriter* doc,
                                                bool enforceQuota) = 0;

    virtual StatusWith<RecordId> insertDocument(OperationContext* txn,
                                                const BSONObj& doc,
                                                MultiIndexBlock* indexBlock,
                                                bool enforceQuota) = 0;

    // need to override updateDocument to handle updates of primary key
    // which move document to another partition
    virtual StatusWith<RecordId> updateDocument(OperationContext* txn,
                                                const RecordId& oldLocation,
                                                const Snapshotted<BSONObj>& objOld,
                                                const BSONObj& objNew,
                                                bool enforceQuota,
                                                bool indexesAffected,
                                                OpDebug* debug) = 0;

private:
    const bool _partitioned;

};

} // namespace mongo
