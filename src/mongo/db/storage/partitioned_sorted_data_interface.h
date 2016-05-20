// partitioned_sorted_data_interface.h

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

#include "mongo/bson/bsonobj.h"

namespace mongo {

    // methods should be overrriden in 'partitioned' descendants
    // methods won't be called on instances of 'non-partitioned' descendants
    class PartitionedSortedDataInterface {
    public:
        virtual ~PartitionedSortedDataInterface() {}

        virtual bool getMaxKeyFromLastPartition(OperationContext* txn, BSONObj &result) const {
            invariant(false);
            return false;
        }

        virtual void createPartition(OperationContext* txn, int64_t id) {
            invariant(false);
        }

        virtual void dropPartition(OperationContext* txn, int64_t id) {
            invariant(false);
        }
    };

} // namespace mongo
