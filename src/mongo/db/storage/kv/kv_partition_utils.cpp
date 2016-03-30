// kv_partition_utils.cpp

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

#include "mongo/bson/util/builder.h"
#include "mongo/db/storage/kv/kv_partition_utils.h"

namespace mongo {

    std::string getPartitionName(const StringData &ns, int64_t partitionID) {
        mongo::StackStringBuilder ss;
        ss << ns << "$$p" << partitionID;
        return ss.str();
    }

} // namespace mongo
