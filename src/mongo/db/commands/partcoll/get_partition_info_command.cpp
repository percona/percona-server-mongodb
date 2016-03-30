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

#include "mongo/db/auth/action_type.h"
#include "mongo/db/catalog/collection.h"
#include "mongo/db/catalog/collection_catalog_entry.h"
#include "mongo/db/catalog/partitioned_collection.h"
#include "mongo/db/client.h"
#include "mongo/db/commands.h"

#include "get_partition_info_command.h"

namespace mongo {
    namespace partcoll {
        GetPartitionInfoCommand::GetPartitionInfoCommand()
            : PartitionCommandBase("getPartitionInfo") {}

        void GetPartitionInfoCommand::addRequiredPrivileges(const std::string& dbname,
                                                          const BSONObj& cmdObj,
                                                          std::vector<Privilege>* out) {
            ActionSet actions;
            actions.addAction(ActionType::getPartitionInfo);
            out->push_back(Privilege(parseResourcePattern(dbname, cmdObj), actions));
        }

        void GetPartitionInfoCommand::help(std::stringstream &h) const {
            h << "get partition information, returns BSON with number of partitions and array\n" <<
                "of partition info.\n" <<
                "Example: {getPartitionInfo:\"foo\"}";
        }

        bool GetPartitionInfoCommand::run(mongo::OperationContext* txn,
                                        const std::string &db,
                                        BSONObj &cmdObj,
                                        int options,
                                        std::string &errmsg,
                                        BSONObjBuilder &result,
                                        bool fromRepl) {
            if (!this->currentEngineSupportsPartitionedCollections()) {
                this->printEngineSupportFailure(errmsg);
                return false;
            }

            BSONElement first = cmdObj.firstElement();
            uassert(19172,
                    str::stream() << "Argument to getPartitionInfo must be of type String, not "
                                  << typeName(first.type()),
                    first.type() == String);
            const NamespaceString ns(parseNs(db, cmdObj));
            uassert(19173, "Argument to getPartitionInfo must be a collection name, not the empty string",
                    !ns.coll().empty());

            AutoGetCollectionForRead autoColl(txn, ns);
            if (!autoColl.getDb()) {
                return appendCommandStatus(result,
                                           Status(ErrorCodes::NamespaceNotFound, "no database"));
            }

            const Collection* collection = autoColl.getCollection();
            if (!collection) {
                return appendCommandStatus(result,
                                           Status(ErrorCodes::NamespaceNotFound, "no collection"));
            }

            uassert(19174, "collection must be partitioned", collection->isPartitioned() );

            uint64_t numPartitions = 0;
            BSONArray arr;
            collection->getCatalogEntry()->getPartitionInfo(txn, &numPartitions, &arr);
            result.append("numPartitions", (long long)numPartitions);
            result.append("partitions", arr);
            return true;
        }

    }

    partcoll::GetPartitionInfoCommand getPartitionInfo;
}
