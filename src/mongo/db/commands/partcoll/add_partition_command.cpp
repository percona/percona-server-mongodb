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
#include "mongo/db/catalog/collection_catalog_entry.h"
#include "mongo/db/catalog/partitioned_collection.h"
#include "mongo/db/client.h"
#include "mongo/db/commands.h"
#include "mongo/db/ops/insert.h"
#include "mongo/db/repl/oplog.h"
#include "mongo/db/repl/replication_coordinator_global.h"

#include "add_partition_command.h"

#include "mongo/bson/bsonclone.h"

namespace mongo {
    namespace partcoll {
        AddPartitionCommand::AddPartitionCommand()
            : PartitionCommandBase("addPartition") {}

        void AddPartitionCommand::addRequiredPrivileges(const std::string& dbname,
                                                          const BSONObj& cmdObj,
                                                          std::vector<Privilege>* out) {
            ActionSet actions;
            actions.addAction(ActionType::addPartition);
            out->push_back(Privilege(parseResourcePattern(dbname, cmdObj), actions));
        }

        void AddPartitionCommand::help(std::stringstream &h) const {
            h << "add partition to a partitioned collection,\n" <<
                "optionally provide pivot for last current partition\n." <<
                "Example: {addPartition : \"foo\"} or {addPartition: \"foo\", newMax: {_id: 1000}}";
        }

        bool AddPartitionCommand::run(mongo::OperationContext* txn,
                                        const std::string &dbname,
                                        BSONObj &cmdObj,
                                        int options,
                                        std::string &errmsg,
                                        BSONObjBuilder &result,
                                        bool fromRepl) {
            if (!this->currentEngineSupportsPartitionedCollections()) {
                this->printEngineSupportFailure(errmsg);
                return false;
            }

            std::string coll = cmdObj[ "addPartition" ].valuestrsafe();
            uassert( 19179, "addPartition must specify a collection", !coll.empty() );
            std::string ns = dbname + "." + coll;
            BSONElement force = cmdObj["force"];
            bool isOplogNS = (strcmp(ns.c_str(), repl::rsoplog) == 0);
            uassert( 19180, "cannot manually add partition on oplog", force.trueValue() || !isOplogNS);

            ScopedTransaction transaction(txn, MODE_IX);
            AutoGetDb autoDb(txn, dbname, MODE_X);

            if (!fromRepl &&
                !repl::getGlobalReplicationCoordinator()->canAcceptWritesForDatabase(dbname)) {
                return appendCommandStatus(result,
                                           Status(ErrorCodes::NotMaster,
                                                  str::stream()
                                                      << "Not primary while adding partition to " << ns));
            }

            Database* const db = autoDb.getDb();

            if (!db) {
                return appendCommandStatus(result,
                                           Status(ErrorCodes::NamespaceNotFound,
                                                  str::stream() << "database " << dbname << " does not exist"));
            }

            Collection *cl = db->getCollection( ns );
            uassert( 19181, "addPartition no such collection", cl );
            uassert( 19182, "collection must be partitioned", cl->isPartitioned() );
            BSONElement pivotElement = cmdObj["newMax"];
            BSONElement infoElement = cmdObj["info"];
            WriteUnitOfWork wunit(txn);
            if (pivotElement.ok()) {
                BSONObj pivot = pivotElement.embeddedObjectUserCheck();
                fixDocumentForInsert(pivot);
                cl->createPartition(txn, pivot, infoElement.ok() ? infoElement.embeddedObjectUserCheck() : BSONObj());
            }
            else {
                cl->createPartition(txn);
            }
            // now that we have added the partition, take care of the oplog
            uint64_t numPartitions = cl->numPartitions();
            massert(19183, str::stream() << "bad numPartitions after adding a partition " << numPartitions, numPartitions > 1);

            if (!fromRepl) {
                uint64_t numPartitions;
                BSONArray partitionArray;
                cl->getCatalogEntry()->getPartitionInfo(txn, &numPartitions, &partitionArray);
                std::vector<BSONElement> v;
                partitionArray.elems(v);

                // now we need to log this thing for replication
                BSONObj cmdWithPivot;
                if (!pivotElement.ok()) {
                    // add the pivot
                    BSONObjBuilder bPivot;
                    BSONObj o = v[numPartitions-2].Obj();
                    cloneBSONWithFieldChanged(bPivot, cmdObj, "newMax", o["max"].Obj(), true);
                    cmdWithPivot = bPivot.obj();
                }
                else {
                    cmdWithPivot = cmdObj;
                }
                BSONObj cmdWithInfo;
                if (!infoElement.ok()) {
                    BSONObjBuilder bInfo;
                    cloneBSONWithFieldChanged(bInfo, cmdWithPivot, "info", v[numPartitions-1].Obj(), true);
                    cmdWithInfo = bInfo.obj();
                }
                else {
                    cmdWithInfo = cmdWithPivot;
                }
                std::string logNs = dbname + ".$cmd";
                repl::logOp(txn, "c", logNs.c_str(), cmdWithInfo);
            }
            wunit.commit();
            return true;
        }

    }

    partcoll::AddPartitionCommand addPartition;
}
