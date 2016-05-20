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
#include "mongo/db/background.h"
#include "mongo/db/catalog/partitioned_collection.h"
#include "mongo/db/client.h"
#include "mongo/db/commands.h"
#include "mongo/db/curop.h"
#include "mongo/db/concurrency/write_conflict_exception.h"
#include "mongo/db/ops/insert.h"
#include "mongo/db/repl/oplog.h"
#include "mongo/db/repl/replication_coordinator_global.h"

#include "drop_partition_command.h"

namespace mongo {
    namespace partcoll {
        DropPartitionCommand::DropPartitionCommand()
            : PartitionCommandBase("dropPartition") {}

        void DropPartitionCommand::addRequiredPrivileges(const std::string& dbname,
                                                          const BSONObj& cmdObj,
                                                          std::vector<Privilege>* out) {
            ActionSet actions;
            actions.addAction(ActionType::dropPartition);
            out->push_back(Privilege(parseResourcePattern(dbname, cmdObj), actions));
        }

        void DropPartitionCommand::help(std::stringstream &h) const {
            h << "drop partition with id retrieved from getPartitionInfo command\n" <<
                "Example: {dropPartition: foo, id: 5}";
        }

        bool DropPartitionCommand::run(mongo::OperationContext* txn,
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

            const std::string nsToDrop = parseNsCollectionRequired(dbname, cmdObj);
            const std::string coll = cmdObj[ "dropPartition" ].valuestrsafe();
            uassert( 19184, "dropPartition must specify a collection", !coll.empty() );
            std::string ns = dbname + "." + coll;
            BSONElement force = cmdObj["force"];
            bool isOplogNS = (strcmp(ns.c_str(), repl::rsoplog) == 0);
            uassert( 19185, "cannot manually drop partition on oplog or oplog.refs",
                    force.trueValue() || !isOplogNS);

            MONGO_WRITE_CONFLICT_RETRY_LOOP_BEGIN {
                ScopedTransaction transaction(txn, MODE_IX);
                AutoGetDb autoDb(txn, dbname, MODE_X);

                Client::Context context(txn, nsToDrop);
                if (!fromRepl &&
                    !repl::getGlobalReplicationCoordinator()->canAcceptWritesForDatabase(dbname)) {
                    return appendCommandStatus(result,
                                               Status(ErrorCodes::NotMaster,
                                                      str::stream()
                                                          << "Not primary while dropping partition of " << ns));
                }

                Database* const db = autoDb.getDb();

                if (!db) {
                    return appendCommandStatus(result,
                                               Status(ErrorCodes::NamespaceNotFound,
                                                      str::stream() << "database " << dbname << " does not exist"));
                }

                Collection *cl = db->getCollection( ns );
                uassert( 19186, "dropPartition no such collection", cl );
                uassert( 19187, "collection must be partitioned", cl->isPartitioned() );

                BackgroundOperation::assertNoBgOpInProgForNs(nsToDrop);

                BSONElement idElem = cmdObj["id"];
                BSONElement maxElem = cmdObj["max"];
                WriteUnitOfWork wunit(txn);
                if (idElem.ok() ==  maxElem.ok()) {
                    errmsg = "must provide either an id or a max key of data to be dropped";
                    return false;
                }
                else if (idElem.ok()) {
                    if (!idElem.isNumber()) {
                        errmsg = "invalid id";
                        return false;
                    }
                    int64_t partitionID = idElem.numberLong();
                    cl->dropPartition(txn, partitionID);
                }
                else {
                    verify(maxElem.ok());
                    BSONObj pivot = maxElem.embeddedObjectUserCheck();
                    fixDocumentForInsert(pivot);
                    cl->dropPartitionsLEQ(txn, pivot);
                }

                if (!fromRepl) {
                    repl::logOp(txn, "c", (dbname + ".$cmd").c_str(), cmdObj);
                }
                wunit.commit();
            }
            MONGO_WRITE_CONFLICT_RETRY_LOOP_END(txn, "dropPartition", nsToDrop);
            return true;
        }

    }

    partcoll::DropPartitionCommand dropPartition;
}
