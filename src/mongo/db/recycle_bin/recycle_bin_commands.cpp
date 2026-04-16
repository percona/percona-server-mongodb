/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2026-present Percona and/or its affiliates. All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the Server Side Public License, version 1,
    as published by MongoDB, Inc.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Server Side Public License for more details.

    You should have received a copy of the Server Side Public License
    along with this program. If not, see
    <http://www.mongodb.com/licensing/server-side-public-license>.

    As a special exception, the copyright holders give permission to link the
    code of portions of this program with the OpenSSL library under certain
    conditions as described in each individual source file and distribute
    linked combinations including the program with the OpenSSL library. You
    must comply with the Server Side Public License in all respects for
    all of the code used other than as permitted herein. If you modify file(s)
    with this exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do so,
    delete this exception statement from your version. If you delete this
    exception statement from all source files in the program, then also delete
    it in the license file.
======= */

#include "mongo/db/auth/action_type.h"
#include "mongo/db/auth/authorization_session.h"
#include "mongo/db/commands.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/recycle_bin/recycle_bin.h"

namespace mongo {
namespace {

class CmdUndeleteCollection : public BasicCommand {
public:
    CmdUndeleteCollection() : BasicCommand("undeleteCollection") {}

    std::string help() const override {
        return "Restores a collection from the recycle bin.\n"
               "{ undeleteCollection: '<full_recycle_bin_ns>' }\n"
               "  e.g. { undeleteCollection: 'mydb.system.recycle_bin.mycoll.1713260000' }\n"
               "Optional field 'restoreAs' to specify a different target namespace:\n"
               "  { undeleteCollection: 'mydb.system.recycle_bin.mycoll.1713260000', "
               "restoreAs: 'mydb.mycoll_restored' }";
    }

    bool adminOnly() const override {
        return true;
    }

    AllowedOnSecondary secondaryAllowed(ServiceContext*) const override {
        return AllowedOnSecondary::kNever;
    }

    bool supportsWriteConcern(const BSONObj& cmd) const override {
        return true;
    }

    Status checkAuthForOperation(OperationContext* opCtx,
                                 const DatabaseName&,
                                 const BSONObj& cmdObj) const override {
        auto nsStr = cmdObj.firstElement().String();
        auto nss = NamespaceString::createNamespaceString_forTest(boost::none, nsStr);
        return AuthorizationSession::get(opCtx->getClient())
                       ->isAuthorizedForActionsOnNamespace(nss, ActionType::dropCollection)
                   ? Status::OK()
                   : Status(ErrorCodes::Unauthorized, "Unauthorized");
    }

    bool run(OperationContext* opCtx,
             const DatabaseName&,
             const BSONObj& cmdObj,
             BSONObjBuilder& result) override {
        auto nsStr = cmdObj.firstElement().String();
        auto recycleBinNss =
            NamespaceString::createNamespaceString_forTest(boost::none, nsStr);

        boost::optional<NamespaceString> restoreAs;
        if (cmdObj.hasField("restoreAs")) {
            restoreAs = NamespaceString::createNamespaceString_forTest(
                boost::none, cmdObj["restoreAs"].String());
        }

        auto status = recycleBinRestore(opCtx, recycleBinNss, restoreAs);
        uassertStatusOK(status);

        auto parsed = parseRecycleBinNss(recycleBinNss);
        if (parsed) {
            if (restoreAs) {
                result.append("restoredNs", restoreAs->toStringForErrorMsg());
            } else {
                auto targetNss = NamespaceString::createNamespaceString_forTest(
                    recycleBinNss.dbName(), parsed->originalCollection);
                result.append("restoredNs", targetNss.toStringForErrorMsg());
            }
        }

        return true;
    }
};
MONGO_REGISTER_COMMAND(CmdUndeleteCollection).forShard();

class CmdListRecycleBin : public BasicCommand {
public:
    CmdListRecycleBin() : BasicCommand("listRecycleBin") {}

    std::string help() const override {
        return "Lists collections in the recycle bin.\n"
               "{ listRecycleBin: '<dbname>' }\n"
               "  Use { listRecycleBin: '' } to list across all databases.";
    }

    bool adminOnly() const override {
        return true;
    }

    AllowedOnSecondary secondaryAllowed(ServiceContext*) const override {
        return AllowedOnSecondary::kAlways;
    }

    bool supportsWriteConcern(const BSONObj& cmd) const override {
        return false;
    }

    Status checkAuthForOperation(OperationContext* opCtx,
                                 const DatabaseName&,
                                 const BSONObj&) const override {
        return AuthorizationSession::get(opCtx->getClient())
                       ->isAuthorizedForActionsOnResource(
                           ResourcePattern::forClusterResource(boost::none),
                           ActionType::listDatabases)
                   ? Status::OK()
                   : Status(ErrorCodes::Unauthorized, "Unauthorized");
    }

    bool run(OperationContext* opCtx,
             const DatabaseName&,
             const BSONObj& cmdObj,
             BSONObjBuilder& result) override {
        auto dbStr = cmdObj.firstElement().String();

        DatabaseName filterDb;
        if (!dbStr.empty()) {
            filterDb = DatabaseName::createDatabaseName_forTest(boost::none, dbStr);
        }

        auto entries = recycleBinList(opCtx, filterDb);

        BSONArrayBuilder arrBuilder(result.subarrayStart("collections"));
        for (const auto& entry : entries) {
            BSONObjBuilder entryBuilder(arrBuilder.subobjStart());
            entryBuilder.append("ns", entry.recycleBinNss.toStringForErrorMsg());
            entryBuilder.append("originalCollection", entry.originalCollection);
            entryBuilder.append("db", entry.db);
            entryBuilder.append("dropTime", entry.dropTimeSecs);
            entryBuilder.done();
        }
        arrBuilder.done();

        return true;
    }
};
MONGO_REGISTER_COMMAND(CmdListRecycleBin).forShard();

}  // namespace
}  // namespace mongo
