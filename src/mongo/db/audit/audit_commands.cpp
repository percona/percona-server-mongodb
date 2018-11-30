/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
// vim: ft=cpp:expandtab:ts=8:sw=4:softtabstop=4:

/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2018-present Percona and/or its affiliates. All rights reserved.

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


#include <cstdio>
#include <iostream>
#include <string>

#include "mongo/base/init.h"
#include "mongo/bson/bson_field.h"
#include "mongo/db/audit.h"
#include "mongo/db/auth/authorization_manager.h"
#include "mongo/db/client.h"
#include "mongo/db/commands.h"
#include "mongo/db/commands/test_commands_enabled.h"
#include "mongo/db/jsobj.h"
#include "mongo/db/namespace_string.h"
#include "mongo/util/mongoutils/str.h"

#include "audit_options.h"

namespace mongo {

    class AuditCommand : public ErrmsgCommandDeprecated {
    public:
        AuditCommand(const char *name, const char *oldName=NULL) : ErrmsgCommandDeprecated(name, oldName) {}
        virtual ~AuditCommand() {}
        // TODO: Investigate if any other Command class virtual
        // methods need to be overridden.
        virtual bool isWriteCommandForConfigServer() const { return false; }
        virtual AllowedOnSecondary secondaryAllowed(ServiceContext* context) const override {
            return AllowedOnSecondary::kAlways;
        }
        virtual bool supportsWriteConcern(const BSONObj& cmd) const { return false; }
    };

    class LogApplicationMessageCommand : public AuditCommand {
    public:
        LogApplicationMessageCommand() : AuditCommand("logApplicationMessage") { }
        virtual ~LogApplicationMessageCommand() { }
        virtual std::string help() const override {
            return "Log a custom application message string to the audit log. Must be a string."
                   "Example: { logApplicationMessage: \"it's a trap!\" }";
        }

        virtual void addRequiredPrivileges(const std::string& dbname,
                                           const BSONObj& cmdObj,
                                           std::vector<Privilege>* out) const override {
            ActionSet actions;
            actions.addAction(ActionType::logApplicationMessage);

            // TODO: Investigate if using the 'normal resource'
            // pattern of the new ResourcePattern API matches our
            // original use of SERVER_RESOURCE_NAME. We may want
            // to use somethine scoped to the given database name.
            out->push_back(Privilege(ResourcePattern::forAnyNormalResource(), actions));
        }

        bool errmsgRun(OperationContext* txn, const std::string& dbname, const BSONObj& jsobj, std::string& errmsg, BSONObjBuilder& result) override {
            bool ok = true;
            const BSONElement &e = jsobj["logApplicationMessage"];

            if (e.type() == String) {
                audit::logApplicationMessage(Client::getCurrent(), e.checkAndGetStringData());
            } else {
                errmsg = "logApplicationMessage only accepts string messages";
                ok = false;
            }
            result.append("ok", ok);
            return ok;
        }
    } cmdLogApplicationMessage;

    class AuditGetOptionsCommand : public AuditCommand {
    public:
        AuditGetOptionsCommand() : AuditCommand("auditGetOptions") { }
        virtual ~AuditGetOptionsCommand() { }
        virtual std::string help() const override {
            return "Get the options the audit system is currently using"
                   "Example: { auditGetOptions: 1 }";
        }

        virtual void addRequiredPrivileges(const std::string& dbname,
                                           const BSONObj& cmdObj,
                                           std::vector<Privilege>* out) const override { }

        bool errmsgRun(OperationContext* txn, const std::string& dbname, const BSONObj& jsobj, std::string& errmsg, BSONObjBuilder& result) override {
            result.appendElements(auditOptions.toBSON());
            return true;
        }
    };

    // so tests can determine where the audit log lives
    MONGO_INITIALIZER(RegisterAuditGetOptionsCommand)(InitializerContext* context) {
        if (getTestCommandsEnabled()) {
            // Leaked intentionally: a Command registers itself when constructed.
            new AuditGetOptionsCommand();
        }

        return Status::OK();
    }

}  // namespace mongo
