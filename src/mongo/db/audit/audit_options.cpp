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

#define MONGO_LOG_DEFAULT_COMPONENT ::mongo::logger::LogComponent::kAccessControl

#include <boost/filesystem/path.hpp>

#include "mongo/base/status.h"
#include "mongo/db/server_options.h"
#include "mongo/db/json.h"
#include "mongo/util/file.h"
#include "mongo/util/log.h"
#include "mongo/util/mongoutils/str.h"
#include "mongo/util/options_parser/startup_option_init.h"
#include "mongo/util/options_parser/startup_options.h"

#include "audit_options.h"

namespace mongo {

    AuditOptions auditOptions;

    AuditOptions::AuditOptions():
        format("JSON"),
        filter("{}")
    {
    }

    BSONObj AuditOptions::toBSON() {
        return BSON("format" << format <<
                    "path" << path <<
                    "destination" << destination <<
                    "filter" << filter);
    }

    Status addAuditOptions(optionenvironment::OptionSection* options) {
        optionenvironment::OptionSection auditOptions("Audit Options");

        auditOptions.addOptionChaining("auditLog.destination", "auditDestination", optionenvironment::String,
                "Output type: enables auditing functionality",
                "audit.destination");

        auditOptions.addOptionChaining("auditLog.format", "auditFormat", optionenvironment::String,
                "Output format",
                "audit.format");

        auditOptions.addOptionChaining("auditLog.filter", "auditFilter", optionenvironment::String,
                "JSON query filter on events, users, etc.",
                "audit.filter");

        auditOptions.addOptionChaining("auditLog.path", "auditPath", optionenvironment::String,
                "Event destination file path and name",
                "audit.path");

        Status ret = options->addSection(auditOptions);
        if (!ret.isOK()) {
            log() << "Failed to add audit option section: " << ret.toString();
            return ret;
        }

        return Status::OK();
    }

    Status storeAuditOptions(const optionenvironment::Environment& params) {
        if (params.count("auditLog.destination")) {
            auditOptions.destination =
                params["auditLog.destination"].as<std::string>();
        }
        if (auditOptions.destination != "") {
            if (auditOptions.destination != "file" &&
                auditOptions.destination != "console" &&
                auditOptions.destination != "syslog") {
                return Status(ErrorCodes::BadValue,
                              "Supported audit log destinations are 'file', 'console', 'syslog'");
            }
        }

        if (params.count("auditLog.format")) {
            auditOptions.format =
                params["auditLog.format"].as<std::string>();
        }
        if (auditOptions.format != "JSON" && auditOptions.format != "BSON") {
            return Status(ErrorCodes::BadValue,
                          "Supported audit log formats are 'JSON' and 'BSON'");
        }
        if (auditOptions.format == "BSON" && auditOptions.destination != "file") {
            return Status(ErrorCodes::BadValue,
                          "BSON audit log format is only allowed when audit log destination is a 'file'");
        }

        if (params.count("auditLog.filter")) {
            auditOptions.filter =
                params["auditLog.filter"].as<std::string>();
        }
        try {
            fromjson(auditOptions.filter);
        }
        catch (const std::exception &ex) {
            return Status(ErrorCodes::BadValue,
                          "Could not parse audit filter into valid json: "
                          + auditOptions.filter);
        }

        if (params.count("auditLog.path")) {
            auditOptions.path =
                params["auditLog.path"].as<std::string>();
        }
        if (auditOptions.path != "") {
            File auditFile;
            auditFile.open(auditOptions.path.c_str(), false, false);
            if (auditFile.bad()) {
                return Status(ErrorCodes::BadValue,
                              "Could not open a file for writing at the given auditPath: "
                              + auditOptions.path);
            }
        } else if (!serverGlobalParams.logWithSyslog && !serverGlobalParams.logpath.empty()) {
            auditOptions.path =
                (boost::filesystem::path(serverGlobalParams.logpath).parent_path() / "auditLog.json").native();
        // storageGlobalParams is not available in mongos    
        //} else if (!storageGlobalParams.dbpath.empty()) {
        //    auditOptions.path =
        //        (boost::filesystem::path(storageGlobalParams.dbpath) / "auditLog.json").native();
        //}
        } else {
            auditOptions.path =
                (boost::filesystem::path(serverGlobalParams.cwd) / "auditLog.json").native();
        }

        return Status::OK();
    }

    MONGO_MODULE_STARTUP_OPTIONS_REGISTER(AuditOptions)(InitializerContext* context) {
        return addAuditOptions(&optionenvironment::startupOptions);
    }

    MONGO_STARTUP_OPTIONS_STORE(AuditOptions)(InitializerContext* context) {
        return storeAuditOptions(optionenvironment::startupOptionsParsed);
    }

} // namespace mongo
