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

#include <boost/filesystem/path.hpp>
#include <boost/filesystem/operations.hpp>

#include <fstream>

#include "mongo/base/status.h"
#include "mongo/db/audit/audit_options_gen.h"
#include "mongo/db/server_options.h"
#include "mongo/db/json.h"
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

        return Status::OK();
    }

    Status validateAuditOptions() {
        if (auditOptions.destination != "file") {
            // no validation needed if audit is disabled or destination is not to a file
            return Status::OK();
        }

        auto getAbsolutePath = [](auto const& p) {
            return boost::filesystem::absolute(p, serverGlobalParams.cwd).native();
        };

        auto isWritable = [](const std::string& path) -> bool {
            // Check if the file is writable by trying to open it for appending.
            const bool exists = boost::filesystem::exists(path);
            std::ofstream testFile(path.c_str(), std::ios_base::app);
            const bool writable = testFile.is_open();
            if (writable) {
                testFile.close();

                if (!exists) {
                    // If the file didn't exist, remove it
                    boost::filesystem::remove(path);
                }
            }

            return writable;
        };

        if (!auditOptions.path.empty()) {
            auditOptions.path = getAbsolutePath(auditOptions.path);
        } else {
            const std::string defaultFilePath =
                (auditOptions.format == "BSON") ? "auditLog.bson" : "auditLog.json";

            const bool useLogPathBase =
                !serverGlobalParams.logWithSyslog && !serverGlobalParams.logpath.empty();

            const auto base = useLogPathBase
                ? boost::filesystem::path(serverGlobalParams.logpath).parent_path()
                : boost::filesystem::path();

            auditOptions.path = getAbsolutePath(base / defaultFilePath);
        }

        if (!isWritable(auditOptions.path)) {
            return Status(ErrorCodes::BadValue,
                          "Could not open a file for writing at the given auditPath: " +
                              auditOptions.path);
        }

        return Status::OK();
    }

    MONGO_MODULE_STARTUP_OPTIONS_REGISTER(AuditOptions)(InitializerContext* context) {
        uassertStatusOK(addAuditOptions(&optionenvironment::startupOptions));
    }

    MONGO_STARTUP_OPTIONS_STORE(AuditOptions)(InitializerContext* context) {
        uassertStatusOK(storeAuditOptions(optionenvironment::startupOptionsParsed));
    }

    // Can't use MONGO_STARTUP_OPTIONS_VALIDATE here as we need serverGlobalParams
    // to be already initialized.
    MONGO_INITIALIZER_GENERAL(AuditOptionsPath_Validate, ("EndStartupOptionHandling"), ("default"))
    (InitializerContext*) {
        uassertStatusOK(validateAuditOptions());
    }
} // namespace mongo
