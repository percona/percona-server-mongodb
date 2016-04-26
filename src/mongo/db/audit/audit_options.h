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

#include <string>

#include "mongo/base/status.h"

namespace mongo {

namespace optionenvironment {
    class OptionSection;
    class Environment;
} // namespace optionenvironment

    struct AuditOptions {

        // Output type: enables auditing functionality, eg 'file'
        std::string destination;

        // Output format, 'eg JSON'
        std::string format;

        // JSON query filter on events, users, etc.
        // Filter query for audit events.
        // eg "{ atype: { $in: [ 'authenticate', 'dropDatabase' ] } }"
        std::string filter;

        // Event destination file path and name, eg '/data/db/audit.json'
        std::string path;

        // Determines if Authz operations with status success are logged
        static std::atomic<bool> auditAuthorized;

        AuditOptions();
        BSONObj toBSON();
    };

    extern AuditOptions auditOptions;

    Status addAuditOptions(optionenvironment::OptionSection* options);

    Status storeAuditOptions(const optionenvironment::Environment& params);

} // namespace mongo
