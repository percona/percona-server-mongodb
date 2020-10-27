/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2019-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/db/ldap_options.h"
#include "mongo/db/ldap_options_gen.h"

#include "mongo/base/status.h"
#include "mongo/util/options_parser/startup_options.h"

namespace mongo {

Status storeLDAPOptions(const moe::Environment& params) {
    if (params.count("security.ldap.servers")) {
        ldapGlobalParams.ldapServers = params["security.ldap.servers"].as<std::string>();
    }
    if (params.count("security.ldap.transportSecurity")) {
        ldapGlobalParams.ldapTransportSecurity = params["security.ldap.transportSecurity"].as<std::string>();
    }
    if (params.count("security.ldap.bind.method")) {
        ldapGlobalParams.ldapBindMethod = params["security.ldap.bind.method"].as<std::string>();
    }
    if (params.count("security.ldap.bind.saslMechanisms")) {
        ldapGlobalParams.ldapBindSaslMechanisms = params["security.ldap.bind.saslMechanisms"].as<std::string>();
    }
    if (params.count("security.ldap.timeoutMS")) {
        ldapGlobalParams.ldapTimeoutMS.store(params["security.ldap.timeoutMS"].as<int>());
    }
    if (params.count("security.ldap.bind.queryUser")) {
        ldapGlobalParams.ldapQueryUser = params["security.ldap.bind.queryUser"].as<std::string>();
    }
    if (params.count("security.ldap.bind.queryPassword")) {
        ldapGlobalParams.ldapQueryPassword = params["security.ldap.bind.queryPassword"].as<std::string>();
    }
    if (params.count("security.ldap.userToDNMapping")) {
        ldapGlobalParams.ldapUserToDNMapping = params["security.ldap.userToDNMapping"].as<std::string>();
    }
    return Status::OK();
}

MONGO_INITIALIZER_GENERAL(StoreLDAPOptions, ("CoreOptions_Store"), ("EndStartupOptionStorage"))
(InitializerContext* const context) {
    return storeLDAPOptions(moe::startupOptionsParsed);
}
}  // namespace mongo 
