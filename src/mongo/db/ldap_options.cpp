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

#define MONGO_LOG_DEFAULT_COMPONENT ::mongo::logger::LogComponent::kAccessControl

#include "mongo/db/ldap_options.h"

#include "mongo/base/status.h"
#include "mongo/db/server_parameters.h"
#include "mongo/util/log.h"
#include "mongo/util/options_parser/environment.h"
#include "mongo/util/options_parser/option_section.h"
#include "mongo/util/options_parser/startup_option_init.h"
#include "mongo/util/options_parser/startup_options.h"

namespace mongo {

LDAPGlobalParams ldapGlobalParams;

Status addLDAPOptions(moe::OptionSection* options) {

    options
        ->addOptionChaining("security.ldap.servers",
                           "ldapServers",
                           moe::String,
                           "Comma separated list of LDAP servers in"
                           "format host:port")
        .setSources(moe::SourceYAMLCLI);

    options
        ->addOptionChaining("security.ldap.transportSecurity",
                           "ldapTransportSecurity",
                           moe::String,
                           "Default is tls to use TLS secured connection to LDAP server. "
                           "To disable it use none")
        .setSources(moe::SourceYAMLCLI)
        .format("(:?none)|(:?tls)", "(none/tls)")
        .setDefault(moe::Value{"tls"});

    options
        ->addOptionChaining("security.ldap.bind.method",
                           "ldapBindMethod",
                           moe::String,
                           "The method used to authenticate to an LDAP server. "
                           "simple or sasl. Default is simple")
        .setSources(moe::SourceYAMLCLI)
        .format("(:?simple)|(:?sasl)", "(simple/sasl)")
        .setDefault(moe::Value{"simple"});

    options
        ->addOptionChaining("security.ldap.bind.saslMechanisms",
                           "ldapBindSaslMechanisms",
                           moe::String,
                           "Comma-separated list of SASL mechanisms which can be used "
                           "to authenticate to an LDAP server. Default is DIGEST-MD5")
        .setSources(moe::SourceYAMLCLI)
        .setDefault(moe::Value{"DIGEST-MD5"});

    options
        ->addOptionChaining("security.ldap.timeoutMS",
                           "ldapTimeoutMS",
                           moe::Int,
                           "Timeout to wait for response from LDAP server in millisecons. "
                           "Default is 10000")
        .setSources(moe::SourceYAMLCLI)
        .setDefault(moe::Value{10000});

    options
        ->addOptionChaining("security.ldap.bind.queryUser",
                           "ldapQueryUser",
                           moe::String,
                           "LDAP user used to connect or query LDAP server")
        .setSources(moe::SourceYAMLCLI);

    options
        ->addOptionChaining("security.ldap.bind.queryPassword",
                           "ldapQueryPassword",
                           moe::String,
                           "Password used with queryUser to bind to an LDAP server")
        .setSources(moe::SourceYAMLCLI);

    options
        ->addOptionChaining("security.ldap.userToDNMapping",
                           "ldapUserToDNMapping",
                           moe::String,
                           "Provides mechanism to transform authenticated user name "
                           "to a LDAP Distinguished Name (DN)")
        .setSources(moe::SourceYAMLCLI)
        .setDefault(moe::Value{"[{match: \"(.+)\", substitution: \"{0}\"}]"});

    return Status::OK();
}

Status storeLDAPOptions(const moe::Environment& params) {
    if (params.count("security.ldap.servers")) {
        ldapGlobalParams.ldapServers =
            params["security.ldap.servers"].as<std::string>();
    }
    if (params.count("security.ldap.transportSecurity")) {
        ldapGlobalParams.ldapTransportSecurity =
            params["security.ldap.transportSecurity"].as<std::string>();
    }
    if (params.count("security.ldap.bind.method")) {
        ldapGlobalParams.ldapBindMethod = params["security.ldap.bind.method"].as<std::string>();
    }
    if (params.count("security.ldap.bind.saslMechanisms")) {
        ldapGlobalParams.ldapBindSaslMechanisms =
            params["security.ldap.bind.saslMechanisms"].as<std::string>();
    }
    if (params.count("security.ldap.timeoutMS")) {
        ldapGlobalParams.ldapTimeoutMS.store(params["security.ldap.timeoutMS"].as<int>());
    }
    if (params.count("security.ldap.bind.queryUser")) {
        ldapGlobalParams.ldapQueryUser =
            params["security.ldap.bind.queryUser"].as<std::string>();
    }
    if (params.count("security.ldap.bind.queryPassword")) {
        ldapGlobalParams.ldapQueryPassword =
            params["security.ldap.bind.queryPassword"].as<std::string>();
    }
    if (params.count("security.ldap.userToDNMapping")) {
        ldapGlobalParams.ldapUserToDNMapping =
            params["security.ldap.userToDNMapping"].as<std::string>();
    }
    return Status::OK();
}

MONGO_STARTUP_OPTIONS_STORE(LDAPOptions)(InitializerContext* context) {
    return storeLDAPOptions(moe::startupOptionsParsed);
}


namespace {

// Server parameter declarations

ExportedServerParameter<std::string, ServerParameterType::kRuntimeOnly> ldapServersParam{
    ServerParameterSet::getGlobal(), "ldapServers",
    &ldapGlobalParams.ldapServers};

ExportedServerParameter<int, ServerParameterType::kRuntimeOnly> ldapTimeoutMSParam{
    ServerParameterSet::getGlobal(), "ldapTimeoutMS",
    &ldapGlobalParams.ldapTimeoutMS};

ExportedServerParameter<std::string, ServerParameterType::kRuntimeOnly> ldapQueryUserParam{
    ServerParameterSet::getGlobal(), "ldapQueryUser",
    &ldapGlobalParams.ldapQueryUser};

ExportedServerParameter<std::string, ServerParameterType::kRuntimeOnly> ldapQueryPasswordParam{
    ServerParameterSet::getGlobal(), "ldapQueryPassword",
    &ldapGlobalParams.ldapQueryPassword};

ExportedServerParameter<std::string, ServerParameterType::kRuntimeOnly> ldapUserToDNMappingParam{
    ServerParameterSet::getGlobal(), "ldapUserToDNMapping",
    &ldapGlobalParams.ldapUserToDNMapping};

// these have no equivalent command line switches
ExportedServerParameter<bool, ServerParameterType::kStartupOnly> ldapUseConnectionPoolParam{
    ServerParameterSet::getGlobal(), "ldapUseConnectionPool",
    &ldapGlobalParams.ldapUseConnectionPool};

ExportedServerParameter<int, ServerParameterType::kStartupAndRuntime> ldapUserCacheInvalidationIntervalParam{
    ServerParameterSet::getGlobal(), "ldapUserCacheInvalidationInterval",
    &ldapGlobalParams.ldapUserCacheInvalidationInterval};

}  // namespace

}  // namespace mongo
