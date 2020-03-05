/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2020-present Percona and/or its affiliates. All rights reserved.

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

// This file contains LDAP-related server parameters which must exist
// in mongod only.
// Other LDAP-related parameters which exist in both mongod and mongos
// are described in ldap_options.cpp

#include "mongo/db/ldap_options.h"
#include "mongo/db/server_parameters.h"
#include "mongo/util/options_parser/environment.h"
#include "mongo/util/options_parser/startup_option_init.h"
#include "mongo/util/options_parser/startup_options.h"

#include <regex>

#include <fmt/format.h>

namespace mongo {

using namespace fmt::literals;

namespace {

Status validateLDAPAuthzQueryTemplate(const std::string& templ) {
    // validate placeholders in template
    // only {USER} and {PROVIDED_USER} are supported
    try {
        // validate placeholders in template
        std::regex placeholder_rex{R"(\{\{|\}\}|\{(.*?)\})"};
        std::sregex_iterator it{templ.begin(), templ.end(), placeholder_rex};
        std::sregex_iterator end;
        for(; it != end; ++it){
            auto w = (*it)[0].str();
            if (w == "{{" || w == "}}")
                continue;
            auto v = (*it)[1].str();
            if (v != "USER" && v != "PROVIDED_USER")
                return {ErrorCodes::BadValue,
                        "security.ldap.authz.queryTemplate: "
                        "{} placeholder is invalid. Only {{USER}} and {{PROVIDED_USER}} placeholders are supported"_format((*it)[0].str())};
        }
        // test format (throws fmt::format_error if something is wrong)
        fmt::format(templ,
            fmt::arg("USER", "test user"),
            fmt::arg("PROVIDED_USER", "test user"));
    } catch (std::regex_error& e) {
        return {ErrorCodes::BadValue,
                "security.ldap.authz.queryTemplate: std::regex_error exception while validating '{}'. "
                "Error message is: {}"_format(templ, e.what())};
    } catch (fmt::format_error& e) {
        return {ErrorCodes::BadValue,
                "security.ldap.authz.queryTemplate is malformed, attempt to substitute placeholders thrown an exception. "
                "Error message is: {}"_format(e.what())};
    }

    return Status::OK();
}

MONGO_STARTUP_OPTIONS_STORE(mongodLDAPParameters)(InitializerContext* context) {
    const moe::Environment& params = moe::startupOptionsParsed;

    if (params.count("security.ldap.authz.queryTemplate")) {
        auto new_value = params["security.ldap.authz.queryTemplate"].as<std::string>();
        auto ret = validateLDAPAuthzQueryTemplate(new_value);
        if (!ret.isOK())
            return ret;
        ldapGlobalParams.ldapQueryTemplate = new_value;
    }

    return Status::OK();
}

ExportedServerParameter<std::string, ServerParameterType::kRuntimeOnly> ldapQueryTemplateParam{
    ServerParameterSet::getGlobal(), "ldapQueryTemplate",
    &ldapGlobalParams.ldapQueryTemplate,
    validateLDAPAuthzQueryTemplate};

}

}  // namespace mongo
