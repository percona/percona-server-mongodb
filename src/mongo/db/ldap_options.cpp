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
#include "mongo/util/str.h"

#include <regex>

#include <boost/algorithm/string/split.hpp>
#include <fmt/format.h>

#include "mongo/bson/json.h"

namespace mongo {

using namespace fmt::literals;

LDAPGlobalParams ldapGlobalParams;

std::string LDAPGlobalParams::getServersStr() const {
    std::string ldap_servers;
    std::string pfx;
    auto guard = *ldapServers;
    for (auto& s: *guard) {
        ldap_servers += pfx;
        ldap_servers += s;
        pfx = ",";
    }
    return ldap_servers;
}

void LDAPGlobalParams::setServersStr(StringData ldap_servers) {
    auto guard = *ldapServers;
    boost::split(
        *guard, ldap_servers, [](char c) { return c == ','; }, boost::token_compress_on);
}

std::string LDAPGlobalParams::logString() const {
    return fmt::format(
        "ldapServers: {}; "
        "ldapTransportSecurity: {}; "
        "ldapBindMethod: {}; "
        "ldapBindSaslMechanisms: {}",
        getServersStr(),
        ldapTransportSecurity,
        ldapBindMethod,
        ldapBindSaslMechanisms);
}

// build comma separated list of URIs containing schema (protocol)
std::string LDAPGlobalParams::ldapURIList() const {
    const char* ldapprot = "ldaps";
    if (ldapTransportSecurity == "none")
        ldapprot = "ldap";
    std::string uri;
    auto backins = std::back_inserter(uri);
    auto guard = *ldapServers;
    for (auto& s: *guard) {
        if (!uri.empty())
            backins = ',';
        fmt::format_to(backins, "{}://{}/", ldapprot, s);
    }
    return uri;
}


void LDAPServersParameter::append(OperationContext*,
                                  BSONObjBuilder* b,
                                  StringData name,
                                  const boost::optional<TenantId>&) {
    b->append(name, ldapGlobalParams.getServersStr());
}

Status LDAPServersParameter::setFromString(StringData newValueString,
                                           const boost::optional<TenantId>&) {
    ldapGlobalParams.setServersStr(newValueString);
    return Status::OK();
}


Status validateLDAPBindMethod(const std::string& value) {
    constexpr auto kSimple = "simple"_sd;
    constexpr auto kSasl = "sasl"_sd;

    if (!str::equalCaseInsensitive(kSimple, value) && !str::equalCaseInsensitive(kSasl, value)) {
        return {ErrorCodes::BadValue, "security.ldap.bind.method expects one of 'simple' or 'sasl'"};
    }

    return Status::OK();
}

Status validateLDAPTransportSecurity(const std::string& value) {
    constexpr auto kNone = "none"_sd;
    constexpr auto kTls = "tls"_sd;

    if (!str::equalCaseInsensitive(kNone, value) && !str::equalCaseInsensitive(kTls, value)) {
        return {ErrorCodes::BadValue, "security.ldap.transportSecurity expects one of 'none' or 'tls'"};
    }

    return Status::OK();
}

Status validateLDAPUserToDNMapping(const std::string& mapping) {
    if (!JParse(mapping).isArray())
        return {ErrorCodes::BadValue, "security.ldap.userToDNMapping: User to DN mapping must be json array of objects"};

    BSONArray bsonmapping{fromjson(mapping)};
    for (const auto& elt: bsonmapping) {
        auto step = elt.Obj();
        BSONElement elmatch = step["match"];
        if (!elmatch)
            return {ErrorCodes::BadValue, "security.ldap.userToDNMapping: Each object in user to DN mapping array must contain the 'match' string"};
        BSONElement eltempl = step["substitution"];
        if (!eltempl)
            eltempl = step["ldapQuery"];
        if (!eltempl)
            return {ErrorCodes::BadValue, "security.ldap.userToDNMapping: Each object in user to DN mapping array must contain either 'substitution' or 'ldapQuery' string"};
        try {
            std::regex rex{elmatch.str()};
            const auto sm_count = rex.mark_count();
            // validate placeholders in template
            std::regex placeholder_rex{R"(\{(\d+)\})"};
            const std::string stempl = eltempl.str();
            std::sregex_iterator it{stempl.begin(), stempl.end(), placeholder_rex};
            std::sregex_iterator end;
            for(; it != end; ++it){
                if (std::stol((*it)[1].str()) >= sm_count)
                    return {ErrorCodes::BadValue,
                            fmt::format(
                                "security.ldap.userToDNMapping: "
                                "Regular expresssion '{}' has {} capture groups so '{}' "
                                "placeholder is invalid "
                                "(placeholder number must be less than number of capture groups)",
                                elmatch.str(),
                                sm_count,
                                it->str())};
            }
        } catch (std::regex_error& e) {
            return {ErrorCodes::BadValue,
                    fmt::format("security.ldap.userToDNMapping: std::regex_error exception while "
                                "validating '{}'. "
                                "Error message is: {}",
                                elmatch.str(),
                                e.what())};
        }
    }

    return Status::OK();
}

Status validateLDAPUserToDNMappingServerParam(const std::string& mapping,
                                              [[maybe_unused]] const boost::optional<TenantId>&) {
    return validateLDAPUserToDNMapping(mapping);
}

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
                        fmt::format("security.ldap.authz.queryTemplate: "
                                    "{} placeholder is invalid. Only {{USER}} and "
                                    "{{PROVIDED_USER}} placeholders are supported",
                                    (*it)[0].str())};
        }
        // test format (throws fmt::format_error if something is wrong)
        (void)fmt::format(fmt::runtime(templ),
                    fmt::arg("USER", "test user"),
                    fmt::arg("PROVIDED_USER", "test user"));
    } catch (std::regex_error& e) {
        return {ErrorCodes::BadValue,
                fmt::format("security.ldap.authz.queryTemplate: std::regex_error exception while "
                            "validating '{}'. "
                            "Error message is: {}",
                            templ,
                            e.what())};
    } catch (fmt::format_error& e) {
        return {ErrorCodes::BadValue,
                fmt::format("security.ldap.authz.queryTemplate is malformed, attempt to substitute "
                            "placeholders thrown an exception. "
                            "Error message is: {}",
                            e.what())};
    }

    return Status::OK();
}

Status validateLDAPAuthzQueryTemplateServerParam(const std::string& templ,
                                                 const boost::optional<TenantId>&) {
    return validateLDAPAuthzQueryTemplate(templ);
}

}  // namespace mongo
