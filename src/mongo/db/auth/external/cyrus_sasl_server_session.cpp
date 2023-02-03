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

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kAccessControl

#include "mongo/db/auth/external/cyrus_sasl_server_session.h"

#include <fmt/format.h>
#include <gssapi/gssapi.h>

#include "mongo/db/auth/sasl_command_constants.h"
#include "mongo/db/auth/sasl_options.h"
#include "mongo/logv2/log.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/net/socket_utils.h"

namespace mongo {

static Status getInitializationError(int result) {
    return Status(ErrorCodes::OperationFailed,
                  fmt::format("Could not initialize SASL server session ({})",
                              sasl_errstring(result, nullptr, nullptr)));
}

CyrusSASLServerSession::CyrusSASLServerSession(const StringData mechanismName)
    : _mechanismName(mechanismName) {}

CyrusSASLServerSession::~CyrusSASLServerSession() {
    if (_saslConnection) {
        sasl_dispose(&_saslConnection);
    }
}

StatusWith<std::tuple<bool, std::string>> CyrusSASLServerSession::getStepResult() const {
    if (_results.resultsShowNoError()) {
        return std::make_tuple(_results.resultsAreOK(),
                               std::string(_results.output, _results.length));
    }

    return Status(ErrorCodes::OperationFailed,
                  fmt::format("SASL step did not complete: ({})",
                              sasl_errstring(_results.result, nullptr, nullptr)));
}

namespace {

void saslSetError(sasl_conn_t* conn, const std::string& msg) {
    sasl_seterror(conn, 0, "%s", msg.c_str());
}

struct gss_result {
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    void check(const char* loc) const {
        if (major != GSS_S_COMPLETE) {
            throw std::runtime_error(
                fmt::format("{} error: major: {}; minor: {}", loc, major, minor));
        }
    }
};

class auto_gss_name_t {
public:
    // Scope guard is the only intended usage
    // so make this class noncopyable/nonmoveable
    auto_gss_name_t(const auto_gss_name_t&) = delete;
    auto_gss_name_t(auto_gss_name_t&&) = delete;
    auto_gss_name_t& operator=(const auto_gss_name_t&) = delete;
    auto_gss_name_t& operator=(auto_gss_name_t&&) = delete;

    auto_gss_name_t() = default;
    ~auto_gss_name_t() {
        gss_result gr;
        gr.major = gss_release_name(&gr.minor, &_v);
    }
    operator gss_name_t() const {
        return _v;
    }
    gss_name_t* operator&() {
        return &_v;
    }

private:
    gss_name_t _v = nullptr;
};

class auto_gss_buffer_desc : public gss_buffer_desc {
public:
    // Scope guard is the only intended usage
    // so make this class noncopyable/nonmoveable
    auto_gss_buffer_desc(const auto_gss_buffer_desc&) = delete;
    auto_gss_buffer_desc(auto_gss_buffer_desc&&) = delete;
    auto_gss_buffer_desc& operator=(const auto_gss_buffer_desc&) = delete;
    auto_gss_buffer_desc& operator=(auto_gss_buffer_desc&&) = delete;

    auto_gss_buffer_desc() : gss_buffer_desc{.length = 0, .value = nullptr} {}
    ~auto_gss_buffer_desc() {
        gss_result gr;
        gr.major = gss_release_buffer(&gr.minor, this);
    }
    operator std::string() const {
        return {static_cast<const char*>(value), length};
    }
};

std::string canonicalizeGSSAPIUser(const StringData v) {
    // It is possible to get OID using gss_str_to_oid("1.2.840.113554.1.2.2")
    // But result will be the same
    // https://docs.oracle.com/cd/E19683-01/816-1331/6m7oo9sno/index.html
    gss_OID_desc mech_krb5 = {9, const_cast<char*>("\052\206\110\206\367\022\001\002\002")};
    gss_OID mech_type = &mech_krb5;

    gss_result gr;
    gss_buffer_desc input_name_buffer{.length = v.size(), .value = const_cast<char*>(v.rawData())};
    auto_gss_name_t gssname;
    gr.major = gss_import_name(&gr.minor, &input_name_buffer, GSS_C_NT_USER_NAME, &gssname);
    gr.check("gss_import_name");

    auto_gss_name_t canonname;
    gr.major = gss_canonicalize_name(&gr.minor, gssname, mech_type, &canonname);
    gr.check("gss_canonicalize_name");

    auto_gss_buffer_desc displayname;
    gss_OID nt = nullptr;
    gr.major = gss_display_name(&gr.minor, canonname, &displayname, &nt);
    gr.check("gss_display_name");

    return displayname;
}

/* improved callback to verify authorization;
 *     canonicalization now handled elsewhere
 *  conn           -- connection context
 *  requested_user -- the identity/username to authorize (NUL terminated)
 *  rlen           -- length of requested_user
 *  auth_identity  -- the identity associated with the secret (NUL terminated)
 *  alen           -- length of auth_identity
 *  default_realm  -- default user realm, as passed to sasl_server_new if
 *  urlen          -- length of default realm
 *  propctx        -- auxiliary properties
 * returns SASL_OK on success,
 *         SASL_NOAUTHZ or other SASL response on failure
 */
int saslSessionProxyPolicy(sasl_conn_t* conn,
                           void* context,
                           const char* requested_user,
                           unsigned rlen,
                           const char* auth_identity,
                           unsigned alen,
                           const char* def_realm,
                           unsigned urlen,
                           struct propctx* propctx) {
    try {
        LOGV2_DEBUG(29053,
                    2,
                    "saslSessionProxyPolicy: {{ requested_user: '{user}', auth_identity: "
                    "'{ident}', default_realm: '{realm}' }}",
                    "user"_attr = requested_user ? requested_user : "nullptr",
                    "ident"_attr = auth_identity ? auth_identity : "nullptr",
                    "realm"_attr = def_realm ? def_realm : "nullptr");
        const std::string canon_auth_identity = canonicalizeGSSAPIUser({auth_identity, alen});
        const std::string str_requested_user{requested_user, rlen};
        if (str_requested_user != canon_auth_identity) {
            saslSetError(conn,
                         fmt::format("{} is not authorized to act as {}",
                                     canon_auth_identity,
                                     str_requested_user));
            return SASL_NOAUTHZ;
        }
    } catch (...) {
        saslSetError(conn,
                     fmt::format("Caught unhandled exception in saslSessionProxyPolicy: {}",
                                 exceptionToStatus().reason()));
        return SASL_FAIL;
    }
    return SASL_OK;
}

}  // namespace

Status CyrusSASLServerSession::initializeConnection() {
    typedef int (*SaslCallbackFn)();
    static const sasl_callback_t callbacks[] = {
        {SASL_CB_PROXY_POLICY, SaslCallbackFn(saslSessionProxyPolicy), nullptr},
        {SASL_CB_LIST_END}};
    int result = sasl_server_new(
        saslGlobalParams.serviceName.c_str(),
        saslGlobalParams.hostName
            .c_str(),       // Fully Qualified Domain Name (FQDN), nullptr => gethostname()
        nullptr,            // User Realm string, nullptr forces default value: FQDN.
        nullptr,            // Local IP address
        nullptr,            // Remote IP address
        callbacks,          // Callbacks specific to this connection.
        0,                  // Security flags.
        &_saslConnection);  // Connection object output parameter.
    if (result != SASL_OK) {
        return getInitializationError(result);
    }

    return Status::OK();
}

StatusWith<std::tuple<bool, std::string>> CyrusSASLServerSession::processInitialClientPayload(
    const StringData& payload) {
    _results.initialize_results();
    _results.result = sasl_server_start(_saslConnection,
                                        _mechanismName.c_str(),
                                        payload.rawData(),
                                        static_cast<unsigned>(payload.size()),
                                        &_results.output,
                                        &_results.length);
    return getStepResult();
}

StatusWith<std::tuple<bool, std::string>> CyrusSASLServerSession::processNextClientPayload(
    const StringData& payload) {
    _results.initialize_results();
    _results.result = sasl_server_step(_saslConnection,
                                       payload.rawData(),
                                       static_cast<unsigned>(payload.size()),
                                       &_results.output,
                                       &_results.length);
    return getStepResult();
}

StatusWith<std::tuple<bool, std::string>> CyrusSASLServerSession::step(StringData inputData) {
    if (_step++ == 0) {
        Status status = initializeConnection();
        if (!status.isOK()) {
            return status;
        }
        return processInitialClientPayload(inputData);
    }
    return processNextClientPayload(inputData);
}

StringData CyrusSASLServerSession::getPrincipalName() const {
    const char* username = nullptr;
    int result =
        sasl_getprop(_saslConnection, SASL_USERNAME, reinterpret_cast<const void**>(&username));
    if (result == SASL_OK) {
        return username;
    }

    return "";
}

}  // namespace mongo
