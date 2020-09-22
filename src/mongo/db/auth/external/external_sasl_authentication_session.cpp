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

#define MONGO_LOG_DEFAULT_COMPONENT ::mongo::logger::LogComponent::kAccessControl

#include <fmt/format.h>
#include <ldap.h>

#include "mongo/db/auth/native_sasl_authentication_session.h"

#include <boost/scoped_ptr.hpp>
#include <boost/range/size.hpp>

#include "mongo/base/init.h"
#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/util/bson_extract.h"
#include "mongo/client/sasl_client_authenticate.h"
#include "mongo/db/commands.h"
#include "mongo/db/auth/authorization_manager.h"
#include "mongo/db/auth/authorization_manager_global.h"
#include "mongo/db/auth/authorization_session.h"
#include "mongo/db/auth/external/external_sasl_authentication_session.h"
#include "mongo/db/auth/external/gssapi_server_mechanism.h"
#include "mongo/db/auth/sasl_options.h"
#include "mongo/db/ldap/ldap_manager.h"
#include "mongo/db/ldap/ldap_manager_impl.h"
#include "mongo/db/ldap_options.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/log.h"
#include "mongo/util/mongoutils/str.h"
#include "mongo/util/net/sock.h"

namespace mongo {

    using boost::scoped_ptr;
    using namespace fmt::literals;

namespace {

    static SaslAuthenticationSession::SaslAuthenticationSessionFactoryFn createSaslBase;

    SaslAuthenticationSession* createExternalSaslAuthenticationSession(
        AuthorizationSession* authzSession,
        StringData db,
        StringData mechanism) {
        if (db == saslDefaultDBName) {
            if (mechanism == "PLAIN") {
                if (!ldapGlobalParams.ldapServers->empty())
                    return new OpenLDAPAuthenticationSession(authzSession);
                else
                    return new ExternalSaslAuthenticationSession(authzSession);
            } else if (mechanism == "GSSAPI") {
                return new GSSAPIServerSession(authzSession);
            }
        }
        return createSaslBase(authzSession, db, mechanism);
    }

    int saslServerLog(void* context, int priority, const char* message) throw() {
        log() << "SASL server message: (" << priority << ") " << message;
        return SASL_OK;  // do nothing
    }

    // External SASL session factory needs to be set AFTER the native one has been set.
    MONGO_INITIALIZER_GENERAL(ExternalSaslServerCore, ("NativeSaslServerCore"), ("PostSaslCommands"))
        (InitializerContext* context) {
        if (saslGlobalParams.hostName.empty())
            saslGlobalParams.hostName = getHostNameCached();
        if (saslGlobalParams.serviceName.empty())
            saslGlobalParams.serviceName = "mongodb";

        typedef int (*SaslCallbackFn)();
        static sasl_callback_t saslServerGlobalCallbacks[] = {
            {SASL_CB_LOG, SaslCallbackFn(saslServerLog), nullptr /* context */},
            {SASL_CB_LIST_END}
        };
        int result = sasl_server_init(saslServerGlobalCallbacks, saslGlobalParams.serviceName.c_str());
        if (result != SASL_OK) {
            error() << "Failed Initializing External Auth Session";
            return ExternalSaslAuthenticationSession::getInitializationError(result);
        }

        log() << "Initialized External Auth Session" << std::endl;
        createSaslBase = SaslAuthenticationSession::create;
        SaslAuthenticationSession::create = createExternalSaslAuthenticationSession;
        return Status::OK();
    }

} //namespace

    ExternalSaslAuthenticationSession::ExternalSaslAuthenticationSession(
        AuthorizationSession* authzSession) :
        SaslAuthenticationSession(authzSession),
        _saslConnection(NULL),
        _mechanism("") {
        _results.result = SASL_FAIL;
        _results.output = NULL;
        _results.length = 0;
    }

    ExternalSaslAuthenticationSession::~ExternalSaslAuthenticationSession() {
        if (_saslConnection) {
            sasl_dispose(&_saslConnection);
        }
    }

    Status ExternalSaslAuthenticationSession::start(StringData authenticationDatabase,
                                                    StringData mechanism,
                                                    StringData serviceName,
                                                    StringData serviceHostname,
                                                    int64_t conversationId,
                                                    bool autoAuthorize) {
        if (_conversationId != 0) {
            return Status(ErrorCodes::AlreadyInitialized,
                          "Cannot call start() twice on same ExternalSaslAuthenticationSession.");
        }

        _authenticationDatabase = authenticationDatabase.toString();
        _mechanism = mechanism.toString();
        _serviceName = serviceName.toString();
        _serviceHostname = serviceHostname.toString();
        _conversationId = conversationId;
        _autoAuthorize = autoAuthorize;

        // NOTE: At this point we could ask libsasl2 if the given
        // mechanism is supported, though later it will report an
        // error for an unsupported mechanism during the first SASL
        // step.
        return this->initializeConnection();
    }

    Status ExternalSaslAuthenticationSession::step(StringData inputData, std::string* outputData) {
        if (_saslStep++ == 0) {
            this->processInitialClientPayload(inputData);
        } else {
            this->processNextClientPayload(inputData);
        }

        this->copyStepOutput(outputData);
        return this->getStepResult();
    }
    
    Status ExternalSaslAuthenticationSession::getStepResult() const {
        if (_results.resultsShowNoError()) {
            return Status::OK();
        }

        return Status(ErrorCodes::OperationFailed,
                      mongoutils::str::stream() <<
                      "SASL step did not complete: (" <<
                      sasl_errstring(_results.result, nullptr, nullptr) <<
                      ")");
    }

    std::string ExternalSaslAuthenticationSession::getPrincipalId() const {
        const char * username;
        int result = this->getUserName(&username);
        if (result == SASL_OK) {
            std::string principal(username);
            return principal;
        }
        
        return std::string("");
    }

    const char* ExternalSaslAuthenticationSession::getMechanism() const {
        return _mechanism.c_str();
    }

    Status ExternalSaslAuthenticationSession::initializeConnection() {
        int result = sasl_server_new(saslGlobalParams.serviceName.c_str(),
                                     saslGlobalParams.hostName.c_str(), // Fully Qualified Domain Name (FQDN), nullptr => gethostname()
                                     nullptr, // User Realm string, nullptr forces default value: FQDN.
                                     nullptr, // Local IP address
                                     nullptr, // Remote IP address
                                     nullptr, // Callbacks specific to this connection.
                                     0,    // Security flags.
                                     &_saslConnection); // Connection object output parameter.
        if (result != SASL_OK) {
            return ExternalSaslAuthenticationSession::getInitializationError(result);
        }

        return Status::OK();
    }

    Status ExternalSaslAuthenticationSession::getInitializationError(int result) {
        return Status(ErrorCodes::OperationFailed,
                      mongoutils::str::stream() <<
                      "Could not initialize sasl server session (" <<
                      sasl_errstring(result, nullptr, nullptr) <<
                      ")");
    }

    void ExternalSaslAuthenticationSession::processInitialClientPayload(const StringData& payload) {
        _results.initialize_results();
        _results.result = sasl_server_start(_saslConnection,
                                           _mechanism.c_str(),
                                           payload.rawData(),
                                           static_cast<unsigned>(payload.size()),
                                           &_results.output,
                                           &_results.length);
        this->updateDoneStatus();
    }

    void ExternalSaslAuthenticationSession::processNextClientPayload(const StringData& payload) {
        _results.initialize_results();
        _results.result = sasl_server_step(_saslConnection,
                                          payload.rawData(),
                                          static_cast<unsigned>(payload.size()),
                                          &_results.output,
                                          &_results.length);
        this->updateDoneStatus();
    }

    void ExternalSaslAuthenticationSession::copyStepOutput(std::string *output) const {
        if (_results.resultsShowNoError()) {
            output->assign(_results.output, _results.length);
        }
    }

    void ExternalSaslAuthenticationSession::updateDoneStatus() {
        if (_results.resultsAreOK()) {
            _done = true;
        }
    }

    int ExternalSaslAuthenticationSession::getUserName(const char ** username) const {
        return sasl_getprop(_saslConnection, SASL_USERNAME, (const void**)username);
    }



OpenLDAPAuthenticationSession::OpenLDAPAuthenticationSession(
    AuthorizationSession* authzSession) :
    SaslAuthenticationSession(authzSession) {}

OpenLDAPAuthenticationSession::~OpenLDAPAuthenticationSession() {
    if (_ld) {
        ldap_unbind_ext(_ld, nullptr, nullptr);
        _ld = nullptr;
    }
}


Status OpenLDAPAuthenticationSession::start(StringData authenticationDatabase,
                                              StringData mechanism,
                                              StringData serviceName,
                                              StringData serviceHostname,
                                              int64_t conversationId,
                                              bool autoAuthorize) {
    if (_conversationId != 0) {
        return Status(ErrorCodes::AlreadyInitialized,
                      "Cannot call start() twice on same OpenLDAPAuthenticationSession.");
    }

    _authenticationDatabase = authenticationDatabase.toString();
    _mechanism = mechanism.toString();
    _serviceName = serviceName.toString();
    _serviceHostname = serviceHostname.toString();
    _conversationId = conversationId;
    _autoAuthorize = autoAuthorize;

    return Status::OK();
}

Status OpenLDAPAuthenticationSession::step(StringData inputData, std::string* outputData) {
    if (_saslStep++ == 0) {
        // [authz-id]\0authn-id\0pwd
        const char* authz_id = inputData.rawData();
        const char* authn_id = authz_id + std::strlen(authz_id) + 1; // authentication id
        const char* pw = authn_id + std::strlen(authn_id) + 1; // password

        // transform user to DN
        std::string mappedUser;
        {
            auto ldapManager = LDAPManager::get(_opCtx->getServiceContext());
            auto mapRes = ldapManager->mapUserToDN(authn_id, mappedUser);
            if (!mapRes.isOK())
                return mapRes;
        }

        const char* ldapprot = "ldaps";
        if (ldapGlobalParams.ldapTransportSecurity == "none")
            ldapprot = "ldap";
        auto uri = "{}://{}/"_format(ldapprot, ldapGlobalParams.ldapServers.get());
        int res = ldap_initialize(&_ld, uri.c_str());
        if (res != LDAP_SUCCESS) {
            return Status(ErrorCodes::LDAPLibraryError,
                          "Cannot initialize LDAP structure for {}; LDAP error: {}"_format(
                              uri, ldap_err2string(res)));
        }

        Status status = LDAPbind(_ld, mappedUser.c_str(), pw);
        if (!status.isOK())
            return status;
        _principal = authn_id;
        _done = true;
        return Status::OK();
    }
    // This authentication session supports single step
    return Status(ErrorCodes::InternalError,
                  "An invalid second step was called against the OpenLDAP authentication session");

}

std::string OpenLDAPAuthenticationSession::getPrincipalId() const {
    return _principal;
}

const char* OpenLDAPAuthenticationSession::getMechanism() const {
    return _mechanism.c_str();
}

}  // namespace mongo
