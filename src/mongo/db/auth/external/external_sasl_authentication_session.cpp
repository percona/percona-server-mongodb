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

#include <sasl/sasl.h>

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
#include "mongo/db/auth/sasl_options.h"
#include "mongo/db/auth/external/external_sasl_authentication_session.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/log.h"
#include "mongo/util/mongoutils/str.h"
#include "mongo/util/net/sock.h"

namespace mongo {

    using boost::scoped_ptr;

namespace {

    SaslAuthenticationSession* createExternalSaslAuthenticationSession(
        AuthorizationSession* authzSession,
        const std::string& mechanism) {
        return new IntegratedAuthenticationSession(authzSession);
    }

    // External SASL session factory needs to be set AFTER the native one has been set.
    MONGO_INITIALIZER_WITH_PREREQUISITES(ExternalSaslServerCore, ("NativeSaslServerCore"))
        (InitializerContext* context) {
        if (saslGlobalParams.hostName.empty())
            saslGlobalParams.hostName = getHostNameCached();
        if (saslGlobalParams.serviceName.empty())
            saslGlobalParams.serviceName = "mongodb";

        int result = sasl_server_init(NULL, saslDefaultServiceName);
        if (result != SASL_OK) {
            log() << "Failed Initializing External Auth Session" << std::endl;
            return ExternalSaslAuthenticationSession::getInitializationError(result);
        }

        log() << "Initialized External Auth Session" << std::endl;
        SaslAuthenticationSession::create = createExternalSaslAuthenticationSession;
        return Status::OK();
    }

} //namespace

    ExternalSaslAuthenticationSession::ExternalSaslAuthenticationSession(
        AuthorizationSession* authzSession) :
        NativeSaslAuthenticationSession(authzSession),
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
                      sasl_errstring(_results.result, NULL, NULL) <<
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
        int result = sasl_server_new(saslDefaultServiceName,
                                     prettyHostName().c_str(), // Fully Qualified Domain Name (FQDN), NULL => gethostname()
                                     NULL, // User Realm string, NULL forces default value: FQDN.
                                     NULL, // Local IP address
                                     NULL, // Remote IP address
                                     NULL, // Callbacks specific to this connection.
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
                      sasl_errstring(result, NULL, NULL) <<
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

    IntegratedAuthenticationSession::IntegratedAuthenticationSession(AuthorizationSession* authSession)
        : ExternalSaslAuthenticationSession(authSession),
          _external(false) {
    }

    IntegratedAuthenticationSession::~IntegratedAuthenticationSession() {
    }

    Status IntegratedAuthenticationSession::start(StringData authenticationDatabase,
                                                  StringData mechanism,
                                                  StringData serviceName,
                                                  StringData serviceHostname,
                                                  int64_t conversationId,
                                                  bool autoAuthorize) {
        if (authenticationDatabase == saslDefaultDBName) {
            _external = true;
            return this->ExternalSaslAuthenticationSession::start(authenticationDatabase,
                                                            mechanism,
                                                            serviceName,
                                                            serviceHostname,
                                                            conversationId,
                                                            autoAuthorize);
        }

        _external = false;
        return this->NativeSaslAuthenticationSession::start(authenticationDatabase,
                                                      mechanism,
                                                      serviceName,
                                                      serviceHostname,
                                                      conversationId,
                                                      autoAuthorize);
    }

    Status IntegratedAuthenticationSession::step(StringData inputData, std::string* outputData) {
        if (_external) {
            return this->ExternalSaslAuthenticationSession::step(inputData, outputData);
        }

        return this->NativeSaslAuthenticationSession::step(inputData, outputData);
    }

    std::string IntegratedAuthenticationSession::getPrincipalId() const {
        if (_external) {
            return this->ExternalSaslAuthenticationSession::getPrincipalId();
        }

        return this->NativeSaslAuthenticationSession::getPrincipalId();
    }

    const char* IntegratedAuthenticationSession::getMechanism() const {
        if (_external) {
            return this->ExternalSaslAuthenticationSession::getMechanism();
        }

        return this->NativeSaslAuthenticationSession::getMechanism();
    }
}  // namespace mongo
