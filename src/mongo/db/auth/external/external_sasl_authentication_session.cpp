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

#include "mongo/db/auth/external/external_sasl_authentication_session.h"

#include <sasl/sasl.h>

#include "mongo/base/init.h"
#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/client/sasl_client_authenticate.h"
#include "mongo/db/auth/sasl_command_constants.h"
#include "mongo/db/auth/sasl_mechanism_registry.h"
#include "mongo/util/log.h"
#include "mongo/util/mongoutils/str.h"
#include "mongo/util/net/socket_utils.h"

namespace mongo {

static Status getInitializationError(int result) {
    return Status(ErrorCodes::OperationFailed,
                  mongoutils::str::stream() <<
                  "Could not initialize sasl server session (" <<
                  sasl_errstring(result, NULL, NULL) <<
                  ")");
}

StatusWith<std::tuple<bool, std::string>> SaslExternalLDAPServerMechanism::getStepResult() const {
    if (_results.resultsShowNoError()) {
        return std::make_tuple(_results.resultsAreOK(), std::string(_results.output, _results.length));
    }

    return Status(ErrorCodes::OperationFailed,
                  mongoutils::str::stream() <<
                  "SASL step did not complete: (" <<
                  sasl_errstring(_results.result, NULL, NULL) <<
                  ")");
}

Status SaslExternalLDAPServerMechanism::initializeConnection() {
    int result = sasl_server_new(saslDefaultServiceName.rawData(),
                                 prettyHostName().c_str(), // Fully Qualified Domain Name (FQDN), NULL => gethostname()
                                 NULL, // User Realm string, NULL forces default value: FQDN.
                                 NULL, // Local IP address
                                 NULL, // Remote IP address
                                 NULL, // Callbacks specific to this connection.
                                 0,    // Security flags.
                                 &_saslConnection); // Connection object output parameter.
    if (result != SASL_OK) {
        return getInitializationError(result);
    }

    return Status::OK();
}

StatusWith<std::tuple<bool, std::string>> SaslExternalLDAPServerMechanism::processInitialClientPayload(const StringData& payload) {
    _results.initialize_results();
    _results.result = sasl_server_start(_saslConnection,
                                       mechanismName().rawData(),
                                       payload.rawData(),
                                       static_cast<unsigned>(payload.size()),
                                       &_results.output,
                                       &_results.length);
    return getStepResult();
}

StatusWith<std::tuple<bool, std::string>> SaslExternalLDAPServerMechanism::processNextClientPayload(const StringData& payload) {
    _results.initialize_results();
    _results.result = sasl_server_step(_saslConnection,
                                      payload.rawData(),
                                      static_cast<unsigned>(payload.size()),
                                      &_results.output,
                                      &_results.length);
    return getStepResult();
}

SaslExternalLDAPServerMechanism::~SaslExternalLDAPServerMechanism() {
    if (_saslConnection) {
        sasl_dispose(&_saslConnection);
    }
}

StatusWith<std::tuple<bool, std::string>> SaslExternalLDAPServerMechanism::stepImpl(
    OperationContext* opCtx, StringData inputData) {
    if (_step++ == 0) {
        Status status = initializeConnection();
        if (!status.isOK()) {
            return status;
        }
        return processInitialClientPayload(inputData);
    }
    return processNextClientPayload(inputData);
}

StringData SaslExternalLDAPServerMechanism::getPrincipalName() const {
    const char* username;
    int result = sasl_getprop(_saslConnection, SASL_USERNAME, (const void**)&username);
    if (result == SASL_OK) {
        return username;
    }

    return "";
}

// Mongo initializers will run before any ServiceContext is created
// and before any ServiceContext::ConstructorActionRegisterer is executed
// (see SERVER-36258 and SERVER-34798)
MONGO_INITIALIZER(SaslExternalLDAPServerMechanism)(InitializerContext*) {
    int result = sasl_server_init(NULL, saslDefaultServiceName.rawData());
    if (result != SASL_OK) {
        log() << "Failed Initializing SASL " << std::endl;
        return getInitializationError(result);
    }
    return Status::OK();
}

namespace {
GlobalSASLMechanismRegisterer<ExternalLDAPServerFactory> externalLDAPRegisterer;
}
}  // namespace mongo
