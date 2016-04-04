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

#include <boost/scoped_ptr.hpp>
#include <string>
#include <cstdint>

#include "mongo/base/disallow_copying.h"
#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/db/auth/authentication_session.h"
#include "mongo/db/auth/native_sasl_authentication_session.h"
#include "mongo/db/auth/sasl_authentication_session.h"

namespace mongo {

    /**
     * Authentication session data for the server side of external SASL authentication.
     */
    class ExternalSaslAuthenticationSession : public NativeSaslAuthenticationSession {
        MONGO_DISALLOW_COPYING(ExternalSaslAuthenticationSession);
    public:
        explicit ExternalSaslAuthenticationSession(AuthorizationSession* authSession);
        virtual ~ExternalSaslAuthenticationSession();
        virtual Status start(StringData authenticationDatabase,
                             StringData mechanism,
                             StringData serviceName,
                             StringData serviceHostname,
                             int64_t conversationId,
                             bool autoAuthorize);
        virtual Status step(StringData inputData, std::string* outputData);
        virtual std::string getPrincipalId() const;
        virtual const char* getMechanism() const;
        static Status getInitializationError(int);

    private:
        Status initializeConnection();
        void processInitialClientPayload(const StringData& payload);
        void processNextClientPayload(const StringData& payload);
        void updateDoneStatus();
        void copyStepOutput(std::string *output) const;
        Status getStepResult() const;
        int getUserName(const char **username) const;

    private:
        sasl_conn_t * _saslConnection;
        std::string _mechanism;
        struct SaslServerResults {
            int result;
            const char *output;
            unsigned length;
            inline void initialize_results() {
                result = SASL_OK;
                output = NULL;
                length = 0;
            };
            inline bool resultsAreOK() const {
                return result == SASL_OK;
            };
            inline bool resultsShowNoError() const {
                return result == SASL_OK || result == SASL_CONTINUE;
            }
        } _results;
    };

    class IntegratedAuthenticationSession : public ExternalSaslAuthenticationSession {
        MONGO_DISALLOW_COPYING(IntegratedAuthenticationSession);
    public:
        explicit IntegratedAuthenticationSession(AuthorizationSession* authSession);
        virtual ~IntegratedAuthenticationSession();
        virtual Status start(StringData authenticationDatabase,
                             StringData mechanism,
                             StringData serviceName,
                             StringData serviceHostname,
                             int64_t conversationId,
                             bool autoAuthorize);
        virtual Status step(StringData inputData, std::string* outputData);
        virtual std::string getPrincipalId() const;
        virtual const char* getMechanism() const;
    private:
        bool _external;
    };

}  // namespace mongo
