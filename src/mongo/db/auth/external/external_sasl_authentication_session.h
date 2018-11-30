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

#pragma once

#include <string>

#include <sasl/sasl.h>

#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/db/auth/sasl_mechanism_policies.h"

namespace mongo {

class SaslExternalLDAPServerMechanism : public MakeServerMechanism<PLAINPolicy> {
public:
    explicit SaslExternalLDAPServerMechanism(std::string authenticationDatabase)
        : MakeServerMechanism<PLAINPolicy>(std::move(authenticationDatabase)) {}

    virtual ~SaslExternalLDAPServerMechanism();

private:
    int _step{0};
    sasl_conn_t * _saslConnection{nullptr};

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

    StatusWith<std::tuple<bool, std::string>> stepImpl(OperationContext* opCtx,
                                                       StringData input) final;
    virtual StringData getPrincipalName() const override final;

    Status initializeConnection();
    StatusWith<std::tuple<bool, std::string>> processInitialClientPayload(const StringData& payload);
    StatusWith<std::tuple<bool, std::string>> processNextClientPayload(const StringData& payload);
    StatusWith<std::tuple<bool, std::string>> getStepResult() const;
};

class ExternalLDAPServerFactory : public MakeServerFactory<SaslExternalLDAPServerMechanism> {
public:
    static constexpr bool isInternal = false;

    bool canMakeMechanismForUser(const User* user) const final {
        auto credentials = user->getCredentials();
        return credentials.isExternal && (credentials.scram<SHA1Block>().isValid() ||
                                          credentials.scram<SHA256Block>().isValid());
    }
};


}  // namespace mongo
