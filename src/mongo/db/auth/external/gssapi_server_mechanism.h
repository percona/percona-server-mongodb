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

#pragma once

#include "mongo/db/auth/external/cyrus_sasl_server_session.h"
#include "mongo/db/auth/sasl_mechanism_policies.h"
#include "mongo/db/auth/sasl_mechanism_registry.h"

namespace mongo {

class GSSAPIServerMechanism : public MakeServerMechanism<GSSAPIPolicy> {
public:
    explicit GSSAPIServerMechanism(std::string authenticationDatabase)
        : MakeServerMechanism<GSSAPIPolicy>(std::move(authenticationDatabase)),
          _sess(mechanismName()) {}

    ~GSSAPIServerMechanism() override;

    boost::optional<unsigned int> currentStep() const override {
        return (unsigned int)1;
    }

    boost::optional<unsigned int> totalSteps() const override {
        return (unsigned int)1;
    }

private:
    CyrusSASLServerSession _sess;

    StatusWith<std::tuple<bool, std::string>> stepImpl(OperationContext* opCtx,
                                                               StringData input) final;
    StringData getPrincipalName() const final;
};

class GSSAPIServerFactory : public MakeServerFactory<GSSAPIServerMechanism> {
public:
    using MakeServerFactory<GSSAPIServerMechanism>::MakeServerFactory;
    static constexpr bool isInternal = false;

    bool canMakeMechanismForUser(const User* user) const final {
        auto credentials = user->getCredentials();
        return credentials.isExternal && (credentials.scram<SHA1Block>().isValid() ||
                                          credentials.scram<SHA256Block>().isValid());
    }
};

}  // namespace mongo
