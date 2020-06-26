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

#pragma once

#include "mongo/db/ldap/ldap_manager.h"

#include <ldap.h>

namespace mongo {

class LDAPManagerImpl : public LDAPManager {
public:
    class ConnectionPoller;

    LDAPManagerImpl();
    virtual ~LDAPManagerImpl() override;

    virtual Status initialize() override;

    virtual Status queryUserRoles(const UserName& userName, stdx::unordered_set<RoleName>& roles) override;

    virtual Status mapUserToDN(const std::string& user, std::string& out) override;

    void needReinit() {
        _reinitPending.store(true);
    }

private:
    LDAP* _ldap{nullptr};
    std::unique_ptr<ConnectionPoller> _connPoller;

    AtomicWord<bool> _reinitPending{true};
    // guard init/reinit of _ldap
    stdx::mutex _mutex;

    Status reinitialize();
    Status execQuery(std::string& ldapurl, std::vector<std::string>& results);
};

// bind either simple or sasl using global LDAP parameters
Status LDAPbind(LDAP* ld, const char* usr, const char* psw);
Status LDAPbind(LDAP* ld, const std::string& usr, const std::string& psw);

}  // namespace mongo
