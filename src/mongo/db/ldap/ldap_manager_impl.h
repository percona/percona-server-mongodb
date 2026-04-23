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

#include "mongo/bson/bsonobj.h"
#include "mongo/db/ldap/ldap_manager.h"
#include "mongo/logv2/log_severity.h"
#include "mongo/util/lru_cache.h"
#include "mongo/util/synchronized_value.h"
#include "mongo/util/time_support.h"

#include <memory>
#include <mutex>

#include <ldap.h>

namespace mongo {

class LDAPManagerImpl : public LDAPManager {
public:
    class ConnectionPoller;

    LDAPManagerImpl();
    ~LDAPManagerImpl() override;

    Status initialize() override;

    void start_threads() override;

    Status queryUserRoles(const UserName& userName, stdx::unordered_set<RoleName>& roles) override;

    Status mapUserToDN(const std::string& user, std::string& out) override;

    void invalidateConnections() override;

    void invalidateUserToDNCache() override;

private:
    struct UserToDNCacheEntry {
        std::string dn;
        Date_t insertedAt;
    };

    struct UserToDNCacheHolder {
        UserToDNCacheHolder();

        using UserToDNCache = LRUCache<std::string, UserToDNCacheEntry>;

        const int size;
        const int ttl;
        const bool enabled;
        const BSONArray mapping;
        std::mutex mutex;
        UserToDNCache cache;
    };

    // UserToDNCacheHolder will be atomically replaced on any configuration changes
    // This enables cache reset without blocking any client threads running mapUserToDN()
    // Multiple threads can have shared_ptr instances pointing to the same UserToDNCacheHolder
    // instance
    synchronized_value<std::shared_ptr<UserToDNCacheHolder>> _userToDNCacheHolder;

    std::unique_ptr<ConnectionPoller> _connPoller;

    LDAP* borrow_search_connection();
    void return_search_connection(LDAP* ldap, bool destroy = false);

    Status execQuery(const std::string& ldapurl,
                     bool entitiesonly,
                     std::vector<std::string>& results);
};

// bind either simple or sasl using global LDAP parameters
Status LDAPbind(LDAP* ld, const char* usr, const char* psw);
Status LDAPbind(LDAP* ld, const std::string& usr, const std::string& psw);

// Set LDAP_OPT_NETWORK_TIMEOUT and LDAP_OPT_TIMEOUT on an LDAP handle using ldapTimeoutMS
bool set_ldap_timeouts(LDAP* ldap, logv2::LogSeverity logSeverity = logv2::LogSeverity::Debug(1));

}  // namespace mongo
