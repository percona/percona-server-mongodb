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

#include <ldap.h>

#include "mongo/bson/bsonobj.h"
#include "mongo/db/ldap/ldap_manager.h"
#include "mongo/logv2/log_severity.h"
#include "mongo/platform/mutex.h"
#include "mongo/platform/rwmutex.h"
#include "mongo/util/lru_cache.h"
#include "mongo/util/time_support.h"

namespace mongo {

class LDAPManagerImpl : public LDAPManager {
public:
    class ConnectionPoller;

    LDAPManagerImpl();
    virtual ~LDAPManagerImpl() override;

    virtual Status initialize() override;

    virtual void start_threads() override;

    virtual Status queryUserRoles(const UserName& userName,
                                  stdx::unordered_set<RoleName>& roles) override;

    virtual Status mapUserToDN(const std::string& user, std::string& out) override;

    void invalidateConnections() override;

    void invalidateUserToDNCache() override;

private:
    struct UserToDNCacheEntry {
        std::string dn;
        Date_t insertedAt;
    };

    // RWMutex ensures invalidateUserToDNCache() waits for all in-flight mapUserToDN() calls.
    // mapUserToDN() holds a shared lock for its entire duration (including LDAP queries).
    // invalidateUserToDNCache() holds an exclusive lock to drain and reset the cache.
    RWMutex _userToDNRWMutex;
    // Inner mutex protects the cache data structure from concurrent mapUserToDN() callers.
    Mutex _userToDNCacheMutex = MONGO_MAKE_LATCH("LDAPManagerImpl::_userToDNCacheMutex");
    using UserToDNCache = LRUCache<std::string, UserToDNCacheEntry>;
    std::unique_ptr<UserToDNCache> _userToDNCache;
    int _userToDNCacheTTLSnapshot{0};
    bool _userToDNCacheEnabled{false};
    BSONArray _userToDNMappingSnapshot;

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
