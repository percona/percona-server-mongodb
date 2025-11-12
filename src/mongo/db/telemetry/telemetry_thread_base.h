/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2024-present Percona and/or its affiliates. All rights reserved.

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

#include <boost/filesystem.hpp>  // IWYU pragma: keep
#include <memory>
#include <string>

#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/bson/oid.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/service_context.h"
#include "mongo/platform/atomic_word.h"
#include "mongo/platform/mutex.h"
#include "mongo/stdx/condition_variable.h"
#include "mongo/util/background.h"
#include "mongo/util/time_support.h"

namespace mongo {

class TelemetryThreadBase : public BackgroundJob {
public:
    // Pointer to the function to create subclass instance
    static std::unique_ptr<TelemetryThreadBase> (*create)();

    TelemetryThreadBase();

    static TelemetryThreadBase* get(ServiceContext* serviceCtx);
    static void set(ServiceContext* serviceCtx,
                    std::unique_ptr<TelemetryThreadBase> newTelemetryThread);

    std::string name() const final {
        return "PerconaTelemetry";
    }

    void run() final;
    void shutdown();

protected:
    static boost::filesystem::path sdPath(StringData sd);
    static StringData boolName(bool v);

    // methods called from _initParameters
    virtual StringData _sourceName() = 0;
    virtual Status _initInstanceId(const OID& initialId) = 0;
    virtual Status _initDbId(ServiceContext* serviceContext,
                             OperationContext* opCtx,
                             const OID& initalId) = 0;

    // methods called from _advance
    virtual Status _advancePersist(ServiceContext* serviceContext) = 0;

    // methods called from _writeMetrics
    virtual void _appendMetrics(ServiceContext* serviceContext, BSONObjBuilder* builder) = 0;

    // names of the fields in the metric file
    static constexpr StringData kDbInstanceId = "db_instance_id"_sd;
    static constexpr StringData kDbInternalId = "db_internal_id"_sd;
    static constexpr StringData kPillarVersion = "pillar_version"_sd;
    static constexpr StringData kPerconaFeatures = "percona_features"_sd;
    static constexpr StringData kStorageEngine = "storage_engine"_sd;
    static constexpr StringData kReplicaSetId = "db_replication_id"_sd;
    static constexpr StringData kReplMemberState = "replication_state"_sd;
    static constexpr StringData kClusterId = "db_cluster_id"_sd;
    static constexpr StringData kShardSvr = "shard_svr"_sd;
    static constexpr StringData kConfigSvr = "config_svr"_sd;
    static constexpr StringData kUptime = "uptime"_sd;
    static constexpr StringData kSource = "source"_sd;
    static constexpr StringData kOIDCEnabled = "oidc_enabled"_sd;
    static constexpr StringData kLDAPEnabled = "ldap_enabled"_sd;
    static constexpr StringData kLDAPAuthorizationEnabled = "ldap_authorization_enabled"_sd;
    static constexpr StringData kLDAPSaslAuthenticationEnabled =
        "ldap_sasl_authentication_enabled"_sd;
    static constexpr StringData kKerberosAuthenticationEnabled = "kerberos_enabled"_sd;
    static constexpr StringData kX509AuthenticationEnabled = "x509_enabled"_sd;

    // instance id stored in kTelemetryFileName
    OID _instid;

    // nextScarpe is set to "now + grace" in the constructor
    // but it is overwritten if we read scheduled time from kTelemetryCollection
    Date_t _nextScrape;

    // database id stored as kTelemetryCollection._id
    OID _dbid;
    // constant prefix for each metrics file
    BSONObj _prefix;

private:
    Status _initParameters(ServiceContext* serviceContext);
    Status _advance(ServiceContext* serviceContext);
    Status _cleanupTelemetryDir();
    Status _writeMetrics(ServiceContext* serviceContext);

    // Used as suffix in metric file names.
    // Accessed only from the telemetry thread so synchronization is not necessary
    static std::string _metricFileSuffix;

    AtomicWord<bool> _shuttingDown{false};

    Mutex _mutex;  // protects _condvar
    // The telemetry thread idles on this condition variable for a particular time duration
    // between creating metrics files. It can be triggered early to expediate shutdown.
    stdx::condition_variable _condvar;
};

void initPerconaTelemetryInternal(ServiceContext* serviceContext);

}  // namespace mongo
