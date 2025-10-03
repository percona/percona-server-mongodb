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

#include "mongo/db/telemetry/telemetry_path.h"

#include <boost/optional.hpp>
#include <string>

#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/cluster_role.h"
#include "mongo/db/server_options.h"
#include "mongo/db/server_parameter.h"
#include "mongo/db/telemetry/telemetry_parameter_gen.h"
#include "mongo/db/tenant_id.h"

namespace mongo {

namespace {

constexpr StringData kTelemetryPath = "/usr/local/percona/telemetry/psmdb"_sd;
constexpr StringData kTelemetryPathS = "/usr/local/percona/telemetry/psmdbs"_sd;

std::string telemetryPath;  // NOLINT(*-avoid-non-const-global-variables)

}  // namespace

StringData getTelemetryPath() {
    if (!telemetryPath.empty()) {
        return telemetryPath;
    }
    return serverGlobalParams.clusterRole.hasExclusively(ClusterRole::RouterServer)
        ? kTelemetryPathS
        : kTelemetryPath;
}

void TelemetryPath::append(OperationContext*,
                           BSONObjBuilder* bob,
                           StringData name,
                           const boost::optional<TenantId>&) {
    bob->append(name, getTelemetryPath());
}

Status TelemetryPath::setFromString(StringData str, const boost::optional<TenantId>&) {
    telemetryPath = std::string{str};
    return Status::OK();
}

}  // namespace mongo
