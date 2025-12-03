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

#include "mongo/db/redaction_parameter_gen.h"
#include "mongo/db/server_options.h"
#include "mongo/logv2/log_util.h"

namespace mongo {

// Allow --redactClientLogData access via setParameter/getParameter

void RedactClientLogDataParameter::append(OperationContext* txn,
                                          BSONObjBuilder* b,
                                          StringData name,
                                          const boost::optional<TenantId>&) {
    b->append(name, logv2::shouldRedactLogs());
}

namespace {

Status _set(bool v) {
    logv2::setShouldRedactLogs(v);
    return Status::OK();
}

}  // namespace

Status RedactClientLogDataParameter::set(const BSONElement& newValueElement,
                                         const boost::optional<TenantId>&) {
    if (!newValueElement.isBoolean()) {
        return Status(ErrorCodes::BadValue, str::stream() << name() << " has to be a boolean");
    }
    return _set(newValueElement.boolean());
}

Status RedactClientLogDataParameter::setFromString(StringData newValueString,
                                                   const boost::optional<TenantId>&) {
    if (newValueString == "true"_sd || newValueString == "1"_sd)
        return _set(true);
    if (newValueString == "false"_sd || newValueString == "0"_sd)
        return _set(false);
    return Status(ErrorCodes::BadValue, "can't convert string to bool");
}

}  // namespace mongo
