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

#include "mongo/base/init.h"
#include "mongo/db/server_options.h"
#include "mongo/db/server_parameters.h"
#include "mongo/util/mongoutils/str.h"  // for str::stream()!

namespace mongo {

// Allow rateLimit access via setParameter/getParameter
namespace {

class RateLimitParameter : public ServerParameter
{
    MONGO_DISALLOW_COPYING(RateLimitParameter);

public:
    RateLimitParameter(ServerParameterSet* sps);
    virtual void append(OperationContext* txn, BSONObjBuilder& b, const std::string& name);
    virtual Status set(const BSONElement& newValueElement);
    virtual Status setFromString(const std::string& str);

private:
    Status _set(int rateLimit);
};

MONGO_INITIALIZER_GENERAL(InitRateLimitParameter,
                          MONGO_NO_PREREQUISITES,
                          ("BeginStartupOptionParsing"))(InitializerContext*) {
    new RateLimitParameter(ServerParameterSet::getGlobal());
    return Status::OK();
}

RateLimitParameter::RateLimitParameter(ServerParameterSet* sps)
    : ServerParameter(sps, "profilingRateLimit", true, true) {}

void RateLimitParameter::append(OperationContext* txn,
                                   BSONObjBuilder& b,
                                   const std::string& name) {
    b.append(name, serverGlobalParams.rateLimit);
}

Status RateLimitParameter::set(const BSONElement& newValueElement) {
    if (!newValueElement.isNumber()) {
        return Status(ErrorCodes::BadValue, str::stream() << name() << " has to be a number");
    }
    return _set(newValueElement.numberInt());
}

Status RateLimitParameter::setFromString(const std::string& newValueString) {
    int num = 0;
    Status status = parseNumberFromString(newValueString, &num);
    if (!status.isOK()) return status;
    return _set(num);
}

Status RateLimitParameter::_set(int rateLimit) {
    if (rateLimit == 0)
        rateLimit = 1;
    if (1 <= rateLimit && rateLimit <= RATE_LIMIT_MAX) {
        if (rateLimit == 1 || serverGlobalParams.sampleRate == 1.0) {
            serverGlobalParams.rateLimit = rateLimit;
            return Status::OK();
        }
        return Status(ErrorCodes::BadValue,
                      "cannot set both sampleRate and ratelimit to non-default values");
    }
    StringBuilder sb;
    sb << "Bad value for profilingRateLimit: " << rateLimit
       << ".  Supported range is 0-" << RATE_LIMIT_MAX;
    return Status(ErrorCodes::BadValue, sb.str());
}

}  // namespace

}  // namespace mongo
