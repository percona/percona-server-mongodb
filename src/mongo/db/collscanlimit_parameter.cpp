/*======
This file is part of Percona Server for MongoDB.

Copyright (c) 2006, 2017, Percona and/or its affiliates. All rights reserved.

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

#include "mongo/base/init.h"
#include "mongo/db/server_options.h"
#include "mongo/db/server_parameters.h"
#include "mongo/util/mongoutils/str.h"  // for str::stream()!

namespace mongo {

// Allow collScanLimit access via setParameter/getParameter
namespace {

class CollScanLimitParameter : public ServerParameter
{
    MONGO_DISALLOW_COPYING(CollScanLimitParameter);

public:
    CollScanLimitParameter(ServerParameterSet* sps);
    virtual void append(OperationContext* txn, BSONObjBuilder& b, const std::string& name);
    virtual Status set(const BSONElement& newValueElement);
    virtual Status setFromString(const std::string& str);

private:
    Status _set(long long collScanLimit);
};

MONGO_INITIALIZER_GENERAL(InitCollScanLimitParameter,
                          MONGO_NO_PREREQUISITES,
                          ("BeginStartupOptionParsing"))(InitializerContext*) {
    new CollScanLimitParameter(ServerParameterSet::getGlobal());
    return Status::OK();
}

CollScanLimitParameter::CollScanLimitParameter(ServerParameterSet* sps)
    : ServerParameter(sps, "profilingCollScanLimit", true, true) {}

void CollScanLimitParameter::append(OperationContext* txn,
                                    BSONObjBuilder& b,
                                    const std::string& name) {
    b.append(name, serverGlobalParams.collScanLimit);
}

Status CollScanLimitParameter::set(const BSONElement& newValueElement) {
	if (newValueElement.isNumber()) {
		return _set(newValueElement.numberLong());
	}
	// boolean true enables profiling of all COLLSCANs
	// boolean false disables COLLSCANs profiling
	if (newValueElement.isBoolean()) {
		return _set(newValueElement.boolean() ? 0 : -1);
	}
	return Status(ErrorCodes::BadValue, str::stream() << name() << " has to be a number or a boolean");
}

Status CollScanLimitParameter::setFromString(const std::string& newValueString) {
    long long num = 0;
    Status status = parseNumberFromString(newValueString, &num);
    if (!status.isOK()) return status;
    return _set(num);
}

Status CollScanLimitParameter::_set(long long collScanLimit) {
    if (-1 <= collScanLimit && collScanLimit <= std::numeric_limits<long long>::max()) {
        serverGlobalParams.collScanLimit = collScanLimit;
        return Status::OK();
    }
    StringBuilder sb;
    sb << "Bad value for profilingCollScanLimit: " << collScanLimit
       << ".  Supported range is -1-" << std::numeric_limits<long long>::max();
    return Status(ErrorCodes::BadValue, sb.str());
}

}  // namespace

}  // namespace mongo
