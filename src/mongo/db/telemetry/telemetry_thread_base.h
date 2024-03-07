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

#include <memory>
#include <string>

#include "mongo/base/status.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/oid.h"
#include "mongo/platform/atomic_word.h"
#include "mongo/platform/mutex.h"
#include "mongo/stdx/condition_variable.h"
#include "mongo/util/background.h"
#include "mongo/util/time_support.h"

namespace mongo {

class ServiceContext;

class TelemetryThreadBase : public BackgroundJob {
public:
    // Pointer to the function to create subclass instance
    static std::unique_ptr<TelemetryThreadBase> (*create)();

    explicit TelemetryThreadBase();

    static TelemetryThreadBase* get(ServiceContext* serviceCtx);
    static void set(ServiceContext* serviceCtx,
                    std::unique_ptr<TelemetryThreadBase> newTelemetryThread);

    std::string name() const final {
        return "PerconaTelemetry";
    }

    void run() final;
    void shutdown();

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

    // instance id stored in kTelemetryFileName
    OID _instid;

    // nextScarpe is set to "now + grace" in the constructor
    // but it is overwritten if we read scheduled time from kTelemetryNamespace
    Date_t _nextScrape;

    // database id stored as kTelemetryNamespace._id
    OID _dbid;
    // constant prefix for each metrics file
    BSONObj _prefix;
};

void initPerconaTelemetryInternal(ServiceContext* serviceContext);

}  // namespace mongo
