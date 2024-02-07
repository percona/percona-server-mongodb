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

#include "mongo/db/telemetry/telemetry_thread.h"

#include <memory>
#include <string>

#include "mongo/base/string_data.h"
#include "mongo/db/client.h"
#include "mongo/db/server_parameter.h"
#include "mongo/db/service_context.h"
#include "mongo/db/telemetry/telemetry_parameter_gen.h"
#include "mongo/logv2/log.h"
#include "mongo/platform/atomic_word.h"
#include "mongo/platform/mutex.h"
#include "mongo/stdx/condition_variable.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/background.h"
#include "mongo/util/concurrency/idle_thread_block.h"

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kDefault

namespace mongo {

namespace {

constexpr StringData kParamName = "perconaTelemetry"_sd;

// We need this flag to filter out updates from server parameter which can arrive before global
// service context is set. In other words we need to avoid asserts from getGlobalServiceContext()
bool updatesEnabled = false;

// mutex to serialize external API calls and access to updatesEnabled
Mutex mutex = MONGO_MAKE_LATCH("TelemetryThread::mutex");

class TelemetryThread;

const auto getTelemetryThread =
    ServiceContext::declareDecoration<std::unique_ptr<TelemetryThread>>();

class TelemetryThread final : public BackgroundJob {
public:
    explicit TelemetryThread() : BackgroundJob(false /* selfDelete */) {}

    static TelemetryThread* get(ServiceContext* serviceCtx) {
        return getTelemetryThread(serviceCtx).get();
    }

    static void set(ServiceContext* serviceCtx,
                    std::unique_ptr<TelemetryThread> newTelemetryThread) {
        auto& telemetryThread = getTelemetryThread(serviceCtx);
        if (telemetryThread) {
            invariant(
                !telemetryThread->running(),
                "Tried to reset the TelemetryThread without shutting down the previous instance.");
        }

        invariant(newTelemetryThread);
        telemetryThread = std::move(newTelemetryThread);
    }

    std::string name() const final {
        return "PerconaTelemetry";
    }

    void run() final {
        const ThreadClient tc(name(), getGlobalServiceContext());
        LOGV2_DEBUG(29121, 1, "starting {name} thread", "name"_attr = name());

        while (!_shuttingDown.load()) {
            {
                stdx::unique_lock<Latch> lock(_mutex);
                MONGO_IDLE_THREAD_BLOCK;
                // TODO: implement long sleep between metric files
                _condvar.wait_for(lock, stdx::chrono::seconds(kDebugBuild ? 10 : 100));
            }

            // TODO: create metrics file
        }
        LOGV2_DEBUG(29122, 1, "stopping {name} thread", "name"_attr = name());
    }

    void shutdown() {
        _shuttingDown.store(true);
        {
            stdx::unique_lock<Latch> lock(_mutex);
            // Wake up the telemetry thread early, we do not want the shutdown
            // to wait for us too long.
            _condvar.notify_one();
        }
        wait();
    }

private:
    AtomicWord<bool> _shuttingDown{false};

    Mutex _mutex = MONGO_MAKE_LATCH("TelemetryThread::_mutex");  // protects _condvar
    // The telemetry thread idles on this condition variable for a particular time duration
    // between creating metrics files. It can be triggered early to expediate shutdown.
    stdx::condition_variable _condvar;
};

// start telemetry thread if it is not running
void startTelemetryThread_inlock(ServiceContext* serviceContext) {
    auto* telemetryThread = TelemetryThread::get(serviceContext);
    if (telemetryThread == nullptr) {
        auto telemetryThread = std::make_unique<TelemetryThread>();
        telemetryThread->go();
        TelemetryThread::set(serviceContext, std::move(telemetryThread));
    }
}

// stop telemetry thread if it is running
void stopTelemetryThread_inlock(ServiceContext* serviceContext) {
    auto* telemetryThread = TelemetryThread::get(serviceContext);
    if (telemetryThread != nullptr) {
        telemetryThread->shutdown();
    }
}

}  // namespace


void initPerconaTelemetry(ServiceContext* serviceContext) {
    stdx::unique_lock<Latch> lock(mutex);
    //  enable updates from server parameter
    updatesEnabled = true;
    // only create if telemetry is enabled
    if (ServerParameterSet::getNodeParameterSet()
            ->get<TelemetryParameter>(kParamName)
            ->_data.load()) {
        startTelemetryThread_inlock(serviceContext);
    }
}

void shutdownPerconaTelemetry(ServiceContext* serviceContext) {
    stdx::unique_lock<Latch> lock(mutex);
    // we do not allow any updates during shutdown
    updatesEnabled = false;
    stopTelemetryThread_inlock(serviceContext);
}

void updatePerconaTelemetry(bool state) {
    stdx::unique_lock<Latch> lock(mutex);
    if (updatesEnabled) {
        if (state) {
            startTelemetryThread_inlock(getGlobalServiceContext());
        } else {
            stopTelemetryThread_inlock(getGlobalServiceContext());
        }
    }
}

}  // namespace mongo
