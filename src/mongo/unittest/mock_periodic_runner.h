/**
 *    Copyright (C) 2018-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

#pragma once

#include <memory>
#include <utility>

#include "mongo/util/assert_util_core.h"
#include "mongo/util/duration.h"
#include "mongo/util/periodic_runner.h"

namespace mongo {
class Client;
namespace unittest {

class MockPeriodicJob : public PeriodicRunner::ControllableJob {
public:
    explicit MockPeriodicJob(PeriodicRunner::PeriodicJob job) : _job(std::move(job)) {}

    void start() override {}
    void pause() override {}
    void resume() override {}
    void stop() override {}

    Milliseconds getPeriod() override {
        return _job.interval;
    }

    void setPeriod(Milliseconds period) override {
        _job.interval = period;
    }

    void run(Client* client) {
        _job.job(client);
    }

private:
    PeriodicRunner::PeriodicJob _job;
};

class MockPeriodicRunner : public PeriodicRunner {
public:
    JobAnchor makeJob(PeriodicJob job) override {
        invariant(!_job);
        auto mockJob = std::make_shared<MockPeriodicJob>(std::move(job));
        _job = mockJob;
        return JobAnchor{std::move(mockJob)};
    }

    void run(Client* client) {
        invariant(_job);
        _job->run(client);
    }

protected:
    std::shared_ptr<MockPeriodicJob> _job;
};
}  // namespace unittest
}  // namespace mongo
