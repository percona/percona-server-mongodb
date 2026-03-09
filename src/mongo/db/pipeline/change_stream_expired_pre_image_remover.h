/**
 *    Copyright (C) 2021-present MongoDB, Inc.
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

#include "mongo/db/operation_context.h"
#include "mongo/db/repl/replica_set_aware_service.h"
#include "mongo/db/service_context.h"
#include "mongo/stdx/mutex.h"
#include "mongo/util/modules.h"
#include "mongo/util/periodic_runner.h"

#include <string>

#include <boost/optional/optional.hpp>

namespace mongo {

/**
 * Manages the conditions under which periodic pre-image removal runs on a node.
 */
class ChangeStreamExpiredPreImagesRemoverService
    : public ReplicaSetAwareService<ChangeStreamExpiredPreImagesRemoverService> {
public:
    ChangeStreamExpiredPreImagesRemoverService() = default;

    /**
     * Obtains the service-wide instance.
     */
    static ChangeStreamExpiredPreImagesRemoverService* get(ServiceContext* serviceContext);
    static ChangeStreamExpiredPreImagesRemoverService* get(OperationContext* opCtx);

    void onStartup(OperationContext* opCtx) override {}

    void onSetCurrentConfig(OperationContext* opCtx) override {}

    /**
     * Starts the pre-images removal job in case replicated truncates are disabled. Does nothing in
     * case replicated truncates are enabled.
     */
    void onConsistentDataAvailable(OperationContext* opCtx,
                                   bool isMajority,
                                   bool isRollback) override;

    void onStepUpBegin(OperationContext* opCtx, long long term) override {}

    /**
     * Starts the pre-images removal job in case replicated truncates are enabled. Does nothing in
     * case replicated truncates are disabled.
     */
    void onStepUpComplete(OperationContext* opCtx, long long term) override;

    /**
     * Stops the pre-images removal job in case replicated truncates are enabled. Does nothing in
     * case replicated truncates are disabled.
     */
    void onStepDown() override;

    void onRollbackBegin() override {}

    void onBecomeArbiter() override {}

    /**
     * Stops the pre-images removal job regardless of whether replicated truncates are used.
     */
    void onShutdown() override;

    std::string getServiceName() const final {
        return "ChangeStreamExpiredPreImagesRemoverService";
    }

    bool hasStartedPeriodicJob() const {
        stdx::lock_guard<stdx::mutex> scopedLock(_mutex);
        return _periodicJob.isValid();
    }

    boost::optional<bool> useReplicatedTruncates_forTest() const {
        return _useReplicatedTruncates;
    }

private:
    // Populates the '_useReplicatedTruncates' flag with its initial value. Does nothing if the flag
    // is already populated.
    void _populateUseReplicatedTruncatesFlag(OperationContext* opCtx);

    // Starts the pre-images removal job.
    void _startChangeStreamExpiredPreImagesRemoverServiceJob(OperationContext* opCtx);

    // Stops the pre-images removal job.
    void _stopChangeStreamExpiredPreImagesRemoverServiceJob();

    // Protects '_periodicJob'.
    mutable stdx::mutex _mutex;

    // Job for periodic pre-images removal.
    // If replicated truncates are enabled, the job is started only on the primary when it steps up
    // (via 'onStepUpComplete()'), and is stopped on every step-down (via 'onStepDown()').
    // Secondaries do not run the pre-images removal job.
    //
    // If replicated truncates are disabled, the job is executed on primaries and secondaries
    // locally and independently. It is then started as part of the 'onConsistentDataAvailable()'
    // callback.
    PeriodicJobAnchor _periodicJob;

    // Whether or not replicated truncates are used. Populated exactly once inside
    // '_populateUseReplicatedTruncatesFlag()'. callback. Constant afterwards.
    // The flag cannot be populated in the constructor or 'onStartup()' due to the lack of an
    // OperationContext and/or the FCV snapshot not being initialized yet.
    // Outside of tests, this flag is queried or set inside any of the 'ReplicaSetAwareService'
    // callbacks (e.g. 'onConsistentDataAvailable()', 'onStepUpComplete()', 'onStepDown()'), which
    // should never run concurrently inside the same mongod process. Thus access to this member is
    // not synchronized.
    boost::optional<bool> _useReplicatedTruncates;
};
}  // namespace mongo
