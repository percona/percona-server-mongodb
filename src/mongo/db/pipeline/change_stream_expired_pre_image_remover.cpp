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


#include "mongo/db/pipeline/change_stream_expired_pre_image_remover.h"

#include "mongo/db/auth/authorization_session.h"
#include "mongo/db/change_stream_pre_image_util.h"
#include "mongo/db/change_stream_pre_images_collection_manager.h"
#include "mongo/db/client.h"
#include "mongo/db/pipeline/change_stream_preimage_gen.h"
#include "mongo/logv2/log.h"
#include "mongo/stdx/mutex.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/decorable.h"
#include "mongo/util/duration.h"
#include "mongo/util/periodic_runner.h"

#include <utility>

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kQuery

namespace mongo {
namespace {
const auto changeStreamExpiredPreImagesRemoverServiceDecorator =
    ServiceContext::declareDecoration<ChangeStreamExpiredPreImagesRemoverService>();
}  // namespace

const ReplicaSetAwareServiceRegistry::Registerer<ChangeStreamExpiredPreImagesRemoverService>
    changeStreamExpiredPreImagesRemoverServiceJobRegistryRegisterer(
        "ChangeStreamExpiredPreImagesRemoverService");


ChangeStreamExpiredPreImagesRemoverService* ChangeStreamExpiredPreImagesRemoverService::get(
    ServiceContext* serviceContext) {
    return &changeStreamExpiredPreImagesRemoverServiceDecorator(serviceContext);
}

ChangeStreamExpiredPreImagesRemoverService* ChangeStreamExpiredPreImagesRemoverService::get(
    OperationContext* opCtx) {
    return get(opCtx->getServiceContext());
}

void ChangeStreamExpiredPreImagesRemoverService::onConsistentDataAvailable(OperationContext* opCtx,
                                                                           bool isMajority,
                                                                           bool isRollback) {
    // 'onConsistentDataAvailable()' is signaled both on initial startup and after rollbacks.
    // 'isRollback: false' signals data is consistent on initial startup. If the pre-image removal
    // job is to run, it should do so once data is consistent on startup.
    if (isRollback) {
        return;
    }

    _populateUseReplicatedTruncatesFlag(opCtx);

    tassert(11410301,
            "Expecting _useReplicatedTruncates to be populated",
            _useReplicatedTruncates.has_value());

    // If replicated truncates are enabled, the pre-images removal job is only executed on the
    // primary. It therefore needs to be started on every step-up, but not here.
    //
    // If replicated truncates are disabled, the pre-images removal job is executed locally and
    // independently on each node. It is then started here.
    if (!*_useReplicatedTruncates) {
        _startChangeStreamExpiredPreImagesRemoverServiceJob(opCtx);
    }
}

void ChangeStreamExpiredPreImagesRemoverService::onStepUpComplete(OperationContext* opCtx,
                                                                  long long term) {
    _populateUseReplicatedTruncatesFlag(opCtx);

    tassert(11410302,
            "Expecting _useReplicatedTruncates to be populated",
            _useReplicatedTruncates.has_value());

    // If replicated truncates are enabled, the pre-images removal job is only executed on the
    // primary. Therefore it needs to be started on every step-up.
    //
    // If replicated truncates are disabled, the pre-images removal job is executed locally and
    // independently on each node. It then does not need to be started here, but instead it is
    // started in in 'onConsistentDataAvailable()'.
    if (*_useReplicatedTruncates) {
        _startChangeStreamExpiredPreImagesRemoverServiceJob(opCtx);
    }
}

void ChangeStreamExpiredPreImagesRemoverService::onStepDown() {
    // 'onStepDown()' can be called without a prior call to 'onStepUpComplete()', so we cannot
    // assume that '_useReplicatedTruncates' was already populated.
    if (!_useReplicatedTruncates.has_value()) {
        tassert(
            11410303,
            "Expected pre-images removal job not to be running when state is not yet determined",
            !hasStartedPeriodicJob());
        return;
    }

    // If replicated truncates are enabled, only the primary is allowed to execute the pre-images
    // removal job. Secondaries do not run the job. The job must therefore be stopped on step-down
    // when the node becomes a secondary.
    //
    // If replicated truncates are not enabled, the pre-images removal job is run locally and
    // independently on each node. It then does not need to be stopped on step-downs.
    if (*_useReplicatedTruncates) {
        _stopChangeStreamExpiredPreImagesRemoverServiceJob();
    }
}

void ChangeStreamExpiredPreImagesRemoverService::onShutdown() {
    // Unconditionally stop pre-images removal job.
    _stopChangeStreamExpiredPreImagesRemoverServiceJob();
}

void ChangeStreamExpiredPreImagesRemoverService::_populateUseReplicatedTruncatesFlag(
    OperationContext* opCtx) {
    if (!_useReplicatedTruncates.has_value()) {
        // Only populate the value once.
        _useReplicatedTruncates =
            change_stream_pre_image_util::shouldUseReplicatedTruncatesForPreImages(opCtx);
    }
}

void ChangeStreamExpiredPreImagesRemoverService::
    _startChangeStreamExpiredPreImagesRemoverServiceJob(OperationContext* opCtx) {
    if (gPreImageRemoverDisabled ||
        !repl::ReplicationCoordinator::get(opCtx)->getSettings().isReplSet()) {
        // The removal job is disabled or should not run because it is a standalone.
        return;
    }

    stdx::lock_guard<stdx::mutex> scopedLock(_mutex);
    if (!_periodicJob.isValid()) {
        auto periodicRunner = opCtx->getServiceContext()->getPeriodicRunner();
        invariant(periodicRunner);

        PeriodicRunner::PeriodicJob changeStreamExpiredPreImagesRemoverServiceJob(
            "ChangeStreamExpiredPreImagesRemover",
            [](Client* client) {
                AuthorizationSession::get(client)->grantInternalAuthorization();
                ChangeStreamPreImagesCollectionManager::get(client->getServiceContext())
                    .performExpiredChangeStreamPreImagesRemovalPass(client);
            },
            Seconds(gExpiredChangeStreamPreImageRemovalJobSleepSecs.load()),
            true /*isKillableByStepdown*/);

        _periodicJob =
            periodicRunner->makeJob(std::move(changeStreamExpiredPreImagesRemoverServiceJob));
        LOGV2(7080100, "Starting Change Stream Expired Pre-images Remover thread");
        _periodicJob.start();
    }
}

void ChangeStreamExpiredPreImagesRemoverService::
    _stopChangeStreamExpiredPreImagesRemoverServiceJob() {
    stdx::lock_guard<stdx::mutex> scopedLock(_mutex);
    if (_periodicJob.isValid()) {
        LOGV2(6278511, "Shutting down the Change Stream Expired Pre-images Remover");

        // Blocks until job has finalized.
        _periodicJob.stop();

        // Clears the job's shared pointer.
        _periodicJob.detach();
    }
}

}  // namespace mongo
