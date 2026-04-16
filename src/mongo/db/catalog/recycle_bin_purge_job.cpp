/**
 *    Copyright (C) 2018-present MongoDB, Inc.
 */

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kStorage

#include "mongo/platform/basic.h"

#include "mongo/db/catalog/recycle_bin_purge_job.h"

#include "mongo/db/catalog/recycle_bin.h"
#include "mongo/db/client.h"
#include "mongo/db/service_context.h"
#include "mongo/logv2/log.h"
#include "mongo/util/periodic_runner.h"

namespace mongo {

RecycleBinPurgeJob& RecycleBinPurgeJob::get(ServiceContext* serviceContext) {
    auto& job = _serviceDecoration(serviceContext);
    job._ensureStarted(serviceContext);
    return job;
}

PeriodicJobAnchor& RecycleBinPurgeJob::operator*() const noexcept {
    stdx::lock_guard lk(_mutex);
    return *_anchor;
}

PeriodicJobAnchor* RecycleBinPurgeJob::operator->() const noexcept {
    stdx::lock_guard lk(_mutex);
    return _anchor.get();
}

void RecycleBinPurgeJob::start() {
    stdx::lock_guard lk(_mutex);
    if (_anchor) {
        _anchor->start();
    }
}

void RecycleBinPurgeJob::stop() {
    stdx::lock_guard lk(_mutex);
    if (_anchor) {
        _anchor->stop();
    }
}

void RecycleBinPurgeJob::_ensureStarted(ServiceContext* serviceContext) {
    stdx::lock_guard lk(_mutex);
    if (_anchor) {
        return;
    }

    auto periodicRunner = serviceContext->getPeriodicRunner();
    invariant(periodicRunner);

    PeriodicRunner::PeriodicJob job(
        "recycleBinPurge",
        [](Client* client) {
            auto opCtx = client->makeOperationContext();
            try {
                recycle_bin::purgeExpiredCollections(opCtx.get());
            } catch (const ExceptionForCat<ErrorCategory::CancellationError>& ex) {
                LOGV2_DEBUG(9876501, 2, "Recycle bin purge job canceled", "reason"_attr = ex.reason());
            }
        },
        Minutes(1));

    _anchor = std::make_shared<PeriodicJobAnchor>(periodicRunner->makeJob(std::move(job)));
}

}  // namespace mongo
