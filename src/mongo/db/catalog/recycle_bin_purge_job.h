/**
 *    Copyright (C) 2018-present MongoDB, Inc.
 */

#pragma once

#include "mongo/db/service_context.h"
#include "mongo/platform/mutex.h"
#include "mongo/util/hierarchical_acquisition.h"
#include "mongo/util/periodic_runner.h"

namespace mongo {

/**
 * Periodic job that permanently drops recycle-bin collections past their retention window.
 */
class RecycleBinPurgeJob {
public:
    static RecycleBinPurgeJob& get(ServiceContext* serviceContext);

    PeriodicJobAnchor& operator*() const noexcept;
    PeriodicJobAnchor* operator->() const noexcept;

    void start();
    void stop();

private:
    void _ensureStarted(ServiceContext* serviceContext);

    inline static const auto _serviceDecoration =
        ServiceContext::declareDecoration<RecycleBinPurgeJob>();

    mutable Mutex _mutex =
        MONGO_MAKE_LATCH(HierarchicalAcquisitionLevel(1), "RecycleBinPurgeJob::_mutex");
    std::shared_ptr<PeriodicJobAnchor> _anchor;
};

}  // namespace mongo
