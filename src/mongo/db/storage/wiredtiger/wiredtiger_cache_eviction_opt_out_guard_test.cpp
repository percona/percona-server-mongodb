/**
 *    Copyright (C) 2026-present MongoDB, Inc.
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

#include "mongo/db/storage/wiredtiger/wiredtiger_cache_eviction_opt_out_guard.h"

#include "mongo/db/storage/recovery_unit_noop.h"
#include "mongo/unittest/unittest.h"

namespace mongo {

class RecoveryUnitMock : public RecoveryUnitNoop {
public:
    static constexpr auto testWaitTimeout = Milliseconds(1000);

    void setCacheMaxWaitTimeout(const Milliseconds timeout) override {
        _setCacheMaxWaitTimeout = timeout;
    }

    Milliseconds getCacheMaxWaitTimeout() override {
        _isGetCacheMaxWaitTimeoutCalled = true;
        return testWaitTimeout;
    }

    void optOutOfCacheEviction() override {
        _optOutOfCacheEviction = true;
    }

    Milliseconds lastSetCacheMaxWaitTimeout() const {
        return _setCacheMaxWaitTimeout;
    }

    bool isGetCacheMaxWaitTimeoutCalled() const {
        return _isGetCacheMaxWaitTimeoutCalled;
    }

    bool isOptOutOfCacheEvictionSet() const {
        return _optOutOfCacheEviction;
    }

private:
    Milliseconds _setCacheMaxWaitTimeout;
    bool _isGetCacheMaxWaitTimeoutCalled = false;
    bool _optOutOfCacheEviction = false;
};

class CacheEvictionOptOutGuardTest : public unittest::Test {};

TEST(CacheEvictionOptOutGuardTest, OptOutOfCacheEvictionOnConstruction) {
    RecoveryUnitMock mock;

    CacheEvictionOptOutGuard guard(mock);

    ASSERT_TRUE(mock.isGetCacheMaxWaitTimeoutCalled());
    ASSERT_TRUE(mock.isOptOutOfCacheEvictionSet());
}

TEST(CacheEvictionOptOutGuardTest, ResetCacheMaxWaitTimeoutOnDestruction) {
    RecoveryUnitMock mock;

    // Set lastSetCacheMaxWaitTimeout() to a value that is different to the expected value.
    mock.setCacheMaxWaitTimeout(Milliseconds());

    {
        CacheEvictionOptOutGuard guard(mock);
    }

    ASSERT_EQ(mock.lastSetCacheMaxWaitTimeout(), RecoveryUnitMock::testWaitTimeout);
}

}  // namespace mongo
