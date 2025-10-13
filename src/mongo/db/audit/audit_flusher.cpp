/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2020-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/db/audit/audit_flusher.h"

#include "mongo/db/audit/audit.h"
#include "mongo/db/client.h"
#include "mongo/util/background.h"
#include "mongo/util/concurrency/idle_thread_block.h"
#include "mongo/util/exit.h"
#include "mongo/util/time_support.h"

namespace mongo {

namespace {

/**
 * Audit log flusher thread
 */
class AuditLogFlusher : public BackgroundJob {
public:
    bool _with_fsync = false;

    std::string name() const override {
        return "AuditLogFlusher";
    }

    void run() override {
        ThreadClient tc(name(), getGlobalServiceContext()->getService());
        if (!_with_fsync) {
            // This branch is for wiredTiger storage engine
            // audit::fsyncAuditLog is called by journal flusher
            const long long millis = 1000;
            while (!globalInShutdownDeprecated()) {
                audit::flushAuditLog();
                MONGO_IDLE_THREAD_BLOCK;
                sleepmillis(millis);
            }
        } else {
            // mongos has no journal flusher
            // so we need to simulate it here
            // this also works for inMemory
            const long long millis = 100;
            long long i = 0;
            while (!globalInShutdownDeprecated()) {
                if ((++i % 10) == 0)
                    audit::flushAuditLog();
                audit::fsyncAuditLog();
                MONGO_IDLE_THREAD_BLOCK;
                sleepmillis(millis);
            }
        }
    }
};

// Only one instance of the AuditLogFlusher exists
AuditLogFlusher auditLogFlusher;

}  // namespace

void startAuditLogFlusher() {
    auditLogFlusher.go();
}

void startAuditLogFlusherWithFsync() {
    auditLogFlusher._with_fsync = true;
    auditLogFlusher.go();
}

}  // namespace mongo

