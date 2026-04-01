/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2018-present Percona and/or its affiliates. All rights reserved.

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

#include <set>
#include <string>
#include <vector>

namespace mongo {
class DatabaseName;
}

namespace percona {

/**
 * The interface which provides the ability to execute KeyDB-related
 * functions in an engine independent way
 */
struct KeyDBAPI {
    virtual ~KeyDBAPI() {}

    /**
     * Delete the encryption key for the specified database.
     *
     * This method is called by the deferred cleanup process after verifying:
     * 1. The database no longer exists in the catalog
     * 2. No storage idents (including drop-pending ones) use the key
     *
     * NOTE: This should NOT be called directly during dropDatabase operations
     * because drop-pending idents may still exist and require the key for
     * checkpoint cleanup. Use the deferred cleanup mechanism instead.
     */
    virtual void keydbDropDatabase(const mongo::DatabaseName& dbName) {
        // do nothing for engines which do not support KeyDB
    }

    /**
     * Returns all encryption key IDs (database names) stored in the key database.
     * Used for deferred encryption key cleanup.
     */
    virtual std::vector<std::string> getAllEncryptionKeyIds() {
        return {};  // empty for engines which do not support KeyDB
    }

    /**
     * Returns a set of all encryption keyIds currently in use by any ident in storage.
     * This scans the storage engine metadata to find all encrypted idents and extracts their
     * keyids. Used to reliably determine if a key can be safely deleted.
     */
    virtual std::set<std::string> getAllEncryptionKeyIdsInUse() {
        return {};  // empty for engines which do not support KeyDB
    }

    /**
     * Returns true if deferred encryption key cleanup is enabled.
     * When enabled, encryption keys are not deleted immediately on dropDatabase;
     * instead they are cleaned up asynchronously by a background process.
     */
    virtual bool isEncryptionKeyCleanupDeferred() const {
        return false;  // disabled by default for engines which do not support KeyDB
    }

    /**
     * Returns the interval in seconds between orphaned encryption key cleanup attempts.
     * Only effective when isEncryptionKeyCleanupDeferred() returns true.
     */
    virtual int32_t getEncryptionKeyCleanupIntervalSeconds() const {
        return 60;  // default 60 seconds
    }
};

}  // namespace percona
