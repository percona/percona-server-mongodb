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

#include "mongo/base/string_data.h"

#include <string>
#include <vector>

namespace mongo {
class DatabaseName;
class OperationContext;
}  // namespace mongo

namespace percona {

/**
 * The interface which provides the ability to execute KeyDB-related
 * functions in an engine independent way
 */
struct KeyDBAPI {
    virtual ~KeyDBAPI() {}

    /**
     * Invalidates the active encryption keyId for the given database so that
     * the next ident-create in `dbName` allocates a new generation. Called
     * synchronously from the dropDatabase path. Safe to call eagerly: the
     * underlying key bytes are NOT removed here, so any drop-pending idents
     * still encrypted under the previous generation continue to decrypt
     * correctly. Orphan cleanup deletes the actual key once no ident
     * references it (see `deleteEncryptionKey`).
     */
    virtual void keydbDropDatabase(const mongo::DatabaseName& dbName) {
        // do nothing for engines which do not support KeyDB
    }

    /**
     * Deletes a specific encryption key from the keyDB. Called by the
     * orphan-cleanup loop once `findOrphanedEncryptionKeyIds()` has determined
     * that no live ident and no active-keyId mapping references `keyId`.
     */
    virtual void deleteEncryptionKey(const std::string& keyId) {
        // do nothing for engines which do not support KeyDB
    }

    /**
     * Returns the sorted set of encryption keyIds that exist in the key database
     * but are not referenced by any storage ident (including drop-pending ones).
     *
     * Computed inside the engine because both inputs — the keydb listing and the
     * WT-metadata scan — are engine-internal. Callers re-verify each candidate
     * under a DB lock before deleting it; this method does not consult the
     * CollectionCatalog.
     */
    virtual std::vector<std::string> findOrphanedEncryptionKeyIds() {
        return {};  // empty for engines which do not support KeyDB
    }

    /**
     * Returns the interval in seconds between orphaned encryption key cleanup attempts.
     * 0 means periodic cleanup is disabled; >0 means enabled with that interval.
     */
    virtual int32_t getEncryptionKeyCleanupIntervalSeconds() const {
        return 0;  // disabled for engines which do not support KeyDB
    }

    /**
     * Cleans up orphaned encryption keys - keys that belong to databases that
     * no longer exist and are not in use by any storage idents.
     * Called unconditionally on startup, by the periodic cleanup process, and
     * by the cleanupOrphanedEncryptionKeys admin command. `trigger` is a short
     * string identifying the call site ("startup" / "periodic" / "command") so
     * the completion summary log can be filtered/audited.
     */
    virtual void cleanupOrphanedEncryptionKeys(mongo::OperationContext* opCtx,
                                               mongo::StringData trigger) {
        // do nothing for engines which do not support KeyDB
    }

    /**
     * Marks that an orphaned-encryption-key cleanup should run at the next
     * periodic tick. Called from dropDatabase paths so the periodic job can
     * skip the WT-metadata scan when nothing has been dropped since the last
     * run.
     */
    virtual void markEncryptionKeyCleanupDirty() {
        // do nothing for engines which do not support KeyDB
    }
};

}  // namespace percona
