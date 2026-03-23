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

#include <string>

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
     * Mark a database as dropped and pending key deletion.
     * The encryption key will be deleted when all pending ident drops complete,
     * unless the database is recreated (which cancels the pending deletion).
     */
    virtual void keydbMarkDatabaseDropped(const mongo::DatabaseName& dbName) {
        // do nothing for engines which do not support KeyDB
    }

    /**
     * Increment pending drop count for a database.
     * Called when an ident is scheduled for deferred drop.
     */
    virtual void keydbIncrementPendingDropCount(const std::string& keyid) {
        // do nothing for engines which do not support KeyDB
    }

    /**
     * Decrement pending drop count for a database.
     * When count reaches zero AND the database is still marked for deletion
     * (wasn't recreated), delete the encryption key.
     */
    virtual void keydbDecrementPendingDropCount(const std::string& keyid) {
        // do nothing for engines which do not support KeyDB
    }

    /**
     * Get the current keyid for a database (with generation suffix if applicable).
     * For a database "test" that was dropped and recreated, this returns "test.v1", etc.
     * For a database that was never dropped, returns the plain database name.
     * This is used when creating new tables to get the correct encryption keyid.
     */
    virtual std::string keydbGetCurrentKeyId(const std::string& dbName) {
        // Default: return dbName unchanged (for non-TDE engines)
        return dbName;
    }
};

}  // namespace percona
