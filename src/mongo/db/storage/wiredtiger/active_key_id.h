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
class OperationContext;

namespace encryption {

/**
 * Returns the active encryption key id for `dbName`.
 *
 * The lookup is backed by a per-process cache on the global `EncryptionKeyDB`:
 *   1. Cache hit: the cached key id is returned immediately.
 *   2. Cache miss: scan `CollectionCatalog` for any live collection in
 *      `dbName`. If one exists, read its WT ident metadata to extract the
 *      `keyid="..."` clause; the first key id found is cached and returned.
 *      This preserves backward compatibility with the legacy bare-`<dbName>`
 *      format - existing tables continue to use whatever key id they were
 *      created with.
 *   3. Catalog empty: a fresh key id of the form `<dbName>.<UUID>` is
 *      generated, cached, and returned. After `dropDatabase` followed by a
 *      recreate, this is the path that produces a new generation.
 *
 * The header lives in a small target so it can be included from
 * `wiredtiger_customization_hooks.cpp` without dragging in WiredTiger headers.
 */
std::string activeKeyIdForDb(OperationContext* opCtx, const DatabaseName& dbName);

}  // namespace encryption
}  // namespace mongo
