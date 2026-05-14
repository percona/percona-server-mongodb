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

// Forward-declaration header for `encryption::activeKeyIdForDb`. Kept
// intentionally free of WiredTiger and EncryptionKeyDB includes so the
// `storage_wiredtiger_customization_hooks` bazel target (which has no
// WiredTiger dependency) can call into the keys DB without pulling in
// `<wiredtiger.h>`. The function is defined in `encryption_keydb.cpp`
// and resolved at final-binary link time.
namespace mongo {
class DatabaseName;
class OperationContext;

namespace encryption {

// Returns the active encryption keyId for the given database. The lookup
// is backed by the in-memory cache on the global `EncryptionKeyDB`:
//
//   1. Cache hit: cached keyId returned, refcount URI ref incremented.
//   2. Cache miss + non-empty catalog for `dbName`: scan
//      `CollectionCatalog::range(dbName)`, read the keyId out of any
//      existing collection's WT ident metadata, cache it. Preserves
//      backward compatibility with the legacy bare-`<dbName>` format
//      created by pre-Phase-1 code.
//   3. Cache miss + empty catalog (genuinely-new database): a fresh
//      `<dbName>.<UUID>` is allocated, cached, and returned. After
//      `keydbDropDatabase` followed by a recreate, this is the path
//      that produces a new generation.
//
// `opCtx` must be non-null and carry a `WiredTigerRecoveryUnit` so the
// catalog scan and per-ident metadata reads can run. Callers without an
// OpCtx (internal startup paths, size storer table, etc.) should fall
// back to a bare-`<dbName>` keyId via the customization hook's nullptr
// branch rather than calling this function with a null OpCtx.
std::string activeKeyIdForDb(OperationContext* opCtx, const DatabaseName& dbName);

}  // namespace encryption
}  // namespace mongo
