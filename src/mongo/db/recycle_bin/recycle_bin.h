/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2026-present Percona and/or its affiliates. All rights reserved.

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

#include "mongo/base/status.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/db/database_name.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/service_context.h"
#include "mongo/db/shard_role/ddl/drop_gen.h"
#include "mongo/util/uuid.h"

#include <string>
#include <vector>

#include <boost/optional/optional.hpp>

namespace mongo {

constexpr auto kRecycleBinPrefix = "system.recycle_bin."_sd;

struct RecycleBinEntryInfo {
    NamespaceString recycleBinNss;
    std::string originalCollection;
    std::string db;
    long long dropTimeSecs;
};

/**
 * Builds a recycle bin namespace for the given collection.
 * Format: <db>.system.recycle_bin.<original_coll>.<epoch_seconds>
 * If that name already exists, appends the first 8 hex chars of the collection UUID.
 */
NamespaceString makeRecycleBinNss(const NamespaceString& originalNss,
                                  long long dropTimeSecs,
                                  const boost::optional<UUID>& collUuid = boost::none);

/**
 * Parses a recycle bin namespace to extract the original collection name and drop timestamp.
 * Returns boost::none if the namespace doesn't match the expected format.
 */
boost::optional<RecycleBinEntryInfo> parseRecycleBinNss(const NamespaceString& nss);

/**
 * Intercepts a collection drop and redirects it to the recycle bin by renaming the collection.
 * Returns true if the drop was intercepted (collection renamed to recycle bin).
 * Returns false if the recycle bin is disabled or the namespace is excluded.
 */
bool recycleBinInterceptDrop(OperationContext* opCtx,
                             const NamespaceString& nss,
                             const boost::optional<UUID>& expectedUUID,
                             DropReply* reply);

/**
 * Restores a collection from the recycle bin back to its original namespace.
 * Optionally allows specifying a different target namespace via restoreAs.
 */
Status recycleBinRestore(OperationContext* opCtx,
                         const NamespaceString& recycleBinNss,
                         const boost::optional<NamespaceString>& restoreAs = boost::none);

/**
 * Lists all collections currently in the recycle bin for a given database.
 * If dbName is empty, lists across all databases.
 */
std::vector<RecycleBinEntryInfo> recycleBinList(OperationContext* opCtx,
                                                const DatabaseName& dbName);

/**
 * Starts the background purge thread that removes expired recycle bin entries.
 */
void startRecycleBinPurger(ServiceContext* serviceContext);

/**
 * Shuts down the background purge thread.
 */
void shutdownRecycleBinPurger(ServiceContext* serviceContext);

}  // namespace mongo
