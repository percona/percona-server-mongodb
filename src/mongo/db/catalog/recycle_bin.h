/**
 *    Copyright (C) 2024-present MongoDB, Inc.
 */

#pragma once

#include "mongo/base/status.h"
#include "mongo/base/status_with.h"
#include "mongo/db/catalog/collection.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/repl/optime.h"

namespace mongo {

class OperationContext;

namespace recycle_bin {

/**
 * Returns true when drop should be implemented as a same-database rename to __recycle_bin.*
 * instead of immediate catalog removal (WiredTiger pending-drop path).
 */
bool shouldInterceptDropForRecycleBin(OperationContext* opCtx,
                                      const NamespaceString& nss,
                                      const Collection* collection,
                                      bool markFromMigrate,
                                      const repl::OpTime& dropOpTime);

/**
 * Allocates a unique recycle-bin namespace in the same database as nss.
 * Collection name format: __recycle_bin.<unixSeconds>.<uuid>
 */
StatusWith<NamespaceString> allocateUniqueRecycleNamespace(OperationContext* opCtx,
                                                           const NamespaceString& nss);

/**
 * Drops expired recycle-bin collections on the current node (primary only per nss).
 */
void purgeExpiredCollections(OperationContext* opCtx);

}  // namespace recycle_bin
}  // namespace mongo
