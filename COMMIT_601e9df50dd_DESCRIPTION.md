# Commit 601e9df50dd - Architecture Refactoring Description

## Overview

**Commit Hash:** 601e9df50dd69f7176535d82e8c301fae5d56905  
**Author:** Wei Hu <wei.hu@mongodb.com>  
**Date:** February 10, 2025  
**Jira Ticket:** SERVER-98989  
**Pull Request:** #31695  
**Commit Message:** Remove storage_engine_impl's dependency on CollectionCatalog

## Summary

This commit performs a significant architectural refactoring that removes the circular dependency between the storage engine implementation (`StorageEngineImpl`) and the `CollectionCatalog`. The refactoring improves separation of concerns by moving catalog-related operations out of the storage layer and into the catalog layer where they belong.

## Key Changes

### 1. Architecture Reorganization

**Problem Solved:**
- `StorageEngineImpl` previously had a tight coupling with `CollectionCatalog`, creating circular dependencies
- Storage engine layer was handling catalog-level operations like database listing and dropping

**Solution:**
- Moved catalog-aware operations from storage layer to catalog layer
- Storage engine now only handles durable catalog operations, not the in-memory collection catalog
- Clearer separation between storage concerns and catalog management

### 2. Interface Simplification

#### StorageEngine Interface Changes (`src/mongo/db/storage/storage_engine.h`)

**Methods Removed:**
- `listDatabases()` - Moved to catalog layer since it requires CollectionCatalog knowledge
- `dropDatabase()` - Moved to catalog layer 
- `dropCollectionsWithPrefix()` - Moved to catalog layer
- `sizeOnDiskForDb()` - Replaced with more granular `getIdentSize()`

**Methods Renamed/Refactored:**
- `loadCatalog()` → `loadDurableCatalog()` - Clarifies this loads only the durable catalog, not the full CollectionCatalog
- `closeCatalog()` → `closeDurableCatalog()` - Clarifies scope
- `getCatalog()` → `getDurableCatalog()` - Emphasizes this is only the durable catalog
- `sizeOnDiskForDb()` → `getIdentSize()` - More granular, operates on idents instead of databases

**Methods Added:**
- `stopTimestampMonitor()` - Allows external control of timestamp monitor lifecycle
- `restartTimestampMonitor()` - Allows restart after stop (e.g., during rollback)

#### StorageEngineImpl Changes (`src/mongo/db/storage/storage_engine_impl.h`)

**Removed Interface:**
- No longer implements `StorageEngineInterface` (which has been effectively removed)
- Removed 150+ lines of `TimestampMonitor` inner class definition

**Methods Removed:**
- `listDatabases()`
- `dropDatabase()`
- `dropCollectionsWithPrefix()`
- `getStorageEngine()` - No longer needed since it only returned `this`

**Moved Components:**
- `TimestampMonitor` class moved from `StorageEngineImpl` to `StorageEngine` base class
  - Makes timestamp monitoring available to all storage engine implementations
  - Better encapsulation as a storage engine concern rather than implementation detail

### 3. Code Movement and Consolidation

#### Deleted Files:
- `src/mongo/db/storage/storage_util.h` (60 lines removed)
- `src/mongo/db/storage/storage_util.cpp` (221 lines removed)
- `src/mongo/db/storage/storage_engine_interface.h` (46 lines removed)

These files contained operations that mixed storage and catalog concerns. Their functionality has been:
1. Moved to `collection_catalog_helper.h/cpp` for catalog operations
2. Integrated into `StorageEngine` base class for pure storage operations
3. Removed if obsolete

#### New/Enhanced Files:
- `src/mongo/db/catalog/collection_catalog_helper.h` (+73 lines)
- `src/mongo/db/catalog/collection_catalog_helper.cpp` (+255 lines)

These files now contain the catalog-aware operations that were previously in the storage layer:
- `removeIndex()` - Two-phase index drop
- `dropCollection()` - Two-phase collection drop
- `dropDatabase()` - Database deletion with catalog awareness
- `dropCollectionsWithPrefix()` - Prefix-based collection deletion
- `shutDownCollectionCatalogAndGlobalStorageEngineCleanly()` - Clean shutdown coordination
- `startUpStorageEngineAndCollectionCatalog()` - Startup coordination

### 4. CollectionCatalog Interface Changes

**New Methods Added:**
- Catalog-level operations for managing collections and databases
- Operations that understand the in-memory catalog state vs. durable storage

### 5. Dependent Component Updates

The following components were updated to use the new interfaces:

**Catalog Layer:**
- `catalog_control.cpp/h` - Updated to use new startup/shutdown helpers
- `collection_impl.cpp/h` - Updated catalog interactions
- `database_holder_impl.cpp` - Updated database operations
- `database_impl.cpp` - Updated database operations

**Command Layer:**
- `list_databases.cpp/h` - Updated to use catalog layer instead of storage layer
- `feature_compatibility_version.cpp` - Updated for new interfaces

**Replication Layer:**
- `rollback_impl.cpp` - Updated to use new timestamp monitor control
- `storage_interface_impl.cpp` - Updated storage operations
- `replication_coordinator_external_state_impl.cpp` - Updated coordination

**Core System:**
- `mongod_main.cpp` - Updated startup/shutdown using new helper functions
- `repair.cpp` - Updated repair operations
- `startup_recovery.cpp` - Updated recovery operations

**Tests:**
- Multiple test files updated to use new interfaces
- Tests now properly distinguish between durable catalog and in-memory catalog

### 6. Build System Updates

**Modified Build Files:**
- `src/mongo/db/catalog/BUILD.bazel` - Updated dependencies
- `src/mongo/db/repl/BUILD.bazel` - Updated dependencies
- `src/mongo/db/storage/BUILD.bazel` - Removed obsolete dependencies, cleaned up

## Impact Analysis

### Lines Changed:
- **Total:** 2,120 lines changed (1,034 additions, 1,086 deletions)
- **Files Modified:** 51 files

### Benefits:

1. **Better Separation of Concerns:**
   - Storage layer focuses on durable storage operations
   - Catalog layer handles in-memory catalog and coordination
   - Clearer boundaries between layers

2. **Reduced Circular Dependencies:**
   - Storage engine no longer depends on CollectionCatalog
   - Easier to understand and maintain code

3. **Improved Testability:**
   - Clearer interfaces make it easier to mock and test components independently
   - Better unit test isolation

4. **More Maintainable Code:**
   - Operations are in logical locations (catalog operations in catalog layer)
   - Reduced coupling makes future changes easier

5. **Better API Clarity:**
   - Method names better reflect their actual scope (e.g., `loadDurableCatalog` vs. `loadCatalog`)
   - Eliminated confusing dual-purpose methods

## Migration Guide

For code using the old APIs:

1. **Database listing:**
   ```cpp
   // Old:
   auto dbs = storageEngine->listDatabases();
   
   // New:
   auto dbs = CollectionCatalog::get(opCtx)->getAllDbNames();
   ```

2. **Database dropping:**
   ```cpp
   // Old:
   status = storageEngine->dropDatabase(opCtx, dbName);
   
   // New:
   status = catalog::dropDatabase(opCtx, dbName);
   ```

3. **Catalog loading:**
   ```cpp
   // Old:
   storageEngine->loadCatalog(opCtx, stableTs, lastShutdownState);
   
   // New:
   storageEngine->loadDurableCatalog(opCtx, lastShutdownState);
   // Then initialize CollectionCatalog separately
   ```

4. **Accessing durable catalog:**
   ```cpp
   // Old:
   auto catalog = storageEngine->getCatalog();
   
   // New:
   auto catalog = storageEngine->getDurableCatalog();
   ```

5. **Timestamp monitor lifecycle:**
   ```cpp
   // Old:
   storageEngine->startTimestampMonitor();
   
   // New:
   storageEngine->startTimestampMonitor({&listener1, &listener2});
   storageEngine->stopTimestampMonitor();  // Now can be stopped/restarted
   storageEngine->restartTimestampMonitor();
   ```

## Co-Authors

- Yujin Kang Park (@ykangpark)
- Gregory Noma

## Related Tickets

- **SERVER-98989:** Primary ticket for this refactoring
- **GitOrigin-RevId:** 23860763fa67a4e268ae8bef94f9a6f955b25531

## Testing

This refactoring maintains functional equivalence - no behavior changes, only structural improvements. All existing tests were updated to use the new interfaces and continue to pass.

## Conclusion

This commit represents a significant architectural improvement that removes a major source of circular dependencies in the MongoDB codebase. By clearly separating storage concerns from catalog management, the code becomes more maintainable, testable, and easier to understand. The refactoring follows best practices for layered architecture and sets a good foundation for future improvements to both the storage and catalog subsystems.
