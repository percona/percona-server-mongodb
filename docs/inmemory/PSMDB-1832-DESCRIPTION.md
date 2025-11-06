# PSMDB-1832: Preserve WiredTiger Options for inMemory Engine

## Overview

This commit (746a507950103c3544ca58893907005812edac76) introduces functionality to preserve and properly apply WiredTiger configuration options when using the inMemory storage engine in Percona Server for MongoDB.

## What This Commit Does

### Background

The inMemory storage engine is a special configuration of WiredTiger that keeps all data in memory rather than persisting it to disk. Prior to this change, there was a need to ensure that WiredTiger-specific configuration options could be properly preserved and applied when running the database with the inMemory engine.

### Key Changes

The commit implements the `syncInMemoryAndWiredTigerOptions()` function in `src/mongo/db/storage/inmemory/inmemory_init.cpp` which:

1. **Preserves User-Specified WiredTiger Options**: All `wiredTigerGlobalOptions` are preserved except those that are specific to the inMemory storage engine configuration.

2. **Synchronizes Cache Size Settings**: 
   - Takes the cache size from `inMemoryGlobalOptions.cacheSizeGB`
   - Applies it to `wiredTigerGlobalOptions.cacheSizeGB`
   - Ensures consistent memory allocation across the engine

3. **Synchronizes Statistics Logging**:
   - Transfers statistics logging delay settings from inMemory options to WiredTiger options
   - Controlled via `inMemoryGlobalOptions.statisticsLogDelaySecs`

4. **Configures Engine-Specific Settings**:
   - Sets up in-memory mode: `in_memory=true`
   - Disables logging: `log=(enabled=false)`
   - Configures file manager: `close_idle_time=0`
   - Sets checkpoint behavior: `wait=0,log_size=0`
   - User-defined `engineConfig` is appended AFTER default settings to allow overrides

5. **Manages Collection and Index Configurations**:
   - User-defined collection and index configs are applied FIRST
   - Then adds `cache_resident=false` to both collection and index configs
   - This ordering allows user customization while enforcing required inMemory settings

### Configuration Priority

The implementation follows a careful ordering strategy:

**For Engine Config:**
```
[InMemory defaults] + [User-defined engineConfig]
```
User settings can override defaults if needed.

**For Collection and Index Configs:**
```
[User-defined config] + [cache_resident=false]
```
User settings are preserved, with mandatory inMemory options appended.

## Technical Implementation Details

### Code Location
- Primary implementation: `src/mongo/db/storage/inmemory/inmemory_init.cpp`
- Options header: `src/mongo/db/storage/inmemory/inmemory_global_options.h`
- Options implementation: `src/mongo/db/storage/inmemory/inmemory_global_options.cpp`

### Function Flow

When creating an inMemory storage engine instance:

1. `InMemoryFactory::create()` is called
2. `syncInMemoryAndWiredTigerOptions()` executes first to merge configurations
3. WiredTiger configuration is constructed with `inMemory=true` flag
4. Cache size is calculated and validated
5. A `WiredTigerKVEngine` instance is created with the merged configuration
6. Extra options for record stores and indexes are applied

### Configuration Options

The inMemory engine supports the following configuration options:

- `--inMemorySizeGB`: Specifies cache size in gigabytes (fractional values allowed)
- `--inMemoryStatisticsLogDelaySecs`: Controls statistics logging frequency
- `--inMemoryEngineConfigString`: Custom WiredTiger engine configuration
- `--inMemoryCollectionConfigString`: Custom collection configuration
- `--inMemoryIndexConfigString`: Custom index configuration

## Benefits

1. **Flexibility**: Users can specify WiredTiger options that will be properly applied to the inMemory engine
2. **Consistency**: Ensures configuration options are handled consistently between WiredTiger and inMemory engines
3. **Customization**: Allows fine-tuned control over engine behavior while maintaining required inMemory constraints
4. **Safety**: Enforces required inMemory-specific settings (like `cache_resident=false`) that cannot be overridden

## Usage Example

```bash
$ mongod \
  --storageEngine=inMemory \
  --inMemorySizeGB=4.0 \
  --inMemoryStatisticsLogDelaySecs=60 \
  --inMemoryEngineConfigString="eviction=(threads_min=2,threads_max=4)" \
  --inMemoryCollectionConfigString="block_compressor=snappy" \
  --dbpath=/data/inmemory
```

In this example:
- 4GB of memory is allocated for the cache
- Statistics are logged every 60 seconds
- Eviction threads are customized
- Collections use Snappy compression
- All WiredTiger options are properly preserved and applied

## Related Files

- `src/mongo/db/storage/inmemory/inmemory_init.cpp` - Main implementation
- `src/mongo/db/storage/inmemory/inmemory_global_options.h` - Options structure
- `src/mongo/db/storage/inmemory/inmemory_global_options.cpp` - Options handling
- `src/mongo/db/storage/inmemory/inmemory_options_init.cpp` - Options initialization
- `docs/inmemory/README.md` - User documentation

## References

- JIRA Issue: PSMDB-1832
- Commit: 746a507950103c3544ca58893907005812edac76
- Author: Pawel Lebioda <pawel.lebioda@percona.com>
- Date: Tue Nov 4 08:35:03 2025 +0100
