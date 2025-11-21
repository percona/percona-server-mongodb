# InMemory engine

This document describes how to enable, configure and test InMemory engine in Percona Server for MongoDB.

InMemory engine is a special configuration of WiredTiger that doesn’t store user data on disk.
With this engine, data fully resides in the virtual memory of the system.

## Activation and Configuration

To use InMemory engine, run mongod with `--storageEngine=inMemory` option.

The engine can be configured to use desired amount of memory with `--inMemorySizeGB` option.
This option takes fractional numbers to allow precise memory amount specification.
The data isn’t stored between restarts.

Despite the fact that the engine is purely in-memory, there is small amount of diagnostic data and
statistics collected and written on disk (the latter can be controlled with `--inMemoryStatisticsLogDelaySecs` option).
This also means that the engine uses `--dbpath` to store files, and in general it cannot run on the database directory
previously used by any other engine, including WiredTiger.

**Example:**

```
$ mongod                            \
--storageEngine=inMemory            \
--inMemorySizeGB=3.5                \
--inMemoryStatisticsLogDelaySecs=0
```

## Testing

The way of testing InMemory engine is no different from other storage engines.
Refer to WiredTiger testing procedure for more information.
