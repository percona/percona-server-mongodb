# Percona Server for MongoDB <br/> setParameter tuning guide

There are several setParameter options that can be used to
adjust the operation of Percona Server for MongoDB.

## cursorTimeoutMillis

Command line:

```
--setParameter cursorTimeoutMillis={integer}
```

Configuration File:

```
setParameter:
  cursorTimeoutMillis: {integer}
```

Default value: 600000 (Ten Minutes)

Sets the duration of time after which idle query cursors will be removed from
memory.

## failIndexKeyTooLong

Command Line:

```
--setParameter failIndexKeyTooLong={true|false}
```

Configuration File:

```
setParameter:
  failIndexKeyTooLong: {true|false}
```

Default value: true

Versions of MongoDB prior to 2.6 would insert and update documents even if an
index key was too long. The documents would not be included in the index.
Newer versions of MongoDB will not insert or update the documents with the
failure. By setting this value to false, the old behavior is enabled.

This parameter is deprecated in version 4.2 and removed in version 4.4.
Starting from version 4.2 server correctly handles long index keys (see
SERVER-36278).

## internalQueryPlannerEnableIndexIntersection

Command Line:

```
--setParameter internalQueryPlannerEnableIndexIntersection={true|false}
```

Configuration File:

```
setParameter:
  internalQueryPlannerEnableIndexIntersection: {true|false}
```

Default Value: true

Due to changes introduced in MongoDB 2.6.4, some queries that reference
multiple indexed fields where one field matches no documents will choose
a non-optimal single-index plan. Setting this value to false will enable
the old behavior and select the index intersection plan.

## ttlMonitorEnabled

Command Line:

```
--setParameter ttlMonitorEnabled={true|false}
```

Configuration File:

```
setParameter:
  ttlMonitorEnabled: {true|false}
```

Default Value: true

If this option is set to false, the worker thread that monitors TTL Indexes
and removes old documents will be disabled.

## ttlMonitorSleepSecs

Command Line:

```
--setParameter ttlMonitorSleepSecs={int}
```

Configuration File:

```
setParameter:
  ttlMonitorSleepSecs: {int}
```

Default Value: 60 (1 minute)

Defines the number of seconds to wait between checking TTL Indexes
for old documents and removing them.
