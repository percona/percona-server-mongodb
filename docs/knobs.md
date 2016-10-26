# Percona knobs variables

Percona Server for MongoDB makes several additional configuration values
available on the command line as well as in configuration files.

## cursorTimeoutMillis

Command line:

```
--cursorTimeoutMS {integer}
```

Configuration File:

```
Percona:
  cursorTimeoutMillis: {integer}
```

Default value: 600000 (Ten Minutes)

Sets the duration of time after which idle query cursors will be removed from
memory.

## failIndexKeyTooLong

Command Line:
```
--failIndexKeyTooLong {true|false}
```

Configuration File:
```
Percona:
  ignoreLongIndexError: {true|false}
```

Default value: true 

Older versions of MongoDB would insert and update documents even if an index
key was too long.  The documents would not be included in the index.  Newer
versions of MongoDB will not insert or update the documents with the failure.
By setting this value to false, the old behavior is enabled.

## internalQueryPlannerEnableIndexIntersection

Command Line:
```
--internalQueryPlannerEnableIndexIntersection {true|false}
```

Configuration File:
```
Percona:
  allowIndexIntersections: {true|false}
```

Default Value: true

Due to changes introduced in MongoDB 2.6.4, some  queries that reference
multiple indexed fields where one field matches no documents will choose
a non-optimal single-index plan.  Setting this value to false will enable
the old behavior and select the index intersection plan.

## ttlMonitorEnabled

Command Line:
```
--ttlMonitorEnabled {true|false}
```

Configuration File:
```
Percona:
  ttlEnabled: {true|false}
```

Default Value: true

If this option is set to false, the worker thread that monitors TTL Indexes
and removes old documents will be disabled.

## ttlMonitorSleepSecs

Command Line:
```
--ttlMonitorSleepSecs {int}
```
Configuration File:
```
Percona:
  ttlSleepSecs: {int}
```

Default Value: 60 (1 minute)

Defines the number of seconds to wait between checking TTL Indexes
for old documents and removing them.

