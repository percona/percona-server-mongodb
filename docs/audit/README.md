
# Auditing

This document describes how to build, enable, configure and test auditing in Percona Server for MongoDB.  

Auditing allows administrators to track and log user activity on a server.  With auditing enabled, the server 
will generate an audit log file. This file contains information about different user events including authentication, authorization failures, and more.

## Building

By default, when building Percona Server for MongoDB from source, audit functionality is 
neither compiled with, nor linked into, the final binary executable.  To enable auditing, execute
SCons with the `--audit` argument:

    scons <other options> --audit <targets>

## Activation and Configuration

The following server parameters control auditing.  They are entered at the command line when starting a server instance.

###--auditDestination

By default, even when auditing functionality is compiled into the server executable, audit logging is disabled.  
Auditing and audit log generation are activated when this parameter is present on the command line at server startup.

The argument to this parameter is the type of audit log the server will create when storing events.  
In Percona Server for MongoDB, valid values for this argument are `file`, `console` and `syslog`.

```
mongod --auditDestination=file
```

**Note:** Auditing remains active until shutdown, it cannot be disabled dynamically at runtime.

###--auditFormat

This is the format of each audit event stored in the audit log. Format can
be set only when `auditDestination` is `file`. For `console` and `syslog` destinations output format is always `JSON`.
For `file` destination available formats are `JSON` or `BSON`.

The default value for this parameter is `JSON`.

When `BSON` format is specified you can decode audit log file using `bsondump` utility from `mongo-tools`.

```
mongod --auditDestination=file --auditFormat=BSON
```

###--auditPath

This is the fully qualified path to the file you want the server to create.
If this parameter is not specified then `auditLog.json` file will be created in server's configured log path.

```
mongod --auditDestination=file --auditPath /var/log/tokumx/audit.json
```

If log path is not configured then `auditLog.json` will be created in the current directory.

**Note:** This file will rotate in the same manner as the system logpath, either on server reboot or 
using the logRotate command. The time of the rotation will be added to old file’s name.

###--auditFilter

This parameter specifies a filter to apply to incoming audit events, 
allowing the administrator to only capture a subset of all possible audit events.  

This filter should be a JSON string that can be interpreted as a query object; 
each audit log event that matches this query will be logged, 
events which do not match this query will be ignored.  If this parameter is 
not specified then all audit events are stored in the audit log.

**Example:** 

To log only events from a user named “tim”, start the server with the following parameters:

```
$ mongod                                \
--auditDestination file                 \
--auditFormat JSON                      \
--auditPath /var/log/tokumx/audit.json  \
--auditFilter '{ "users.user" : "tim" }'
```

###auditAuthorized parameter
By default auditing in Percona Server for MongoDB logs only unauthorized operations.
With auditAuthorized parameter set to ```true``` both authorized and unauthorized operations will be logged.

To set auditAuthorized parameter at startup run server with following options:
```
mongod  --auditDestination=file --setParameter=auditAuthorized=true
```

You can also change auditAuthorized parameter at runtime with command:
```
db.adminCommand({ setParameter: 1, 'auditAuthorized': true });
```

**Note:** Setting this parameter to ```true``` may strongly affect performance.
## Testing

There are dedicated audit JavaScript tests under the jstests/audit directory. To execute all of
them run:

    python buildscripts/resmoke.py --audit

**Note:** the `mongoimport` utility is required to run the audit tests. 
It must be placed in the same directory from which `resmoke.py` is run. 
Typically this location is the top level MongoDB build/source directory.
