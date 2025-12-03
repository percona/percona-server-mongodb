# Profiling Rate Limit

The purpose of this feature is to limit the number of queries that are logged as part of the `mongod` profiling feature in order to reduce the performance impact of profiling. With using profiling rate limit the `mongod` server will spend less time preparing and reporting profile output and therefore lessen the operational impact of profiling.

## Implementation details

Profiling rate limit is an integer value in the range 1-1000. The rate limit value N represents a 1/N probability that a query will be profiled. Thus higher value will reduce the number of profiled queries. The default value of 1 will disable the feature entirely ( A 1/1 rate should log each query). For compatibility reasons a value of 0 will set the rate limit to 1 and in fact will disable the feature too.

The `mongod` profiling feature has three profiling levels: no profiling, slow queries profiling, all queries profiling. Profiling rate limit only affects the number of queries profiled in the "all queries" mode. Slow queries are always profiled in both "slow queries" and "all queries" modes no matter what is rate limit value. Other (not slow) queries are sampled as described above.

### system.profile collection extension

Each document in the `system.profile` collection will have additional `rateLimit` field. This field will always have value 1 for slow queries and will contain the current rate limit value for "fast" queries.

### Specifying profiling rate limit on the command line

To set profiling rate limit value on the command line use `rateLimit` parameter:

    ./mongod --rateLimit 100

### Specifying profiling rate limit in the configuration file

To set profiling rate limit value in the configuration file use `operationProfiling.rateLimit` parameter:

```
operationProfiling:
  mode: all
  slowOpThresholdMs: 200
  rateLimit: 100
```

### Accessing profiling rate limit value with setParameter/getParameter commands

You can use setParameter/getParameter commands with `profilingRateLimit` variable to set/get current rate limit value.

```
> db.getSiblingDB('admin').runCommand( { setParameter: 1, "profilingRateLimit": 79 } );
{ "was" : 1, "ok" : 1 }
> db.getSiblingDB('admin').runCommand( { getParameter: 1, "profilingRateLimit": 1 } );
{ "profilingRateLimit" : 79, "ok" : 1 }
```

### Accessing profiling rate limit value with 'profile' command

You can use `profile` command to set rate limit value in one batch with profiling level and other profiling parameters. As usual you can use `profile` command with -1 profiling level to check current settings.

```
> db.runCommand( { profile: 2, slowms: 150, ratelimit: 3 } );
{ "was" : 0, "slowms" : 100, "ratelimit" : 79, "ok" : 1 }
> db.runCommand( { profile: -1 } );
{ "was" : 2, "slowms" : 150, "ratelimit" : 3, "ok" : 1 }
```
