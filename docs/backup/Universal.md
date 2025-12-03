# Universal HotBackup

This document describes how to build, configure and use HotBackup for WiredTiger and RocksDB storage engines.

## Building Percona Server for MongoDB

When running SCons, from the top level of the MongoDB source tree, an extra option is needed to build the HotBackup commands. The `--hotbackup` flag must be added to the SCons arguments to build MongoDB.

```
scons --hotbackup ... mongod
```

## Using HotBackup

To take a HotBackup of the MongoDB files in your current `dbpath`, you can execute the following command as an administrator on the `admin` database:

```
> use admin
switched to db admin
> db.runCommand({createBackup: 1, backupDir: "/my/backup/data/path"})
{ "ok" : 1 }
```

You should receive an `{ "ok" : 1 }` object as a return value if the backup was successful. If there was an error, you will receive an error message along with failing `ok` status. It may look something like this:

```
> db.runCommand({createBackup: 1, backupDir: ""})
{ "ok" : 0, "errmsg" : "Destination path must be absolute" }
```

## Testing

There are dedicated backup JavaScript tests under the jstests/backup directory. To execute all of them run:

```
python buildscripts/resmoke.py --suites=backup
```
