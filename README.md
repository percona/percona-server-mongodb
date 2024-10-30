# Percona Server for MongoDB README

Welcome to Percona Server for MongoDB!

Percona Server for MongoDB is a free, enhanced, fully compatible, open source, drop-in replacement for MongoDB Community Edition with enterprise-grade features. It requires no changes to MongoDB applications or code.

## Components

- `mongod` - The database server.
- `mongos` - Sharding router.
- `mongo` - The database shell (uses interactive javascript).
- tools
  - `bsondump`
  - `mongodump`
  - `mongorestore`
  - `mongoexport`
  - `mongostat`
  - `perconadecrypt`

## Documentation

- [Percona Server for MongoDB Documentation](https://docs.percona.com/percona-server-for-mongodb/)
- [MongoDB Manual](https://docs.mongodb.com/manual/)

## Installation

Use [Installing Percona Server for MongoDB](https://docs.percona.com/percona-server-for-mongodb/latest/install/index.html) to navigate to the required installation instructions.

## Running

For command line options invoke:

```bash
$ ./mongod --help
```

To run a single server database:

```bash
$ sudo mkdir -p /data/db
$ ./mongod
$
$ # The mongo javascript shell connects to localhost and test database by default:
$ ./mongo
> help
```

## Drivers

Client drivers for most programming languages are available at
https://docs.mongodb.com/manual/applications/drivers/. Use the shell
(`mongo`) for administrative tasks.

## Packaging

Packages for Percona Server for MongoDB are created by Percona team and are available at [Percona website](https://www.percona.com/downloads).

## Community

Find answers to MongoDB-related questions on [Percona Server for MongoDB Forum](https://forums.percona.com/categories/percona-server-for-mongodb).

Get insights about MongoDB from experts in the industry on [Percona Database Performance Blog](https://www.percona.com/blog/category/mongodb/).

## Submitting bug reports or feature requests

If you find a bug in Percona Server for MongoDB, you can submit a report to the [JIRA issue tracker](https://jira.percona.com/projects/PSMDB) for Percona Server for MongoDB:
    https://jira.percona.com/projects/PSMDB

Start by searching the open tickets in [Percona's JIRA](https://jira.percona.com/projects/PSMDB) or [MongoDB's Jira](https://jira.mongodb.org/) for a similar report. If you find that someone else has already reported your problem, then you can upvote that report to increase its visibility.

If there is no existing report, submit a report following these steps:

1. Sign in to JIRA issue tracker. You will need to create an account if you do not have one.
2. In the Summary, Description, Steps To Reproduce, Affects Version fields describe the problem you have detected.
3. As a general rule of thumb, try to create bug reports that are:
    * Reproducible: describe the steps to reproduce the problem.
    * Specific: include the version of Percona Server for MongoDB, your environment, and so on.
    * Unique: check if there already exists a JIRA ticket to describe the problem.
    * Scoped to a Single Bug: only report one bug in one JIRA ticket.

## LICENSE

   Percona Server for MongoDB is [source-available software](https://en.wikipedia.org/wiki/Source-available_software).
