# Environment Prerequisites

We need a suitable environment for testing our implementation of LDAP authentication for MongoDB.  These setup steps should be performed on a given Linux distribution, and certain open source components must be installed and then specially configured, for accurate testing to be performed.

## Component Installation

1. `libsasl2` - version 2.1.25 - C library used in client and server code.
2. `saslauthd` - SASL Authentication Daemon.  This is distinct from libsasl2.
3. `slapd` - OpenLDAP Server.

NOTE: We have been sandboxing the slapd daemon on our test machines.  This means we just download the OpenLDAP source code, build it locally, and install it in an arbitrary test directory local to the current tester's/user's working directory.

### Installing SASL

There are actually two SASL components that need to be installed.  First is the SASL library itself, `libsasl2`, along with it's development header `sasl.h`.  Second is `saslauthd`, the authentication daemon.

Both SASL components can be downloaded, built and installed from source.  Here is the instructions:

TODO

On Ubuntu, the following packages should be installed:
```
libsasl2-2
libsasl2-dev
libsasl2-modules
sasl2-bin
ldap-utils
```
(optional):
```
cyrus-sasl2-dbg
cyrus-sasl2-doc
```
### Building OpenLDAP

TODO...

# Environment Configuration

## Running the LDAP service

We want to start the LDAP server in the background or in a dedicated `tmux` pane for testing.  Note the given URL and configuration file.  Also note the username: openldapper.  It is important that the user starting the service, and adding entries to the LDAP database, has permissions to do so.

```
$ slapd -h ldap://127.0.0.1:9009/ -u openldapper -f /etc/openldap/slapd.conf -d 1
```

The URL argument will be used for both entering data into the LDAP database, verifying entries, and is an endpoint for `saslauthd` to authenticate against during MongoDB external authentication.  The -d option is for helpful debugging information to help track incoming LDAP requests and responses.

An LDAP configuration file, with simple settings suitable for testing, would have contents like this:
```
database        mdb
suffix          "dc=example,dc=com"
rootdn          "cn=openldapper,dc=example,dc=com"
rootpw          secret
directory       /home/openldapper/ldap/tests/openldap/install/var/openldap-data
```
There are other entries in the slapd.conf file that are important for successfully starting the LDAP service.  OpenLDAP installations have a sample `slapd.conf` file that has the above and other required entries, like `include`, `pidfile`, and `argsfile`.

NOTE: We use the mdb database here because we don't want to add a dependency on a Berkeley DB installation.  The MDB database is an in-memory database compiled-in as part of the OpenLDAP installation.

### Enter users into LDAP service.

OpenLDAP comes with a few programs to communicate with the LDAP daemon/service.  For example, to enter new entries into the LDAP database, one could use the `ldapadd` or `ldapmodify`, with an associated .ldif file.

# Building MongoDB

To connect to these services, MongoDB must be built with extra information.

## Adding SASL support

Both clien and server components, `mongo` and `mongod/mongos`, must be specially compiled to enable external authentication.

To setup the initial build environment you need to follow the basic build instructions.

https://github.com/Percona/percona-server-mongodb/docs/building.md

Both the client and server must be linked with `libsasl2.so`.  This just means that an extra flag `--use-sasl-client` must be passed to SCons at build configuration time.  A quick build would look like this:
```
$ cd percona-server-mongodb
$ git checkout v3.0
$ scons --use-sasl-client -j8 mongo mongod
```
Once configured, the mongo binaries can be built, installed, and packaged as usual.  Note that libsasl2 is NOT statically linked, so any user planning on running either the client or server binaries will need the SASL library installed in the same place it was installed at build time.
