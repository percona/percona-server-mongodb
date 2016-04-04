This document describes how to configure `saslauthd`, `libsasl2`, `mongo`, and `mongod/mongos` to use external authentication.  This assumes that those binaries have been installed in the proper locations and an LDAP service has been setup, is reachable, and has users and credentials installed.

# Configure saslauthd

First, we have to make sure saslauthd is configured properly.  saslauthd, like many of the systems in this project, rely on a .conf file.

## OpenLDAP

These are the typical settings required for saslauthd to connect to a local OpenLDAP service (the server address MUST match the OpenLDAP installation):
```
ldap_servers: ldap://127.0.0.1:9009
ldap_search_base: dc=example,dc=com
ldap_filter: (cn=%u)
ldap_bind_dn: cn=openldapper,dc=example,dc=com
ldap_password: secret
```
Note how the LDAP password and bind domain name are here.  This allows the `saslauthd` service to connect to the LDAP service as the root user.  In production this would not be the case; users should not store the administrative passwords in the clear.  This is a temporary setup for testing.

## Microsoft Windows Active Directory

In order for LDAP operations to be performed against a Windows Active Directory server, a user record must be created to perform the look ups.

For saslauthd to successfully communicate with an Active Directory server it must use the a .conf file of the following form:
```
ldap_servers: <ldap uri>
ldap_mech: PLAIN
ldap_search_base: CN=Users,DC=<AD Domain>,DC=<AD TLD>
ldap_filter: (sAMAccountName=%u)
ldap_bind_dn: CN=<AD LDAP lookup user name>,CN=Users,DC=<AD Domain>,DC=<AD TLD>
ldap_password: <AD LDAP lookup password>
```

For example:

```
ldap_servers: ldap://198.51.100.10
ldap_mech: PLAIN
ldap_search_base: CN=Users,DC=example,DC=com
ldap_filter: (sAMAccountName=%u)
ldap_bind_dn: CN=ldapmgr,CN=Users,DC=<AD Domain>,DC=<AD TLD>
ldap_password: ld@pmgr_Pa55word
```

In order to determine and test the correct search base and filter for your Active Directory installation,  the Microsoft [LDP GUI Tool](https://technet.microsoft.com/en-us/library/Cc772839%28v=WS.10%29.aspx) can be used to bind and search the LDAP-compatibile directory.

## Sanity Check

Verify that the `saslauthd` service can authenticate against the users created in the LDAP service:

```
$ testsaslauthd -u christian -p secret  -f /var/run/saslauthd/mux
```

This should return `0:OK "Success."`  If it doesn't then either the username and password are not in the LDAP service, or `sasaluthd` is not configured properly.

# Configure libsasl2

The SASL library used by `mongod/mongos` must also be configured properly via .conf file.
```
pwcheck_method: saslauthd
saslauthd_path: /var/run/saslauthd/mux
log_level: 5
mech_list: plain
```
The first two entries, `pwcheck_method` and `saslauthd_path`, are required for mongod/mongos to successfully use the saslauthd service.  The log_level is optional but may help determine configuration errors.

The file **must** be named `mongodb.conf` and placed in a directory where `libsasl2` can find it and read it.  `libsasl2` is hard coded to look in certain directories at build time.  This location may be different depending on the installation method.

# Configure mongod/mongos Server

External authentication is enabled the same way as local authentication.  Simply start the server with the `--auth` argument:

```
./mongod --dbpath=/data/db --auth
```

This assumes that libsasl2 has been installed in the system as a dynamic library (a.k.a. `libsasl2.so`).  You may see an error on the command line or in the logs if that library is missing from your server's environment.

# Adding external users

Use the following command to add an external user to the mongod server:

```
$ db.getSiblingDB("$external").createUser( {user : christian, roles: [ {role: "read", db: "test"} ]} );
```

Currently, you can only add externally authenticated users using the `mongo` shell included with the TokuMX build.  The command is a hybrid of 2.4 and 2.6 administration methods.  This also assumes that you have setup the server-wide admin user/role and have successfully locally authenticated as that admin user.

The `mongo` client will add an external user to each database filed in the roles array.  To remove a user from a database simply use the existing 2.4 `db.removeUser()` call.

NOTE: There is no single command to remove the external user from all the databases.  The `removeUser()` command must be called on each database for the given user.

NOTE: External users cannot have roles assigned in the 'admin' database.

# Client Authentication

When running the `mongo` client, a user can authenticate against a given database by using the following command:
```
$ db.auth({ mechanism:"PLAIN", user:"christian", pwd:"secret", digestPassword:false})
```

The other MongoDB drivers need to support the 2.4 interface for authenticating externally.  This means they must be:

1. Compiled/run with SASL authentication support.  Should include usage of the libsasl2 library.
2. Allows users to specify a BSON argument for auth() calls.
3. Allows users to specify the authentication `mechanism` field in the BSON argument.
4. Allows users to specify the `digestPassword` field.

Our implementation follows the 2.4 mongo client code, though some drivers diverge from this logic.  For example, some driver versions only conform to the 2.6 external authentication API, which will not work with the 2.4-based TokuMX implementation.

These newer driver clients expect the external user to only authenticate against the `"$external"` database, not a regular local database.  The driver may need to be modified to detect the mechanism field being set, and then take the external authentication path, using the local db name instead of `$external`.  Drivers that are totally compatible with the 2.4 `mongo` client should work as expected.