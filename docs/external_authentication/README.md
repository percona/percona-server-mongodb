External Authentication Documentation
============

This README describes how to create a one-machine installation of all the components necessary for testing LDAP authentication in MongoDB.

# Overview

Normally, a client needs to authenticate themselves against the MongoDB server user database before doing any work or reading any data from a `mongod` or `mongos` instance.  External authentication allows the MongoDB server to verify the client's user name and password against a separate service, such as OpenLDAP or Active Directory.

There are three high level components necessary for this external authentication to work:

1. LDAP Server - Remotely holds all user credentials (i.e. username and associated password).
2. SASL Daemon - Used as a MongoDB server-local proxy for the remote LDAP service.
3. SASL Library - Used by the MongoDB client and server to create authentication mechanism-specific data.

## Authentication Sequence

An authentication session in this environment moves from component to component in the following way:

1. A `mongo` client connects to a running mongod instance.
2. The client creates a special authentication request using the SASL library and a selected authentication mechanism (in this case `PLAIN`).
3. The client then sends this SASL request to the server as a special Mongo `Command`.
3. The `mongod` server receives this SASL Message, with its authentication request payload.
4.  The server then creates a SASL session scoped to this client, using its own reference to the SASL library.
4. `mongod` then passes the authentication payload to the SASL library, who in turn passes it on to the `saslauthd` daemon.
5. The `saslauthd` daemon passes the payload on to the LDAP service to get a YES or NO authentication response (in other words, does this user exist and is that their password).
6. The YES/NO response moves it way back from `saslauthd`, through the SASL library, to `mongod`.
7. The `mongod` server uses this YES/NO response to authenticate the client or reject the request.  
8. If successful, the client has authenticated and can proceed.

# Client Authentication

Use the following command to add an external user to the mongod server:

```
$ db.getSiblingDB("$external").createUser( {user : christian, roles: [ {role: "read", db: "test"} ]} );
```

When running the `mongo` client, a user can authenticate against a given database by using the following command:
```
$ db.getSiblingDB("$external").auth({ mechanism:"PLAIN", user:"christian", pwd:"secret", digestPassword:false})
```

## References

SASL documentation:

http://cyrusimap.web.cmu.edu/docs/cyrus-sasl/2.1.25/



