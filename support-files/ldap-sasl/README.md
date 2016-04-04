# Deploying OpenLDAP Server (slapd) and Cyrus SASL (libsasl2 & saslauthd)

These scripts will deploy OpenLDAP slapd and Cyrus SASL saslauthd on
Ubuntu 14.x or Debian 7.x in order to test the SASL/LDAP external
authentication funcationality of Percona Server for MongoDB.

As root user:

```sh
cd support-files/ldap-sasl
./deploy_ldap_and_sasl.sh
```

After the scripts run you should see `0: OK "Success."` reported at the end.   To run a test of the OpenLDAP/Cyrus SASL installation you can run the `check_saslauthd.sh` script.

```sh
./check_saslauthd.sh
```

This will insure all the proper LDAP authentication for all of the accounts used in the TokuMX LDAP test suite.

