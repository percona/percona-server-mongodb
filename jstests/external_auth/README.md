# Percona Server for MongoDB LDAP test suite

This script assumes you have deployed the LDAP and SASL packages from the
/setup directory.

In order to run this tests, you must first build the Percona Server for
MongoDB with SASL authentication support and install.

Set the MONGODB_HOME shell variable to the directory you install into 
and execute the ./run.sh

example:

        cd support-files/ldap-sasl
        ./deploy_ldap_and_sasl.sh
        cd ../../jstests/external_auth
        export MONGODB_HOME=/opt/percona-server-for-mongodb
        ./run.sh
