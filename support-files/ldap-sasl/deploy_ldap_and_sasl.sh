#!/bin/bash

# deploy OpenLDAP (slapd) and saslauthd to the local machine (Ubuntu 14.x or 15.x)

BASEDIR=$(dirname $0)

${BASEDIR}/ldap/deploy_openldap.sh
${BASEDIR}/sasl/deploy_sasl.sh

