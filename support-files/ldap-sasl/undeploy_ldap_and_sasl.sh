#!/bin/bash

# undeploy OpenLDAP (slapd) and saslauthd to the local machine (Ubuntu 14.x or 15.x)

BASEDIR=$(dirname $0)

${BASEDIR}/sasl/undeploy_sasl.sh
${BASEDIR}/ldap/undeploy_openldap.sh

