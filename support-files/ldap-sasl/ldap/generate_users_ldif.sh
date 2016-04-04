#!/bin/bash

# This script generates a loader for the LDAP users used
# to test TokuMX ldap enterprise

BASEDIR=$(dirname $0)
source ${BASEDIR}/../settings.conf

cat <<_EOU_ |
exttestro
exttestrw
extotherro
extotherrw
extbothro
extbothrw
exttestrwotherro
exttestrootherrw
_EOU_

while read line
do
  cat <<_EOLDIF_
dn: cn=$line,dc=percona,dc=com
objectclass: organizationalPerson
cn: $line 
sn: $line
userPassword: ${line}${LDAP_PASS_SUFFIX}
description: ${line} userPassword

_EOLDIF_
done

