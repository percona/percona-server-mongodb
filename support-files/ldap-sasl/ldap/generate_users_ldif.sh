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
Surname\\, Name
Question? Mark! *{[(\\<\\>)]} #\\"\\+\\\\
_EOU_

while read -r line
do
  cat <<_EOLDIF_
dn: cn=$line,${LDAP_BIND_DN}
objectclass: organizationalPerson
cn: $line 
sn: $line
userPassword: ${line}${LDAP_PASS_SUFFIX}
description: ${line} userPassword

_EOLDIF_
done

