#!/bin/bash

# This script checks to insure that OpenLDAP (slapd) authentication through
# SASL (saslauthd) is operation on the current host.

# Author: Joel Epstein - 2015-06-29

# Modified: David Bennett = 2015-07-12

BASEDIR=$(dirname $0)

# run under sudo unless we are already root

if [[ $EUID -ne 0 ]]; then
  # running as user
  hash sudo 2>/dev/null || { 
    echo >&2 "Script must be run as root or with the sudo command installed."
    exit 1;
  }
  SUDO="sudo"
else
  # running as root
  SUDO=""
fi

# install net-tools for netstat if it is not installed

hash netstat 2>/dev/null || {
  apt-get install -y net-tools || {
    echo "Failed to install net-tools for the netstat command"
    exit 1;
  }
}

# return the user password from our LDAP database source

function userPass {
  USER=$1
  RET=$(awk "f&&/^userPassword:/{print \$2;f=0} /^cn: ${USER}/{f=1}" $BASEDIR/ldap/users.ldif)
  echo -n $RET
}

# run the tests

echo "---------------------------------------------------------------"
echo
echo "Here is the process list showing saslauthd:"
echo
ps -ef | grep saslauthd
echo
echo "---------------------------------------------------------------"
echo
echo "Here is the netstat output (hopefully) showing ESTABLISHED connections to the named socket:"
echo
${SUDO} netstat -antulp | grep saslauthd
echo
echo "---------------------------------------------------------------"

# iterate through the users in our database

LDAPUSERS=$(awk 'BEGIN{ORS=" "} /^cn:/{print $2}' $BASEDIR/ldap/users.ldif)

for userName in ${LDAPUSERS}; do
  echo ${SUDO} testsaslauthd -u ${userName} -p $(userPass ${userName}) -f /var/run/saslauthd/mux
  ${SUDO} testsaslauthd -u ${userName} -p $(userPass ${userName}) -f /var/run/saslauthd/mux
done

# show netstat again

echo "--------------------------------------------------------------"
echo
echo "Here is the netstat output again for emphasis:"
echo
${SUDO} netstat -antulp | grep saslauthd
echo
echo "--------------------------------------------------------------"
echo "DONE"

