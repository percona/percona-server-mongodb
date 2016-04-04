#!/bin/bash

# slapd ldap server installation on Ubuntu 14.x or 15.x

BASEDIR=$(dirname $0)
source ${BASEDIR}/../settings.conf

# install debconf utils and ldap utils

apt-get install -y debconf-utils ldap-utils || {
  echo "Could not install prerequisites with apt-get.  Aborting..."
  exit 3
}

# set configuration variables

export DEBIAN_FRONTEND=noninteractive
echo -e "\
slapd   slapd/password1 password ${LDAP_ADMIN_PASSWORD}
slapd   slapd/password2 password ${LDAP_ADMIN_PASSWORD}
slapd	slapd/internal/adminpw password ${LDAP_ADMIN_PASSWORD}
slapd	slapd/internal/generated_adminpw password ${LDAP_ADMIN_PASSWORD}
slapd   slapd/domain string ${LDAP_DOMAIN}
slapd   shared/organization string '${LDAP_DOMAIN}
" | debconf-set-selections 

# install and configure slapd

apt-get install -y slapd  || {
  echo "Could not install slapd apt-get.  Aborting..."
  exit 3  
}

# start the service

service slapd start

# add the test users

${BASEDIR}/generate_users_ldif.sh > ${BASEDIR}/users.ldif
ldapadd -D "cn=admin,${LDAP_BIND_DN}" -w ${LDAP_ADMIN_PASSWORD} -f ${BASEDIR}/users.ldif

# dump LDAP data

ldapsearch -z 0 -b "${LDAP_BIND_DN}" -D "cn=admin,${LDAP_BIND_DN}" -w ${LDAP_ADMIN_PASSWORD} "(objectclass=*)"

