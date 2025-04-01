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

# configure memberof overlay
ldapmodify -Q -Y EXTERNAL -H ldapi:/// <<EOF
dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: memberof.la
EOF

ldapadd -Y EXTERNAL -H ldapi:/// <<EOF
dn: olcOverlay=memberof,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcMemberOf
olcOverlay: memberof
olcMemberOfRefint: TRUE
olcMemberOfDangling: ignore
olcMemberOfGroupOC: groupOfNames
olcMemberOfMemberAD: member
olcMemberOfMemberOfAD: memberOf
EOF

# add the test users

${BASEDIR}/generate_users_ldif.sh > ${BASEDIR}/users.ldif
ldapadd -D "cn=admin,${LDAP_BIND_DN}" -w ${LDAP_ADMIN_PASSWORD} -f ${BASEDIR}/users.ldif

# add user groups
ldapadd -D "cn=admin,${LDAP_BIND_DN}" -w ${LDAP_ADMIN_PASSWORD} -f ${BASEDIR}/groups.ldif

# dump LDAP data

ldapsearch -z 0 -b "${LDAP_BIND_DN}" -D "cn=admin,${LDAP_BIND_DN}" -w ${LDAP_ADMIN_PASSWORD} "(objectclass=*)"

