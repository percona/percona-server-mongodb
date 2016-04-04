#!/bin/bash

# slapd ldap server isntallation on Ubuntu 14.x or 15.x

# Usage: ./deploy_sasl.sh {-h host} {-p port} {-d LDAP bind DN}

BASEDIR=$(dirname "$0")
# shellcheck disable=SC2086
source ${BASEDIR}/../settings.conf

# override LDAP host and port using command line options

while getopts :h:p:d: OPT; do
  case "${OPT}" in
    h) # host
      LDAP_HOST="${OPTARG}"
      ;;
    p) # port
      LDAP_PORT="${OPTARG}"
      ;;
    d) # LDAP bind DN
      LDAP_BIND_DN="${OPTARG}"
      ;;
  esac
done

# install sasl components 

apt-get install -y libsasl2-2 libsasl2-dev libsasl2-modules sasl2-bin || {
  echo "Could not install SASL components with apt-get.  Aborting..."
  exit 3
}

# stop the service

service saslauthd stop

# configure saslauthd

sed -ri s/^START=.*$/START=yes/ /etc/default/saslauthd
sed -ri s/^MECHANISMS=.*$/MECHANISMS=\"ldap\"/g /etc/default/saslauthd

cat << _EOF_ > /etc/saslauthd.conf
ldap_servers: ldap://${LDAP_HOST}:${LDAP_PORT}
ldap_auth_method: fastbind
ldap_filter: cn=%u,${LDAP_BIND_DN}
_EOF_

# mongodb conf

mkdir -p /etc/sasl2
cat << _EOF_ > /etc/sasl2/mongodb.conf
pwcheck_method: saslauthd
saslauthd_path: /var/run/saslauthd/mux
log_level: 5
mech_list: plain
_EOF_

# start the service

service saslauthd start

# wait for the service to startup

sleep 3

# test

testsaslauthd -u 'exttestro' -p "exttestro${LDAP_PASS_SUFFIX}"

