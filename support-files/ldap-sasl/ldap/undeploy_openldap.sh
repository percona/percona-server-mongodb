#!/bin/bash

killall slapd
dpkg -r slapd ldap-utils
dpkg -P slapd ldap-utils
/bin/rm -rf /var/lib/ldap /etc/ldap

