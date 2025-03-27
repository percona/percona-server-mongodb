#!/bin/bash
#
PATH="${PATH}:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin"
#
touch /var/log/mongos/mongos.{stdout,stderr}
chown -R mongos:mongos /var/log/mongos
