#!/bin/bash
#
PATH="${PATH}:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin"
#
touch /var/run/mongos.pid
touch /var/log/mongos/mongos.{stdout,stderr}
chown mongos:mongos /var/run/mongos.pid
