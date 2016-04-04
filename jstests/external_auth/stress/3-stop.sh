#!/bin/bash

basedir=$(cd `dirname $0`;pwd)

source "${basedir}/_env.sh"

# stop

kill $(ps aux | grep '[m]ongo .*extlogin' | awk '{print $2}')
${MONGODB_HOME}/bin/mongod --dbpath=${MONGODB_DATA} --shutdown
