#!/bin/bash

basedir=$(cd `dirname $0`;pwd)

source "${basedir}/_env.sh"

# run
 
cd ${basedir}
mkdir -p ${MONGODB_DATA}
${MONGODB_HOME}/bin/mongod --dbpath=${MONGODB_DATA} \
  --setParameter authenticationMechanisms=PLAIN,SCRAM-SHA-1 \
  > ${basedir}/mongod.log 2>&1 &

# clean up data - create local admin user

${MONGODB_HOME}/bin/mongo ${basedir}/../setup.js

${MONGODB_HOME}/bin/mongod --dbpath=${MONGODB_DATA} --shutdown

# run with auth

${MONGODB_HOME}/bin/mongod --dbpath=${MONGODB_DATA} \
  --setParameter authenticationMechanisms=PLAIN,SCRAM-SHA-1 \
  --auth >> ${basedir}/mongod.log 2>&1 &

# add external users

${MONGODB_HOME}/bin/mongo ${basedir}/../addExtUsers.js

# shutdown (ready to run stress test)

${MONGODB_HOME}/bin/mongod --dbpath=${MONGODB_DATA} --shutdown

