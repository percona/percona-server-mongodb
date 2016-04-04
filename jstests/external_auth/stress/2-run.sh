#!/bin/bash

# number of simultaneous threads to run
threads=32

basedir=$(cd `dirname $0`;pwd)

source "${basedir}/_env.sh"

# run mongod with valgrind --tool=massif

cd ${basedir}
mkdir -p ${MONGODB_DATA}
truncate -s0 ${basedir}/mongod_valgrind.log 
valgrind --tool=massif \
  ${MONGODB_HOME}/bin/mongod --dbpath=${MONGODB_DATA} \
    --setParameter authenticationMechanisms=PLAIN,SCRAM-SHA-1 \
    --auth > ${basedir}/mongod_valgrind.log 2>&1 &

# wait until server is listening

tail -f ${basedir}/mongod_valgrind.log | while read LOGLINE
do
   [[ "${LOGLINE}" == *"waiting for connections"* ]] && pkill -P $$ tail
done

# run the stress test

for thread in $(seq 1 ${threads}); do
  ${MONGODB_HOME}/bin/mongo ${basedir}/extlogin.js > /dev/null 2>&1 &
done

