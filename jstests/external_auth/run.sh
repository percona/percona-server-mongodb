#!/bin/bash

# This script will run the TokuDB external authentication test suite

### config ###

HALT_ON_ERROR=1
VERBOSE=0
MONGOD_WAIT=5

# This script will run the full remote authentication suite

if [ "${MONGODB_HOME}" == "" ]; then
  echo "Please set the MONGODB_HOME variable before running this script."
  exit 1;
fi  

if [ ! -x "$MONGODB_HOME/bin/mongod" ] || [ ! -x "${MONGODB_HOME}/bin/mongo" ]; then
  echo "Unable to find the mongod or mongo executables in the home directory"
  exit 1;
fi

if [ "${MONGODB_DATA}" == "" ]; then
  MONGODB_DATA="${MONGODB_HOME}/data"
fi
mkdir -p ${MONGODB_DATA}

# our base directory 

SCRIPTPATH=$(cd $(dirname "$0"); pwd)
PARENTPATH=$(cd "${SCRIPTPATH}/.."; pwd)

### functions ###

# report the status of the last script executed

function report_status {
  msg="$1"
  log="$2"
  exitStatus=$3
  if [ ${VERBOSE:-0} -gt 0 ] || [ ${exitStatus:-0} -gt 0 ]; then
    cat ${log}
  fi
  case $exitStatus in
    0) printf '\e[0;37m%-70.70s \e[1;32m   [OK]\e[0m\n' "$msg"
       ;;
    *) printf '\e[0;37m%-70.70s \e[1;31m[ERROR]\e[0m\n' "$msg"
       ;;
  esac
  if [ "${HALT_ON_ERROR}" == "1" ] && [ ${exitStatus:-0} -gt 0 ]; then
    shutdown_server
    exit ${exitStatus}
  fi
}

# Run the mongod server

function run_server {

  opts="$1"

  # disable transparent huge pages
  
  if [ -e /sys/kernel/mm/transparent_hugepage/enabled ]; then
    if grep -Fq '[always]' /sys/kernel/mm/transparent_hugepage/enabled; then
      echo never > /sys/kernel/mm/transparent_hugepage/enabled
      echo never > /sys/kernel/mm/transparent_hugepage/defrag
    fi
    # check to see if the settings took
    if grep -Fq '[always]' /sys/kernel/mm/transparent_hugepage/enabled; then
      echo "ERROR: Unable to disable transparent huge pages in the kernel."
      echo "You need to set this as root before running this script."
      echo "If you are running in a container, you need to set this in the"
      echo "host kernel."
      exit 1
    fi
  fi

  ${MONGODB_HOME}/bin/mongod --dbpath=${MONGODB_DATA} ${opts} > ${MONGODB_HOME}/mongod.log 2>&1 &
  MONGOD_PID=$!
  MONGO_EXIT=$?

  sleep ${MONGOD_WAIT}
    
  report_status "mongod startup (opts: ${opts})" "${MONGODB_HOME}/mongod.log" ${MONGO_EXIT}

}

# Shutdown mongod using the command line option

function shutdown_server {

  SHUTDOWNLOG=$(mktemp)

  ${MONGODB_HOME}/bin/mongod --dbpath=${MONGODB_DATA} --shutdown > ${SHUTDOWNLOG} 2>&1
  MONGO_EXIT=$?

  sleep ${MONGOD_WAIT}
    
  report_status "mongod shutdown" "${SHUTDOWNLOG}" ${MONGO_EXIT}

  if [ ${MONGO_EXIT:-0} -eq 0 ]; then
    rm ${SHUTDOWNLOG}
  fi

}

# Run the test suite

function run_scripts {
  mode="$1"
  SCRIPTLIST=$(
    awk 'BEGIN{FS=":"}/^\/\/[ \t]*sequence:/{printf "%-8d\t%s\n", $2, FILENAME}' \
      $(grep -El "mode:\s+${mode}" ${SCRIPTPATH}/*.js) \
    | sort -n \
    | awk '{print $2}'
  )
  for script in ${SCRIPTLIST}; do
    SCRIPTNAME=$(awk 'BEGIN{FS=":"}/\/\/[ \t]*name/{gsub(/^[ \t]+/, "", $2); print $2}' $script)  
    SCRIPTLOG=$(mktemp)
    ${MONGODB_HOME}/bin/mongo $script > ${SCRIPTLOG} 2>&1
    MONGO_EXIT=$?
    report_status "${SCRIPTNAME}" "${SCRIPTLOG}" ${MONGO_EXIT}
    if [ ${MONGO_EXIT:-0} -eq 0 ]; then
      rm $SCRIPTLOG
    fi
  done
}

### main script ###

# run the server without --auth

run_server 

# get mode: noauth script names in proper sequence

run_scripts "noauth"

# shutdown server

shutdown_server

# run the server in auth mode

run_server "--setParameter authenticationMechanisms=PLAIN,SCRAM-SHA-1 --auth"

# run the auth scripts in the proper sequence

run_scripts "auth"

# shutdown server

shutdown_server

