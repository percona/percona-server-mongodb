# This script will run the full remote authentication suite

basedir=$(cd `dirname $0`;pwd)

# make sure LDAP/SASL auth is working

ldapsasldir=$(cd ../../../support-files/ldap-sasl;pwd)

(test -e ${ldapsasldir}/check_saslauthd.sh && \
    ${basedir}/../../../support-files/ldap-sasl/check_saslauthd.sh 2>/dev/null  | \
    grep -q 'OK "Success."') || {
  echo -e "\nERROR: slapd/saslauthd are not setup."
  echo -e "See: ${ldapsasldir}/README.md\n"
  exit 1;
}

# make sure environment is set

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
