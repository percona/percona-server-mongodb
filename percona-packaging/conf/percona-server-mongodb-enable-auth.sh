#!/bin/bash
#
PATH="${PATH}:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin"
#
CONF_FORMAT="yaml"
AUTH_SECTION_EXISTS=0
[ -z "${CONF}" ] && CONF=/etc/mongod.conf

parse_yaml() {
   local s='[[:space:]]*' w='[a-zA-Z0-9_]*' fs=$(echo @|tr @ '\034')
   sed -ne "s|^\($s\)\($w\)$s:$s\"\(.*\)\"$s\$|\1$fs\2$fs\3|p" \
        -e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1$fs\2$fs\3|p"  $1 |
   awk -F$fs '{
      indent = length($1)/2;
      vname[indent] = $2;
      for (i in vname) {if (i > indent) {delete vname[i]}}
      if (length($3) > 0) {
         vn=""; for (i=0; i<indent; i++) {vn=(vn)(vname[i])("_")}
         printf("%s%s=\"%s\"\n", vn, $2, $3);
      }
   }'
}

get_value_from_yaml() {
    section=$1
    param=$2
    array=$(parse_yaml $CONF)
    result=0
    while IFS=' ' read -ra VALUES; do
        for value in "${VALUES[@]}"; do
            if [[ $value =~ ([^,]+).*"="\"([^,]+)\" ]]; then
                name=${BASH_REMATCH[1]}
                val=${BASH_REMATCH[2]}
            fi
            if [[ $name =~ $section && $name =~ $param ]]; then
                result=$val
                break
            fi
        done
    done <<< "$array"
    echo $result
}

add_value_to_yaml() {
    section=$1
    param=$2
    value=$3
    if [[ $CONF_FORMAT == "yaml" ]]; then
        if [[ $AUTH_SECTION_EXISTS == 1 ]]; then
            sed -i "s/authorization: disabled/authorization: enabled/" $CONF
        else
            secutity_line=$(grep "security:" $CONF)
            if [[ $secutity_line =~ '#security:' ]]; then
                auth_line=$(grep "authorization:" $CONF)
                regex='#  authorization:'
                if [[ $auth_line =~ $regex ]]; then
                    sed -i "s/#security:/security:/" $CONF
                    sed -i "s/#  authorization:.*$/  authorization: enabled/" $CONF
                else
                    sed -i "s/#security:/security:\n  authorization: enabled/" $CONF
                fi
            elif [[ $secutity_line != '' ]]; then
                auth_line=$(grep "authorization:" $CONF)
                regex='#  authorization:'
                if [[ $auth_line =~ $regex ]]; then
                    sed -i "s/#  authorization:.*$/  authorization: enabled/" $CONF
                else
                    sed -i "s/security:/security:\n  authorization: enabled/" $CONF
                fi
            else
                delim=$( grep '## Enterprise-Only Options:' $CONF )
                if [[ $delim == '' ]]; then
                    echo "security:" >> $CONF
                    echo "  authorization: enabled" >> $CONF
                else
                    sed -i "s/## Enterprise-Only Options:/security:\n  authorization: enabled\n## Enterprise-Only Options:/" $CONF
                fi
            fi
        fi
    fi
}

add_user_to_mongo() {
    port=$(get_value_from_yaml net port)
    user='dba'
    password=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1`
    password="${password%\\n}"
    echo "db.createUser({user: \"$user\", pwd: \"$password\", roles: [ \"root\" ] });" | /usr/bin/mongo -p $port localhost/admin
    if [ $? -eq 0 ];then
        echo -e "OK\tUser:${user}\tPassword:${password}"
    else
        echo "ERROR! User cannot be added!"
        exit 1
    fi
}

if [ ! -f /tmp/mongodb_create.lock ]; then
    if tty -s; then
        ASK=$(grep NOT_ASK $CONF | awk -F'#' '{print $1}')
        if [[ $ASK != "NOT_ASK=1" ]]; then
            AUTH_ENABLED=0
            auth_res=$(get_value_from_yaml security auth)
            if [[ $auth_res == enabled  ]]; then
                AUTH_ENABLED=1
            elif [[ $auth_res == disabled  ]]; then
                AUTH_ENABLED=0
                AUTH_SECTION_EXISTS=1
            elif [[ `egrep '^auth=1' $CONF` ]]; then
                AUTH_ENABLED=1
                CONF_FORMAT="conf"
            elif [[ `egrep '^auth=1' $CONF` ]]; then
                AUTH_ENABLED=0
                AUTH_SECTION_EXISTS=1
            fi
            if [[ $AUTH_ENABLED == 0 ]]; then
                read -t 15 -p "We have detected authentication is not enabled, would you like help creating your first user?(Y/n)" setup_auth
                if [ "$setup_auth" == "Y" -o "$setup_auth" == "y" ]; then
                    touch /tmp/mongodb_create.lock
                    if [ -x /usr/sbin/invoke-rc.d ]; then
                        invoke-rc.d mongod start &> /dev/null
                    else
                        /etc/init.d/mongod start &> /dev/null
                    fi
                    add_value_to_yaml security authentication true
                    add_user_to_mongo
                    if [ -x /usr/sbin/invoke-rc.d ]; then
                        invoke-rc.d mongod stop &> /dev/null
                    else
                        /etc/init.d/mongod stop &> /dev/null
                    fi
                    if [ "$?" != 0 ]; then
                        PID=$(ps wwaux | grep /usr/bin/mongod | grep -v grep | awk '{print $2}')
                        kill -9 $PID
                    fi
                    rm -rf /tmp/mongodb_create.lock
                else
                    read -t 15 -p "Would you like system to stop asking this question?(Y/n)" disable_ask
                    if [ "$disable_ask" == "Y" -o "$disable_ask" == "y" ]; then
                        echo -e "NOT_ASK=1#do not delete this line\n$(cat $CONF)" > $CONF
                    fi
                fi
            fi
        fi
    fi
fi
