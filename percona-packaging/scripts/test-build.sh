#!/bin/bash

function check_libs {
    for elf in $(find $1 -maxdepth 1 -exec file {} \; | grep 'ELF ' | cut -d':' -f1); do
        echo $elf
        ldd $elf | grep "not found"
    done
    return
}

function prepare {
    CURDIR=$(pwd)

    if [ -f /etc/redhat-release ]; then
        GLIBC_VER="$(rpm glibc -qa --qf %{VERSION})"
    else
        GLIBC_VER="$(dpkg-query -W -f='${Version}' libc6 | awk -F'-' '{print $1}')"
    fi

    TARBALLS=""
    for tarball in $(find . -name "*.tar.gz"); do
        if [[ "$(echo $tarball | grep -o "glibc2.*" | awk -F '.' '{print $2}')" -le "$(echo $GLIBC_VER | awk -F '.' '{print $2}')" ]]; then
            TARBALLS+=" $(basename $tarball)"
        fi
    done
    DIRLIST="bin lib/private"
}

function install_deps {
    if [ -f /etc/redhat-release ]; then
        yum install -y perl-Time-HiRes perl numactl numactl-libs libaio git libidn || true
    else
        apt install -y perl numactl libaio-dev git libidn11 || true
    fi
}

main() {

    DIRLIST="bin lib lib/private lib/plugin"

    prepare

    echo "Unpacking tarball"
    cd $TMP_DIR
    tar xf $CURDIR/$TARBALL
    cd ${TARBALL%.tar.gz}

    echo "Checking ELFs for not found"
    for DIR in $DIRLIST; do
        check_libs $DIR | tee -a $TMP_DIR/libs_err.log
    done

    if [[ ! -z $(cat $TMP_DIR/libs_err.log | grep "not found") ]]; then
        echo "ERROR: There are missing libraries: "
        cat $TMP_DIR/libs_err.log
        exit 1
    fi

    # Run tests
    mkdir -p $TMP_DIR/db tests
    wget -O $TMP_DIR/mgodatagen.tar.gz https://github.com/feliixx/mgodatagen/releases/download/v0.8.2/mgodatagen_linux_x86_64.tar.gz
    wget -O tests/big.json https://raw.githubusercontent.com/feliixx/mgodatagen/master/datagen/testdata/big.json
    tar -xvf $TMP_DIR/mgodatagen.tar.gz

    ./bin/mongod --dbpath $TMP_DIR/db 2>&1 >status.log &
    MONGOPID=$(echo $!)
    ./mgodatagen -f tests/big.json
    if [ $? -eq 0 ]; then
        echo "Tests succeeded"
        kill -2 $MONGOPID
        echo " == PSMDB Log =="
        cat status.log
    else
        echo "Tests failed"
        exit 1
    fi
}

case "$1" in
--install_deps) install_deps ;;
--test) main ;;
--help | *)
    cat <<EOF
Usage: $0 [OPTIONS]
    The following options may be given :
        --install_deps
        --test
        --help) usage ;;
Example $0 --install_deps 
EOF
    ;;
esac
