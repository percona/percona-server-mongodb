#!/usr/bin/env bash

shell_quote_string() {
  echo "$1" | sed -e 's,\([^a-zA-Z0-9/_.=-]\),\\\1,g'
}

usage () {
    cat <<EOF
Usage: $0 [OPTIONS]
    The following options may be given :
        --builddir=DIR      Absolute path to the dir where all actions will be performed
        --get_sources       Source will be downloaded from github
        --build_src_rpm     If it is set - src rpm will be built
        --build_src_deb  If it is set - source deb package will be built
        --build_rpm         If it is set - rpm will be built
        --build_deb         If it is set - deb will be built
        --build_tarball     If it is set - tarball will be built
        --install_deps      Install build dependencies(root privilages are required)
        --branch            Branch for build
        --repo              Repo for build
        --psm_ver           PSM_VER(mandatory)
        --psm_release       PSM_RELEASE(mandatory)
        --mongo_tools_tag   MONGO_TOOLS_TAG(mandatory)
        --special_targets   Special targets for tests
        --debug             build debug tarball
        --help) usage ;;
Example $0 --builddir=/tmp/PSMDB --get_sources=1 --build_src_rpm=1 --build_rpm=1
EOF
        exit 1
}

append_arg_to_args () {
  args="$args "$(shell_quote_string "$1")
}

parse_arguments() {
    pick_args=
    if test "$1" = PICK-ARGS-FROM-ARGV
    then
        pick_args=1
        shift
    fi

    for arg do
        val=$(echo "$arg" | sed -e 's;^--[^=]*=;;')
        case "$arg" in
            --builddir=*) WORKDIR="$val" ;;
            --build_src_rpm=*) SRPM="$val" ;;
            --build_src_deb=*) SDEB="$val" ;;
            --build_rpm=*) RPM="$val" ;;
            --build_deb=*) DEB="$val" ;;
            --get_sources=*) SOURCE="$val" ;;
            --build_tarball=*) TARBALL="$val" ;;
            --branch=*) BRANCH="$val" ;;
            --repo=*) REPO="$val" ;;
            --install_deps=*) INSTALL="$val" ;;
            --psm_ver=*) PSM_VER="$val" ;;
            --psm_release=*) PSM_RELEASE="$val" ;;
            --mongo_tools_tag=*) MONGO_TOOLS_TAG="$val" ;;
            --debug=*) DEBUG="$val" ;;
            --special_targets=*) SPECIAL_TAR="$val" ;;
            --help) usage ;;
            *)
              if test -n "$pick_args"
              then
                  append_arg_to_args "$arg"
              fi
              ;;
        esac
    done
}

check_workdir(){
    if [ "x$WORKDIR" = "x$CURDIR" ]
    then
        echo >&2 "Current directory cannot be used for building!"
        exit 1
    else
        if ! test -d "$WORKDIR"
        then
            echo >&2 "$WORKDIR is not a directory."
            exit 1
        fi
    fi
    return
}

add_percona_yum_repo(){
    if [ ! -f /etc/yum.repos.d/percona-dev.repo ]
    then
      wget http://jenkins.percona.com/yum-repo/percona-dev.repo
      mv -f percona-dev.repo /etc/yum.repos.d/
    fi
    return
}

add_percona_apt_repo(){
  if [ ! -f /etc/apt/sources.list.d/percona-dev.list ]; then
    cat >/etc/apt/sources.list.d/percona-dev.list <<EOL
deb http://jenkins.percona.com/apt-repo/ @@DIST@@ main
deb-src http://jenkins.percona.com/apt-repo/ @@DIST@@ main
EOL
    sed -i "s:@@DIST@@:$OS_NAME:g" /etc/apt/sources.list.d/percona-dev.list
  fi
  wget -qO - http://jenkins.percona.com/apt-repo/8507EFA5.pub | apt-key add -
  return
}

get_sources(){
    cd "${WORKDIR}"
    if [ "${SOURCE}" = 0 ]
    then
        echo "Sources will not be downloaded"
        return 0
    fi
    PRODUCT=percona-server-mongodb
    echo "PRODUCT=${PRODUCT}" > percona-server-mongodb-40.properties

    PRODUCT_FULL=${PRODUCT}-${PSM_VER}-${PSM_RELEASE}
    echo "PRODUCT_FULL=${PRODUCT_FULL}" >> percona-server-mongodb-40.properties
    echo "VERSION=${PSM_VER}" >> percona-server-mongodb-40.properties
    echo "RELEASE=$PSM_RELEASE" >> percona-server-mongodb-40.properties
    echo "PSM_BRANCH=${PSM_BRANCH}" >> percona-server-mongodb-40.properties
    echo "JEMALLOC_TAG=${JEMALLOC_TAG}" >> percona-server-mongodb-40.properties
    echo "MONGO_TOOLS_TAG=${MONGO_TOOLS_TAG}" >> percona-server-mongodb-40.properties
    echo "BUILD_NUMBER=${BUILD_NUMBER}" >> percona-server-mongodb-40.properties
    echo "BUILD_ID=${BUILD_ID}" >> percona-server-mongodb-40.properties
    git clone "$REPO"
    retval=$?
    if [ $retval != 0 ]
    then
        echo "There were some issues during repo cloning from github. Please retry one more time"
        exit 1
    fi
    cd percona-server-mongodb
    if [ ! -z "$BRANCH" ]
    then
        git reset --hard
        git clean -xdf
        git checkout "$BRANCH"
    fi
    REVISION=$(git rev-parse --short HEAD)
    # create a proper version.json
    REVISION_LONG=$(git rev-parse HEAD)
    echo "{" > version.json
    echo "    \"version\": \"${PSM_VER}-${PSM_RELEASE}\"," >> version.json
    echo "    \"githash\": \"${REVISION_LONG}\"" >> version.json
    echo "}" >> version.json
    #
    echo "REVISION=${REVISION}" >> ${WORKDIR}/percona-server-mongodb-40.properties
    rm -fr debian rpm
    cp -a percona-packaging/manpages .
    cp -a percona-packaging/docs/* .
    #
    # submodules
    git submodule init
    git submodule update
    #
    git clone https://github.com/mongodb/mongo-tools.git
    cd mongo-tools
    git checkout $MONGO_TOOLS_TAG
    echo "export PSMDB_TOOLS_COMMIT_HASH=\"$(git rev-parse HEAD)\"" > set_tools_revision.sh
    echo "export PSMDB_TOOLS_REVISION=\"${PSM_VER}-${PSM_RELEASE}\"" >> set_tools_revision.sh
    chmod +x set_tools_revision.sh
    cd ${WORKDIR}
    #
    #source ${WORKDIR}/percona-server-mongodb-40.properties
    #
    source percona-server-mongodb-40.properties
    #

    mv percona-server-mongodb ${PRODUCT}-${PSM_VER}-${PSM_RELEASE}
    tar --owner=0 --group=0 --exclude=.* -czf ${PRODUCT}-${PSM_VER}-${PSM_RELEASE}.tar.gz ${PRODUCT}-${PSM_VER}-${PSM_RELEASE}
    echo "UPLOAD=UPLOAD/experimental/BUILDS/${PRODUCT}-4.0/${PRODUCT}-${PSM_VER}-${PSM_RELEASE}/${PSM_BRANCH}/${REVISION}/${BUILD_ID}" >> percona-server-mongodb-40.properties
    mkdir $WORKDIR/source_tarball
    mkdir $CURDIR/source_tarball
    cp ${PRODUCT}-${PSM_VER}-${PSM_RELEASE}.tar.gz $WORKDIR/source_tarball
    cp ${PRODUCT}-${PSM_VER}-${PSM_RELEASE}.tar.gz $CURDIR/source_tarball
    cd $CURDIR
    rm -rf percona-server-mongodb
    return
}

get_system(){
    if [ -f /etc/redhat-release ]; then
        RHEL=$(rpm --eval %rhel)
        ARCH=$(echo $(uname -m) | sed -e 's:i686:i386:g')
        OS_NAME="el$RHEL"
        OS="rpm"
    else
        ARCH=$(uname -m)
        OS_NAME="$(lsb_release -sc)"
        OS="deb"
    fi
    return
}

install_golang() {
    wget https://dl.google.com/go/go1.11.4.linux-amd64.tar.gz -O /tmp/golang1.11.tar.gz
    tar --transform=s,go,go1.11, -zxf /tmp/golang1.11.tar.gz
    rm -rf /usr/local/go1.11  /usr/local/go1.8 /usr/local/go1.9 /usr/local/go1.9.2 /usr/local/go
    mv go1.11 /usr/local/
    ln -s /usr/local/go1.11 /usr/local/go
}

install_gcc_8_centos(){
    if [ "${RHEL}" -lt 8 ]; then
        until yum -y install centos-release-scl; do
            echo "waiting"
            sleep 1
        done
        yum -y install  gcc-c++ devtoolset-8-gcc-c++ devtoolset-8-binutils cmake3 rh-python36
        source /opt/rh/devtoolset-8/enable
        source /opt/rh/rh-python36/enable
    else
        yum -y install binutils gcc gcc-c++
    fi

}

install_gcc_8_deb(){
    if [ x"${DEBIAN}" = xjessie ]; then
        wget https://jenkins.percona.com/downloads/gcc8/gcc-8.3.0_Debian-jessie-x64.tar.gz -O /tmp/gcc-8.3.0_Debian-jessie-x64.tar.gz
        tar -zxf /tmp/gcc-8.3.0_Debian-jessie-x64.tar.gz
        rm -rf /usr/local/gcc-8.3.0
        mv gcc-8.3.0 /usr/local/
    fi
    if [ x"${DEBIAN}" = xxenial ]; then
        wget https://jenkins.percona.com/downloads/gcc8/gcc-8.3.0_Ubuntu-xenial-x64.tar.gz -O /tmp/gcc-8.3.0_Ubuntu-xenial-x64.tar.gz
        CUR_DIR=$PWD
        cd /tmp
        tar -zxf gcc-8.3.0_Ubuntu-xenial-x64.tar.gz
        rm -rf /usr/local/gcc-8.3.0
        mv gcc-8.3.0 /usr/local/
        cd $CUR_DIR
    fi
    if [ x"${DEBIAN}" = xcosmic -o x"${DEBIAN}" = xbionic -o x"${DEBIAN}" = xdisco ]; then
        apt-get -y install gcc-8 g++-8
    fi
    if [ x"${DEBIAN}" = xstretch ]; then
        wget https://jenkins.percona.com/downloads/gcc8/gcc-8.3.0_Debian-stretch-x64.tar.gz -O /tmp/gcc-8.3.0_Debian-stretch-x64.tar.gz
        tar -zxf /tmp/gcc-8.3.0_Debian-stretch-x64.tar.gz
        rm -rf /usr/local/gcc-8.3.0
        mv gcc-8.3.0 /usr/local/
    fi
}

set_compiler(){
    if [ x"${DEBIAN}" = xcosmic -o x"${DEBIAN}" = xbionic -o x"${DEBIAN}" = xdisco ]; then
        export CC=/usr/bin/gcc-8
        export CXX=/usr/bin/g++-8
    else
        export CC=/usr/local/gcc-8.3.0/bin/gcc-8.3
        export CXX=/usr/local/gcc-8.3.0/bin/g++-8.3
    fi
}

fix_rules(){
    if [ x"${DEBIAN}" = xcosmic -o x"${DEBIAN}" = xbionic -o x"${DEBIAN}" = xdisco ]; then
        sed -i 's|CC = gcc-5|CC = /usr/bin/gcc-8|' debian/rules
        sed -i 's|CXX = g++-5|CXX = /usr/bin/g++-8|' debian/rules
    else
        sed -i 's|CC = gcc-5|CC = /usr/local/gcc-8.3.0/bin/gcc-8.3|' debian/rules
        sed -i 's|CXX = g++-5|CXX = /usr/local/gcc-8.3.0/bin/g++-8.3|' debian/rules
    fi
    sed -i 's:release:release --disable-warnings-as-errors :g' debian/rules
}

install_deps() {
    if [ $INSTALL = 0 ]
    then
        echo "Dependencies will not be installed"
        return;
    fi
    if [ $( id -u ) -ne 0 ]
    then
        echo "It is not possible to instal dependencies. Please run as root"
        exit 1
    fi
    CURPLACE=$(pwd)

    if [ "x$OS" = "xrpm" ]; then
      yum -y install wget
      add_percona_yum_repo
      wget http://jenkins.percona.com/yum-repo/percona-dev.repo
      mv -f percona-dev.repo /etc/yum.repos.d/
      yum clean all
      rm -fr /usr/local/gcc-5.4.0
      RHEL=$(rpm --eval %rhel)
      if [ x"$RHEL" = x6 ]; then
        yum -y update
        yum -y install epel-release
        yum -y install rpmbuild rpm-build libpcap-devel gcc make cmake gcc-c++ openssl-devel git
        yum -y install cyrus-sasl-devel snappy-devel zlib-devel bzip2-devel libpcap-devel
        yum -y install scons make rpm-build rpmbuild percona-devtoolset-gcc percona-devtoolset-binutils 
        yum -y install percona-devtoolset-gcc-c++ percona-devtoolset-libstdc++-devel percona-devtoolset-valgrind-devel
        yum -y install python27 python27-devel rpmlint libcurl-devel
        wget https://bootstrap.pypa.io/get-pip.py
        python2.7 get-pip.py
        rm -rf /usr/bin/python2
        ln -s /usr/bin/python2.7 /usr/bin/python2
      elif [ x"$RHEL" = x7 ]; then
        yum -y install epel-release
        yum -y install rpmbuild rpm-build libpcap-devel gcc make cmake gcc-c++ openssl-devel
        yum -y install cyrus-sasl-devel snappy-devel zlib-devel bzip2-devel scons rpmlint
        yum -y install rpm-build git python-pip python-devel libopcodes libcurl-devel rpmlint
      else
        yum -y install bzip2-devel libpcap-devel snappy-devel gcc gcc-c++ rpm-build rpmlint
        yum -y install cmake cyrus-sasl-devel make openssl-devel zlib-devel libcurl-devel
        yum -y install python2-scons python2-pip python36-devel
        yum -y install redhat-rpm-config python2-devel
      fi
      if [ "x${RHEL}" == "x8" ]; then
        /usr/bin/pip3.6 install --user typing pyyaml regex Cheetah3
        /usr/bin/pip2.7 install --user typing pyyaml regex Cheetah
      fi
#
      install_golang
      install_gcc_8_centos
    else
      export DEBIAN=$(lsb_release -sc)
      export ARCH=$(echo $(uname -m) | sed -e 's:i686:i386:g')
      INSTALL_LIST="python3 python3-dev python3-pip valgrind scons liblz4-dev devscripts debhelper debconf libpcap-dev libbz2-dev libsnappy-dev pkg-config zlib1g-dev libzlcore-dev dh-systemd libsasl2-dev gcc g++ cmake curl"
      INSTALL_LIST="${INSTALL_LIST} libssl-dev libcurl4-openssl-dev"
      until apt-get -y install dirmngr; do
        sleep 1
        echo "waiting"
      done
      add_percona_apt_repo
      until apt-get update; do
        sleep 1
        echo "waiting"
      done
      until DEBIAN_FRONTEND=noninteractive apt-get -y install ${INSTALL_LIST}; do
        sleep 1
        echo "waiting"
      done
      install_golang
      install_gcc_8_deb
      wget https://bootstrap.pypa.io/get-pip.py
      update-alternatives --install /usr/bin/python python /usr/bin/python3 1
      python get-pip.py
      easy_install pip
    fi
    return;
}

get_tar(){
    TARBALL=$1
    TARFILE=$(basename $(find $WORKDIR/$TARBALL -name 'percona-server-mongodb*.tar.gz' | sort | tail -n1))
    if [ -z $TARFILE ]
    then
        TARFILE=$(basename $(find $CURDIR/$TARBALL -name 'percona-server-mongodb*.tar.gz' | sort | tail -n1))
        if [ -z $TARFILE ]
        then
            echo "There is no $TARBALL for build"
            exit 1
        else
            cp $CURDIR/$TARBALL/$TARFILE $WORKDIR/$TARFILE
        fi
    else
        cp $WORKDIR/$TARBALL/$TARFILE $WORKDIR/$TARFILE
    fi
    return
}

get_deb_sources(){
    param=$1
    echo $param
    FILE=$(basename $(find $WORKDIR/source_deb -name "percona-server-mongodb*.$param" | sort | tail -n1))
    if [ -z $FILE ]
    then
        FILE=$(basename $(find $CURDIR/source_deb -name "percona-server-mongodb*.$param" | sort | tail -n1))
        if [ -z $FILE ]
        then
            echo "There is no sources for build"
            exit 1
        else
            cp $CURDIR/source_deb/$FILE $WORKDIR/
        fi
    else
        cp $WORKDIR/source_deb/$FILE $WORKDIR/
    fi
    return
}

build_srpm(){
    if [ $SRPM = 0 ]
    then
        echo "SRC RPM will not be created"
        return;
    fi
    if [ "x$OS" = "xdeb" ]
    then
        echo "It is not possible to build src rpm here"
        exit 1
    fi
    cd $WORKDIR
    get_tar "source_tarball"
    rm -fr rpmbuild
    ls | grep -v tar.gz | xargs rm -rf
    TARFILE=$(find . -name 'percona-server-mongodb*.tar.gz' | sort | tail -n1)
    SRC_DIR=${TARFILE%.tar.gz}
    #
    mkdir -vp rpmbuild/{SOURCES,SPECS,BUILD,SRPMS,RPMS}
    tar vxzf ${WORKDIR}/${TARFILE} --wildcards '*/percona-packaging' --strip=1
    SPEC_TMPL=$(find percona-packaging/redhat -name 'percona-server-mongodb.spec.template' | sort | tail -n1)
    #
    cp -av percona-packaging/conf/* rpmbuild/SOURCES
    cp -av percona-packaging/redhat/mongod.* rpmbuild/SOURCES
    #
    sed -i 's:@@LOCATION@@:sysconfig:g' rpmbuild/SOURCES/*.service
    sed -i 's:@@LOCATION@@:sysconfig:g' rpmbuild/SOURCES/percona-server-mongodb-helper.sh
    sed -i 's:@@LOGDIR@@:mongo:g' rpmbuild/SOURCES/*.default
    sed -i 's:@@LOGDIR@@:mongo:g' rpmbuild/SOURCES/percona-server-mongodb-helper.sh
    #
    sed -e "s:@@SOURCE_TARBALL@@:$(basename ${TARFILE}):g" \
    -e "s:@@VERSION@@:${VERSION}:g" \
    -e "s:@@RELEASE@@:${RELEASE}:g" \
    -e "s:@@SRC_DIR@@:$SRC_DIR:g" \
    ${SPEC_TMPL} > rpmbuild/SPECS/$(basename ${SPEC_TMPL%.template})
    mv -fv ${TARFILE} ${WORKDIR}/rpmbuild/SOURCES
    if [ -f /opt/rh/devtoolset-8/enable ]; then
        source /opt/rh/devtoolset-8/enable
        source /opt/rh/rh-python36/enable
    fi
    rpmbuild -bs --define "_topdir ${WORKDIR}/rpmbuild" --define "dist .generic" rpmbuild/SPECS/$(basename ${SPEC_TMPL%.template})
    mkdir -p ${WORKDIR}/srpm
    mkdir -p ${CURDIR}/srpm
    cp rpmbuild/SRPMS/*.src.rpm ${CURDIR}/srpm
    cp rpmbuild/SRPMS/*.src.rpm ${WORKDIR}/srpm
    return
}

build_rpm(){
    if [ $RPM = 0 ]
    then
        echo "RPM will not be created"
        return;
    fi
    if [ "x$OS" = "xdeb" ]
    then
        echo "It is not possible to build rpm here"
        exit 1
    fi
    SRC_RPM=$(basename $(find $WORKDIR/srpm -name 'percona-server-mongodb*.src.rpm' | sort | tail -n1))
    if [ -z $SRC_RPM ]
    then
        SRC_RPM=$(basename $(find $CURDIR/srpm -name 'percona-server-mongodb*.src.rpm' | sort | tail -n1))
        if [ -z $SRC_RPM ]
        then
            echo "There is no src rpm for build"
            echo "You can create it using key --build_src_rpm=1"
            exit 1
        else
            cp $CURDIR/srpm/$SRC_RPM $WORKDIR
        fi
    else
        cp $WORKDIR/srpm/$SRC_RPM $WORKDIR
    fi
    cd $WORKDIR
    rm -fr rpmbuild
    mkdir -vp rpmbuild/{SOURCES,SPECS,BUILD,SRPMS,RPMS}
    cp $SRC_RPM rpmbuild/SRPMS/

    cd rpmbuild/SRPMS/
    rpm2cpio ${SRC_RPM} | cpio -id
    TARF=$(find . -name 'percona-server-mongodb*.tar.gz' | sort | tail -n1)
    tar vxzf ${TARF} --wildcards '*/etc' --strip=1
    if [ -f /opt/rh/devtoolset-8/enable ]; then
        source /opt/rh/devtoolset-8/enable
        source /opt/rh/rh-python36/enable
    fi
    RHEL=$(rpm --eval %rhel)
    ARCH=$(echo $(uname -m) | sed -e 's:i686:i386:g')
    if [ "x${RHEL}" == "x8" ]; then
        pip3.6 install --upgrade pip
        pip3.6 install --user -r etc/pip/dev-requirements.txt
    else
        pip install --upgrade pip
        pip install --user -r etc/pip/dev-requirements.txt
    fi
    #
    cd $WORKDIR
    if [ -f /opt/rh/devtoolset-8/enable ]; then
        source /opt/rh/devtoolset-8/enable
        source /opt/rh/rh-python36/enable
    fi

    echo "CC and CXX should be modified once correct compiller would be installed on Centos"
    if [ "x${RHEL}" == "x8" ]; then
        export CC=/usr/bin/gcc
        export CXX=/usr/bin/g++
    else
        export CC=/opt/rh/devtoolset-8/root/usr/bin/gcc
        export CXX=/opt/rh/devtoolset-8/root/usr/bin/g++
    fi
    #
    echo "RHEL=${RHEL}" >> percona-server-mongodb-40.properties
    echo "ARCH=${ARCH}" >> percona-server-mongodb-40.properties
    #
    file /usr/bin/scons
    #
    #if [ "x${RHEL}" == "x6" ]; then
        [[ ${PATH} == *"/usr/local/go/bin"* && -x /usr/local/go/bin/go ]] || export PATH=/usr/local/go/bin:${PATH}
        export GOROOT="/usr/local/go/"
        export GOPATH=$(pwd)/
        export PATH="/usr/local/go/bin:$PATH:$GOPATH"
        export GOBINPATH="/usr/local/go/bin"
    #fi
    rpmbuild --define "_topdir ${WORKDIR}/rpmbuild" --define "dist .$OS_NAME" --rebuild rpmbuild/SRPMS/$SRC_RPM

    return_code=$?
    if [ $return_code != 0 ]; then
        exit $return_code
    fi
    mkdir -p ${WORKDIR}/rpm
    mkdir -p ${CURDIR}/rpm
    cp rpmbuild/RPMS/*/*.rpm ${WORKDIR}/rpm
    cp rpmbuild/RPMS/*/*.rpm ${CURDIR}/rpm
}

build_source_deb(){
    if [ $SDEB = 0 ]
    then
        echo "source deb package will not be created"
        return;
    fi
    if [ "x$OS" = "xrpm" ]
    then
        echo "It is not possible to build source deb here"
        exit 1
    fi
    rm -rf percona-server-mongodb*
    get_tar "source_tarball"
    rm -f *.dsc *.orig.tar.gz *.debian.tar.gz *.changes
    #
    TARFILE=$(basename $(find . -name 'percona-server-mongodb*.tar.gz' | sort | tail -n1))
    DEBIAN=$(lsb_release -sc)
    ARCH=$(echo $(uname -m) | sed -e 's:i686:i386:g')
    tar zxf ${TARFILE}
    BUILDDIR=${TARFILE%.tar.gz}
    #
    rm -fr ${BUILDDIR}/debian
    cp -av ${BUILDDIR}/percona-packaging/debian ${BUILDDIR}
    cp -av ${BUILDDIR}/percona-packaging/conf/* ${BUILDDIR}/debian/
    #
    sed -i 's:@@LOCATION@@:default:g' ${BUILDDIR}/debian/*.service
    sed -i 's:@@LOCATION@@:default:g' ${BUILDDIR}/debian/percona-server-mongodb-helper.sh
    sed -i 's:@@LOGDIR@@:mongodb:g' ${BUILDDIR}/debian/mongod.default
    sed -i 's:@@LOGDIR@@:mongodb:g' ${BUILDDIR}/debian/percona-server-mongodb-helper.sh
    #
    mv ${BUILDDIR}/debian/mongod.default ${BUILDDIR}/debian/percona-server-mongodb-server.mongod.default
    mv ${BUILDDIR}/debian/mongod.service ${BUILDDIR}/debian/percona-server-mongodb-server.mongod.service
    #
    mv ${TARFILE} ${PRODUCT}_${VERSION}.orig.tar.gz
    cd ${BUILDDIR}
    pip install --upgrade pip
    pip install --user -r etc/pip/dev-requirements.txt

    set_compiler
    fix_rules

    dch -D unstable --force-distribution -v "${VERSION}-${RELEASE}" "Update to new Percona Server for MongoDB version ${VERSION}"
    dpkg-buildpackage -S
    cd ../
    mkdir -p $WORKDIR/source_deb
    mkdir -p $CURDIR/source_deb
    cp *.debian.tar.* $WORKDIR/source_deb
    cp *_source.changes $WORKDIR/source_deb
    cp *.dsc $WORKDIR/source_deb
    cp *.orig.tar.gz $WORKDIR/source_deb
    cp *.debian.tar.* $CURDIR/source_deb
    cp *_source.changes $CURDIR/source_deb
    cp *.dsc $CURDIR/source_deb
    cp *.orig.tar.gz $CURDIR/source_deb
}

build_deb(){
    if [ $DEB = 0 ]
    then
        echo "source deb package will not be created"
        return;
    fi
    if [ "x$OS" = "xrmp" ]
    then
        echo "It is not possible to build source deb here"
        exit 1
    fi
    for file in 'dsc' 'orig.tar.gz' 'changes' 'debian.tar*'
    do
        get_deb_sources $file
    done
    cd $WORKDIR
    rm -fv *.deb
    #
    export DEBIAN=$(lsb_release -sc)
    export ARCH=$(echo $(uname -m) | sed -e 's:i686:i386:g')
    #
    echo "DEBIAN=${DEBIAN}" >> percona-server-mongodb-40.properties
    echo "ARCH=${ARCH}" >> percona-server-mongodb-40.properties

    #
    DSC=$(basename $(find . -name '*.dsc' | sort | tail -n1))
    #
    dpkg-source -x ${DSC}
    #
    cd ${PRODUCT}-${VERSION}
    pip install --upgrade pip
    pip install --user -r etc/pip/dev-requirements.txt
    #
    cp -av percona-packaging/debian/rules debian/
    set_compiler
    fix_rules
    sed -i 's|VersionStr="$(git describe)"|VersionStr="$PSMDB_TOOLS_REVISION"|' mongo-tools/set_goenv.sh
    sed -i 's|Gitspec="$(git rev-parse HEAD)"|Gitspec="$PSMDB_TOOLS_COMMIT_HASH"|' mongo-tools/set_goenv.sh
    sed -i 's|go build|go build -a -x|' mongo-tools/build.sh
    sed -i 's|exit $ec||' mongo-tools/build.sh
    dch -m -D "${DEBIAN}" --force-distribution -v "${VERSION}-${RELEASE}.${DEBIAN}" 'Update distribution'

    dpkg-buildpackage -rfakeroot -us -uc -b
    mkdir -p $CURDIR/deb
    mkdir -p $WORKDIR/deb
    cp $WORKDIR/*.deb $WORKDIR/deb
    cp $WORKDIR/*.deb $CURDIR/deb
}

build_tarball(){
    if [ $TARBALL = 0 ]
    then
        echo "Binary tarball will not be created"
        return;
    fi
    get_tar "source_tarball"
    cd $WORKDIR
    TARFILE=$(basename $(find . -name 'percona-server-mongodb*.tar.gz' | sort | tail -n1))

    if [ -f /opt/rh/devtoolset-8/enable ]; then
        source /opt/rh/devtoolset-8/enable
        source /opt/rh/rh-python36/enable
    fi
    #
    export DEBIAN_VERSION="$(lsb_release -sc)"
    export DEBIAN="$(lsb_release -sc)"
    export PATH=/usr/local/go/bin:$PATH
    #
    set_compiler
    #
    PSM_TARGETS="mongod mongos mongo mongobridge perconadecrypt $SPECIAL_TAR"
    TARBALL_SUFFIX=""
    if [ ${DEBUG} = 1 ]; then
    TARBALL_SUFFIX=".dbg"
    fi
    if [ -f /etc/debian_version ]; then
    export OS_RELEASE="$(lsb_release -sc)"
    fi
    #
    if [ -f /etc/redhat-release ]; then
    #export OS_RELEASE="centos$(lsb_release -sr | awk -F'.' '{print $1}')"
    export OS_RELEASE="centos$(rpm --eval %rhel)"
    RHEL=$(rpm --eval %rhel)
    fi
    #
    ARCH=$(uname -m 2>/dev/null||true)
    TARFILE=$(basename $(find . -name 'percona-server-mongodb*.tar.gz' | sort | grep -v "tools" | tail -n1))
    PSMDIR=${TARFILE%.tar.gz}
    PSMDIR_ABS=${WORKDIR}/${PSMDIR}
    TOOLSDIR=${PSMDIR}/mongo-tools
    TOOLSDIR_ABS=${WORKDIR}/${TOOLSDIR}
    TOOLS_TAGS="ssl sasl"
    NJOBS=4

    tar xzf $TARFILE
    rm -f $TARFILE

    rm -fr /tmp/${PSMDIR}
    ln -fs ${PSMDIR_ABS} /tmp/${PSMDIR}
    cd /tmp
    #
    export CFLAGS="${CFLAGS:-} -fno-omit-frame-pointer"
    export CXXFLAGS="${CFLAGS}"
    if [ ${DEBUG} = 1 ]; then
    export CXXFLAGS="${CFLAGS} -Wno-error=deprecated-declarations"
    fi
    export INSTALLDIR=${WORKDIR}/install
    export PORTABLE=1
    export USE_SSE=1
    #

    # Finally build Percona Server for MongoDB with SCons
    cd ${PSMDIR_ABS}
    pip install --upgrade pip
    pip install --user -r etc/pip/dev-requirements.txt
    if [ ${DEBUG} = 0 ]; then
        buildscripts/scons.py CC=${CC} CXX=${CXX} --disable-warnings-as-errors --release --ssl --opt=on -j$NJOBS --use-sasl-client --wiredtiger --audit --inmemory --hotbackup CPPPATH=${INSTALLDIR}/include LIBPATH=${INSTALLDIR}/lib ${PSM_TARGETS}
    else
        buildscripts/scons.py CC=${CC} CXX=${CXX} --disable-warnings-as-errors --audit --ssl --dbg=on -j$NJOBS --use-sasl-client \
        CPPPATH=${INSTALLDIR}/include LIBPATH=${INSTALLDIR}/lib --wiredtiger --inmemory --hotbackup ${PSM_TARGETS}
    fi
    #
    # scons install doesn't work - it installs the binaries not linked with fractal tree
    #scons --prefix=$PWD/$PSMDIR install
    #
    mkdir -p ${PSMDIR}/bin
    for target in ${PSM_TARGETS[@]}; do
        cp -f $target ${PSMDIR}/bin
        if [ ${DEBUG} = 0 ]; then
            strip --strip-debug ${PSMDIR}/bin/${target}
        fi
    done
    #
    cd ${WORKDIR}
    #
    # Build mongo tools
    cd ${TOOLSDIR}
    mkdir -p build_tools/src/github.com/mongodb/mongo-tools
    export GOROOT="/usr/local/go/"
    export GOPATH=$PWD/
    export PATH="/usr/local/go/bin:$PATH:$GOPATH"
    export GOBINPATH="/usr/local/go/bin"
    rm -rf vendor/pkg
    cp -r $(ls | grep -v build_tools) build_tools/src/github.com/mongodb/mongo-tools/
    cd build_tools/src/github.com/mongodb/mongo-tools
    . ./set_tools_revision.sh
    sed -i 's|VersionStr="$(git describe)"|VersionStr="$PSMDB_TOOLS_REVISION"|' set_goenv.sh
    sed -i 's|Gitspec="$(git rev-parse HEAD)"|Gitspec="$PSMDB_TOOLS_COMMIT_HASH"|' set_goenv.sh
    . ./set_goenv.sh
    if [ ${DEBUG} = 0 ]; then
        sed -i 's|go build|go build -a -x|' build.sh
    else
        sed -i 's|go build|go build -a |' build.sh
    fi
    sed -i 's|exit $ec||' build.sh
    . ./build.sh ${TOOLS_TAGS}
    # move mongo tools to PSM installation dir
    mv bin/* ${PSMDIR_ABS}/${PSMDIR}/bin
    # end build tools
    #
    sed -i "s:TARBALL=0:TARBALL=1:" ${PSMDIR_ABS}/percona-packaging/conf/percona-server-mongodb-enable-auth.sh
    cp ${PSMDIR_ABS}/percona-packaging/conf/percona-server-mongodb-enable-auth.sh ${PSMDIR_ABS}/${PSMDIR}/bin

    cd ${PSMDIR_ABS}
    tar --owner=0 --group=0 -czf ${WORKDIR}/${PSMDIR}-${OS_RELEASE}-${ARCH}${TARBALL_SUFFIX}.tar.gz ${PSMDIR}
    DIRNAME="tarball"
    if [ "${DEBUG}" = 1 ]; then
    DIRNAME="debug"
    fi
    mkdir -p ${WORKDIR}/${DIRNAME}
    mkdir -p ${CURDIR}/${DIRNAME}
    cp ${WORKDIR}/${PSMDIR}-${OS_RELEASE}-${ARCH}${TARBALL_SUFFIX}.tar.gz ${WORKDIR}/${DIRNAME}
    cp ${WORKDIR}/${PSMDIR}-${OS_RELEASE}-${ARCH}${TARBALL_SUFFIX}.tar.gz ${CURDIR}/${DIRNAME}
}

#main

CURDIR=$(pwd)
VERSION_FILE=$CURDIR/percona-server-mongodb.properties
args=
WORKDIR=
SRPM=0
SDEB=0
RPM=0
DEB=0
SOURCE=0
TARBALL=0
OS_NAME=
ARCH=
OS=
INSTALL=0
RPM_RELEASE=1
DEB_RELEASE=1
REVISION=0
BRANCH="master"
REPO="https://github.com/percona/percona-server-mongodb.git"
PSM_VER="4.0.9"
PSM_RELEASE="1"
MONGO_TOOLS_TAG="r4.0.9"
PRODUCT=percona-server-mongodb
DEBUG=0
parse_arguments PICK-ARGS-FROM-ARGV "$@"
VERSION=${PSM_VER}
RELEASE=${PSM_RELEASE}
PRODUCT_FULL=${PRODUCT}-${PSM_VER}-${PSM_RELEASE}
PSM_BRANCH=${BRANCH}
if [ ${DEBUG} = 1 ]; then
  TARBALL=1
fi

check_workdir
get_system
install_deps
get_sources
build_tarball
build_srpm
build_source_deb
build_rpm
build_deb
