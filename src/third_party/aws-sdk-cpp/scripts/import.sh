#!/bin/bash

set -vxeuo pipefail

#
# The script is based on the [similar upstream script][10]
#
# [10]: https://github.com/mongodb/mongo/blob/dcb8f27db8bdf5908f41aff04909660115c6cc78/src/third_party/aws-sdk/scripts/getsources.sh
#

abort() {
  echo "error: $1" >& 2
  exit 1
}


# ======== Check the input ========

HELP_MSG="\
Description:
    Import the source code of AWS SDK for C++ into the PSMDB repository.

    If run with the \`-p\` option, the script generates and imports only the
    platform-dependent files into the
    \`src/third_party/aws-sdk-cpp/platform/build_linux_<cpu_arch>\` directory.
    Otherwise, it generates and imports the platform-independent files into the
    \`src/third_party/aws-sdk-cpp/dist\` directory.

Options:
    -h
        Print this help message and exit.
    -p
        Only generate and import the platform-dependent files for the CPU
        architecture the script runs on"

ONLY_PLATFORM_FILES=""
while getopts "hp" opt; do
    case "$opt" in
        h) echo "${HELP_MSG}"; exit 0;;
        p) ONLY_PLATFORM_FILES="yes";;
       \?) abort "Unsupported option: \`$OPTARG\`";;
    esac
done


# ======== Check the directories ========

BASE_DIR=$(git rev-parse --show-toplevel)/src/third_party/aws-sdk-cpp
DIST_DIR="${BASE_DIR}/dist"
PLATFORM_DIR="${BASE_DIR}/platform/linux_$(uname -m)"
TMP_DIR=/tmp/aws-sdk-cpp

if [ -d ${TMP_DIR} ]; then
    abort "Please remove or rename \`${TMP_DIR}\` before running \`$0\`"
fi
if [ -z "${ONLY_PLATFORM_FILES}" -a -d ${DIST_DIR} ]; then
    abort "Please remove or rename \`${DIST_DIR}\` before running \`$0\`"
fi
if [ -n "${ONLY_PLATFORM_FILES}" -a -d ${PLATFORM_DIR} ]; then
    abort "Please remove or rename \`${PLATFORM_DIR}\` before running \`$0\`"
fi


# ======== Install dependencies ========

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if ! sudo id -u > /dev/null 2>&1; then
        abort "Can't install dependencies. Please either login as \`root\` or install \`sudo\`"
    fi
    SUDO="sudo"
fi

if dnf --version > /dev/null 2>&1; then
    ${SUDO} dnf install -y gcc gcc-c++ cmake curl openssl-devel libcurl-devel zlib-devel
elif apt-get --version > /dev/null 2>&1; then
    ${SUDO} apt-get update
    ${SUDO} apt-get install -y gcc g++ cmake curl libssl-dev libcurl4-openssl-dev \
        zlib1g-dev libzlcore-dev
else
    abort "Unsupported platform. Please use either an RPM- or a DEB-based OS.";
fi


# ======== Get and build AWS SDK for C++ ========

NAME=aws-sdk-cpp
VERSION="1.11.471"
REVISION="${VERSION}"

git clone --recurse-submodules --depth 1 --branch ${VERSION} \
    https://github.com/aws/aws-sdk-cpp.git ${TMP_DIR}

pushd ${TMP_DIR}
REL_BUILD_DIR="_build"
cmake -S. -B${REL_BUILD_DIR} \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_CXX_STANDARD=17 -DBUILD_SHARED_LIBS=OFF \
    -DMINIMIZE_SIZE=ON -DBUILD_ONLY="s3;transfer" -DENABLE_UNITY_BUILD=OFF \
    -DENABLE_TESTING=OFF -DAUTORUN_UNIT_TESTS=OFF -DENABLE_HTTP_CLIENT_TESTING=OFF \
    -DCMAKE_INSTALL_PREFIX=.
cmake --build ${REL_BUILD_DIR} --config=Debug -j$(nproc)
cmake --install ${REL_BUILD_DIR} --config=Debug


# ======== Import platform-dependent files ========

if [ -n "${ONLY_PLATFORM_FILES}" ]; then
    mkdir -p ${PLATFORM_DIR}
    pushd ${REL_BUILD_DIR}
    cp --parents crt/aws-crt-cpp/crt/aws-c-common/generated/include/aws/common/config.h \
        ${PLATFORM_DIR}
    cp --parents crt/aws-crt-cpp/generated/include/aws/crt/Config.h ${PLATFORM_DIR}
    exit 0
fi


# ======== Import platform-independent files ========

mkdir -p ${DIST_DIR}
find . -type f \
    \( -iname "*.h" -o -iname "*.c" -o -iname "*.cpp" -o -iname "*.def" -o -iname "*.inl" -o \
        -iname "*license*" -o -iname "*clang*" -o -iname "*notice*" \) \
    -exec cp --parents {} ${DIST_DIR} ';'

pushd ${DIST_DIR}
find . -type d \
    \(  -name "${REL_BUILD_DIR}" -o -name "aws-lc" -o -name "bin" -o -name "tests" -o \
        -name "verification" -o -name "integration-testing" -o -name "smoke-tests" -o \
        -name "tools" -o -name "AWSCRTAndroidTestRunner" -o -name "testing" -o -name "samples" -o \
        -name "docs" -o -name "CMakeFiles" -o -name ".github" -o -name "clang-tidy" -o \
        -name "codebuild" -o -name ".builder"  -o -name "toolchains" \) \
    -exec rm -rf {} \; || true
# sub folders in source folders that are not needed
find . -type d \
    \(  -name "darwin" -o -name "windows" -o -name "android" -o -name "msvc" -o -name "msvc" -o \
        -name "platform_fallback_stubs" -o -name "huffman_generator" -o -name "bsd" \) \
    -exec rm -rf {} \; || true
# The `config.h` file is platform-dependent and a dedicated version for each
# supported platform exists in the `${PLATFORM_DIR}` directory.
rm -f include/aws/common/config.h

pushd ${DIST_DIR}/src
find . -maxdepth 1 -type d \
    -not \( -name "." -o -name "aws-cpp-sdk-core" -o -name "aws-cpp-sdk-transfer" \) \
    -exec rm -rf {} \; || true
pushd ${DIST_DIR}/generated/src
find . -maxdepth 1 -type d -not \( -name "." -o -name "aws-cpp-sdk-s3" \) -exec rm -rf {} \; || true
