
#!/bin/bash
# This script downloads and imports opentelemetry-cpp.
#
# Turn on strict error checking, like perl use 'strict'
set -xeuo pipefail
IFS=$'\n\t'

NAME="prometheus-cpp"

VERSION="1.3.0"
BRANCH="mongo/v${VERSION}"

LIB_GIT_URL="https://github.com/mongodb-forks/prometheus-cpp.git"
LIB_GIT_DIR=$(mktemp -d /tmp/import-prometheus-cpp.XXXXXX)

trap "rm -rf $LIB_GIT_DIR" EXIT

LIBDIR=$(git rev-parse --show-toplevel)/src/third_party/$NAME
DIST=${LIBDIR}/dist
git clone "$LIB_GIT_URL" $LIB_GIT_DIR
git -C $LIB_GIT_DIR checkout $BRANCH

DEST_DIR=$(git rev-parse --show-toplevel)/src/third_party/$NAME

SUBDIR_WHITELIST=(
    bazel
    core
    util
    LICENSE
    BUILD.bazel
    MODULE.bazel
    README.md
)

for subdir in ${SUBDIR_WHITELIST[@]}
do
    [[ -d $LIB_GIT_DIR/$subdir ]] && mkdir -p $DIST/$subdir
    cp -Trp $LIB_GIT_DIR/$subdir $DIST/$subdir
done

## Remove all CMakelists.txt files
find $DIST/ -name "CMakeLists.txt" -delete

# Remove unneeded directories
pushd $DIST

# Test directories
rm -rf core/tests
rm -rf util/tests

# Unneeded bazel-related files
rm bazel/civetweb.BUILD
rm bazel/curl.BUILD
rm bazel/curl.bzl
rm bazel/repositories.bzl
rm bazel/zlib.BUILD

PATCHES_DIR="${LIBDIR}/patches"
git apply "${PATCHES_DIR}/0001-fix-build-and-deps-for-bazel.patch"

popd
