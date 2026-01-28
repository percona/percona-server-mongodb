#!/usr/bin/bash
# The scripts clones the specified version of `libarchive` and removes unused parts.

set -o verbose
set -o errexit
set -euo pipefail
IFS=$'\n\t'

set -vx

NAME=libarchive
VERSION="v3.8.4"
REVISION="${VERSION}-percona"

# get the source
DEST_DIR=$(git rev-parse --show-toplevel)/src/third_party/libarchive
if [[ -d $DEST_DIR/dist ]]; then
    echo "Please remove '$DEST_DIR/dist' before running $0" >&2
    exit 1
fi
git clone --depth 1 --branch $REVISION https://github.com/Percona-Lab/libarchive.git $DEST_DIR/dist

pushd $DEST_DIR/dist/
find . -mindepth 1 -maxdepth 1 \
    ! -name "CONTRIBUTING.md" \
    ! -name "COPYING" \
    ! -name "INSTALL" \
    ! -name "NEWS" \
    ! -name "README.md" \
    ! -name "SECURITY.md" \
    ! -name "libarchive" \
    -exec rm -rf {} \;
pushd libarchive
find . -mindepth 1 -maxdepth 1 \
    ! -name "*.c" \
    ! -name "*.h" \
    -exec rm -rf {} \;
popd
popd
