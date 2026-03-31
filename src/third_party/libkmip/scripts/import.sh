#!/usr/bin/bash
# The scripts clones the specified version of `libkmip` and removes unused parts.

set -o verbose
set -o errexit
set -euo pipefail
IFS=$'\n\t'

set -vx

NAME=libkmip
VERSION="v0.2.0"
REVISION="${VERSION}-33-g6611941-psmdb"

# get the source
DEST_DIR=$(git rev-parse --show-toplevel)/src/third_party/libkmip
PATCH_DIR=$(git rev-parse --show-toplevel)/src/third_party/libkmip/patches
if [[ -d $DEST_DIR/dist ]]; then
    echo "Please remove '$DEST_DIR/dist' before running $0" >&2
    exit 1
fi
git clone --depth 1 --branch $REVISION https://github.com/Percona-Lab/libkmip.git $DEST_DIR/dist

pushd $DEST_DIR/dist/
git apply $PATCH_DIR/*.patch
find . -mindepth 1 -maxdepth 1 \
    ! -name "CHANGELOG.rst" \
    ! -name "LICENSE*" \
    ! -name "README.md" \
    ! -name "include" \
    ! -name "src" \
    -exec rm -rf {} \;
rm include/kmip_bio.h include/kmip_io.h src/kmip_bio.c src/kmip_io.c
popd
