In the Percona Server for MongoDB repository, we upgraded `libbson` to
version 1.30.9, but did so only for `linux` on `amd64` and `arm64`
architectures, since we don't support any other platforms anyway. To
avoid misleading future maintainers into thinking that other platforms are
supported, we removed all the `*-config.h` and `*-version.h` files for those
platforms from the repository. We also updated the SConscript files so they no
longer mention those platforms.

Since the `import.sh` script doesn't generate the platform-specific files
itself, we did it manually as follows:
```shell
$ pushd /tmp
$ git clone --recurse-submodules --shallow-submodules  --depth 1 --branch 1.30.9 \
  https://github.com/mongodb/mongo-c-driver
$ pushd mongo-c-driver
$ cmake -B_build -H.
$ ls _build/src/common/src/
common-config.h
$ ls _build/src/libbson/src/bson/
bson-config.h  bson-version.h
$ cp _build/src/common/src/common-config.h <psmdb_repo_top_dir>/src/third_party/libbson/build_linux/
$ cp _build/src/libbson/src/bson/* <psmdb_repo_top_dir>/src/third_party/libbson/build_linux/bson/
```
