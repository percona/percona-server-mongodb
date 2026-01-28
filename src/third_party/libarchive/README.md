# Generating the `config.h` file

This is a description of how to generate the following files:
```
src/third_party/libarchive/platform/build_linux_aarch64/config.h
src/third_party/libarchive/platform/build_linux_x86_64/config.h
```

The `libarchive` library uses `cmake` (or `autotools`) as a build tool.
Ideally, we would only need to run `cmake` on the fork repo cloned to the
`dist` directory. However, `cmake` requires tons of stuff besides the source
code itself to be present. Keeping all that stuff (as opposed to stripping it
out in the `import.sh` script) would be overkill just to generate `config.h`.
Additionally, and more importantly, in `libarchive` particularly, `cmake` also
detects libraries and header files installed on the system while doing
configuration, even if all additional options are disabled, which makes some
kind of a clean environment necessary.

As a result, if we wrote a script for generating `config.h` following the
`src/third_party/snappy/scripts/generate_config_headers.sh` approach, it would
be neither complete nor reliable. Instead, we used the following manual method:
```shell
(host) $ docker container run -it oraclelinux:8 bash
(container) $ dnf update && dnf -y install gcc git cmake
(container) $ git clone --depth 1 --branch v3.8.4-percona \
    https://github.com/Percona-Lab/libarchive.git
(container) $ pushd libarchive
(container) $ cmake \
    -DENABLE_OPENSSL=OFF \
    -DENABLE_LIBB2=OFF \
    -DENABLE_LZ4=OFF \
    -DENABLE_LZMA=OFF \
    -DENABLE_ZSTD=OFF \
    -DENABLE_ZLIB=OFF \
    -DENABLE_BZip2=OFF \
    -DENABLE_LIBXML2=OFF \
    -DENABLE_EXPAT=OFF \
    -DENABLE_WIN32_XMLLITE=OFF \
    -DENABLE_PCREPOSIX=OFF \
    -DENABLE_PCRE2POSIX=OFF \
    -DENABLE_LIBGCC=OFF \
    -DENABLE_CNG=OFF \
    -DENABLE_TAR=OFF \
    -DENABLE_CPIO=OFF \
    -DENABLE_CAT=OFF \
    -DENABLE_UNZIP=OFF \
    -DENABLE_XATTR=OFF \
    -DENABLE_ACL=OFF \
    -DENABLE_ICONV=OFF \
    -DENABLE_TEST=OFF \
    -DENABLE_COVERAGE=OFF \
    -DENABLE_INSTALL=OFF \
    -H. -B_build
(host) $ docker container cp <container_id>:/libarchive/_build/config.h \
    src/third_party/libarchive/platform/build_<os_type>_<cpu_arch>/config.h
```
Please execute the above instructions on both `x86_64` and `aarch64` machines
and commit the obtained `config.h` files into the PSMDB repository.
