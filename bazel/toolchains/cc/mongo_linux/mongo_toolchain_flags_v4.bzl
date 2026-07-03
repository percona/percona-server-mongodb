COMMON_LINK_FLAGS = [
    "external/mongo_toolchain_v4/stow/gcc-v4/lib/gcc/{arch}-mongodb-linux/11.3.0",
    "external/mongo_toolchain_v4/v4/lib",
    "external/mongo_toolchain_v4/v4/lib64",
]

COMMON_BUILTIN_INCLUDE_DIRECTORIES = [
    "/usr/include/openssl",
    "/usr/include/{arch}-mongodb-linux",
    "/usr/include",
    # Debian13(trixie) relocated kernel UAPI headers to /usr/lib/linux/uapi/<arch>
    # (old /usr/include asm paths are now symlinks);
    # bazel's absolute-path-inclusion check needs the real dir.
    "/usr/lib/linux",
]

COMMON_INCLUDE_DIRECTORIES = [
    "external/mongo_toolchain_v4/stow/gcc-v4/include/c++/11.3.0",
    "external/mongo_toolchain_v4/stow/gcc-v4/include/c++/11.3.0/{arch}-mongodb-linux",
]

COMMON_BINDIRS = [
    "external/mongo_toolchain_v4/v4/bin",
    "external/mongo_toolchain_v4/stow/gcc-v4/libexec/gcc/{arch}-mongodb-linux/11.3.0",
    "external/mongo_toolchain_v4/stow/gcc-v4/lib/gcc/{arch}-mongodb-linux/11.3.0",
    "external/mongo_toolchain_v4/stow/llvm-v4/bin",
]

GCC_INCLUDE_DIRS = [
    "external/mongo_toolchain_v4/stow/gcc-v4/lib/gcc/{arch}-mongodb-linux/11.3.0/include",
    "external/mongo_toolchain_v4/stow/gcc-v4/lib/gcc/{arch}-mongodb-linux/11.3.0/include-fixed",
]

CLANG_INCLUDE_DIRS = [
    "external/mongo_toolchain_v4/stow/gcc-v4/include/c++/11.3.0/backward",
    "external/mongo_toolchain_v4/stow/llvm-v4/lib/clang/12.0.1/include",
]
