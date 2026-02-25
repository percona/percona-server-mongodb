# Vendoring AWS SDK for C++ into Percona Server for MongoDB®

Note. _Please read `src/third_party/README.Percona.md` first._

Vendoring AWS SDK for C++ (further referred to as `aws-sdk-cpp`) is more than
just copying the source code from its GitHub repository to the respective
subdirectory within the repository of Percona Server for MongoDB (further
referred to as `PSMDB`). First, `aws-sdk-cpp` repo comprises a great number of
submodules that should also be fetched while cloning the main repo. However,
not all of those are actually used in PSMDB. We should be mindful about which
parts of `aws-sdk-cpp` we copy into PSMDB in order to prevent having dead code
in the PSMDB repository. Moreover, a significant part of `aws-sdk-cpp` source
code is actually generated during the build process, making it necessary to run
the build before copying the source files. The build, in turn, requires
installing a number of dependencies. Finally, some of the files the build
generates are tailored to a CPU architecture, so we should repeat the build
on all supported machine types.

The `src/third_party/aws-sdk-cpp/scripts/import.sh` script handles all the
aforementioned aspects in a holistic way. When run with the `-p` option,
it generates and imports the architecture-specific files to the subdirectory
dedicated to that architecture under `src/third_party/aws-sdk-cpp/platform`.
If no options are specified, the script generates and imports
architecture-independent source code into `src/third_party/aws-sdk-cpp/dist`.

The procedure of importing `aws-sdk-cpp` source code looks like the following:
01. On a host of any CPU architecture, check out the PSMDB repository and
    execute `src/third_party/aws-sdk-cpp/scripts/import.sh`
02. Commit the new files
03. On an `x86_64` host, check out the PSMDB repository and execute
    `src/third_party/aws-sdk-cpp/scripts/import.sh -p`
04. Commit the new files
05. Repeat steps 3 and 4 on an `aarch64` host

Note. The script requires the user who runs it either is `root` or has the
permissions to run `sudo`.
