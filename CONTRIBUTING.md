# Contributing guide

Welcome to Percona Server for MongoDB!

We're glad that you would like to become a Percona community member and participate in keeping open source open.  

You can contribute in one of the following ways:

1. Reach us on our [Forums](https://forums.percona.com) and [Discord]([https://discord.gg/mQEyGPkNbR](https://discord.gg/mQEyGPkNbR)).
2. [Submit a bug  report or a feature request](https://github.com/percona/percona-server-mongodb/blob/master/README) 
3. Submit a pull request (PR) with the code patch. 

This document describes the workflow for submitting pull requests.

## Prerequisites

Before submitting code contributions, we ask you to complete the following prerequisites.

### 1. Sign the CLA

Before you can contribute, we kindly ask you to sign our [Contributor License Agreement](https://cla-assistant.percona.com/percona-server-mongodb>) (CLA). You can do this in one click using your GitHub account.

**Note**:  You can sign it later, when submitting your first pull request. The CLA assistant validates the PR and asks you to sign the CLA to proceed.

### 2. Code of Conduct

Please make sure to read and agree to our [Code of Conduct](https://github.com/percona/community/blob/main/content/contribute/coc.md).


## Submitting a pull request

All bug reports, enhancements and feature requests are tracked in Jira. Though not mandatory, we encourage you to first check for a bug report among [Jira issues](https://jira.percona.com/projects/PSMDB/issues) and in the [PR list](https://github.com/percona/percona-server-mongodb/pulls): perhaps the bug has already been addressed. 

For feature requests and enhancements, we ask you to create a Jira issue, describe your idea and discuss the design with us. This way we align your ideas with our vision for the product development.

If the bug hasn’t been reported / addressed, or we’ve agreed on the enhancement implementation with you, do the following:

1. [Fork](https://docs.github.com/en/github/getting-started-with-github/fork-a-repo) this repository
2. Clone this repository on your machine and sync it with upstream. 

   There are several active versions of the project. Each version has its dedicated branch:
	
   * v4.0
   * v4.2
   * v4.4
   * v5.0
   * master - this branch is the source for the next version, should it appear. You should not commit your changes to master branch.

3. Create a branch for your changes based on the corresponding version branch. Please add the version to the end of the branch's name (e.g. `<new-branch-v4.4>`)
4. Make your changes. Please follow these [code guidelines](https://github.com/mongodb/mongo/wiki/Server-Code-Style) to improve code readability.
5. Test your changes locally. See the [Running tests locally](#running-tests-locally) section for more information
6. Commit the changes. Add the Jira issue number at the beginning of your  message subject so that is reads as `<JIRAISSUE> - My subject`. The [commit message guidelines](https://gist.github.com/robertpainsi/b632364184e70900af4ab688decf6f53) will help you with writing great commit messages
7. Open a pull request to Percona
8. Our team will review your code and if everything is correct, will merge it. 
Otherwise, we will contact you for additional information or with the request to make changes.

## Building Percona Server for MongoDB 

Instead of building Percona Server for MongoDB from source, you can [download](https://www.percona.com/downloads/percona-server-mongodb-5.0/) and use binary tarballs. Follow the [installation instructions](https://www.percona.com/doc/percona-server-for-mongodb/5.0/install/tarball.html) in our documentation.

To build Percona Server for MongoDB, you will need:
- A modern C++ compiler capable of compiling C++17 like GCC 8.2 or newer
- Amazon AWS Software Development Kit for C++ library
- Python 3.6.x and Pip.
- The set of dependencies for your operating system. 

| Linux Distribution              |  Dependencies           | 
| --------------------------------|-------------------------|
| Debian/Ubuntu                   |python3 python3-dev      |
|                                 |python3-pip scons gcc    |
|                                 |g++ cmake curl           |
|                                 |libssl-dev libldap2-dev  |
|                                 |libkrb5-dev              |
|                                 |libcurl4-openssl-dev     |
|                                 |libsasl2-dev liblz4-dev  |
|                                 |libpcap-dev libbz2-dev   |
|                                 |libsnappy-dev zlib1g-dev | 
|                                 |libzlcore-dev            |
|                                 |libsasl2-dev liblzma-dev |
|                                 |libext2fs-dev            |
|                                 |e2fslibs-dev bear        |
|CentOS / RedHat Enterprise Linux |centos-release-scl       |
|                                 |epel-release             | 
|                                 |python3 python3-devel    |
|                                 |scons gcc gcc-c++ cmake3 |
|                                 |openssl-devel            |
|                                 |cyrus-sasl-devel         |
|                                 |snappy-devel zlib-devel  |
|                                 |bzip2-devel libcurl-devel|
|                                 |lz4-devel openldap-devel |
|                                 |krb5-devel xz-devel      |
|                                 |e2fsprogs-devel          |
|                                 |expat-devel              |
|                                 |devtoolset-8-gcc         |
|                                 |devtoolset-8-gcc-c++     |
|RedHat Enterprise Linux/CentOS 8 |python36 python36-devel  |  
|                                 |gcc-c++ gcc cmake3 wget  |
|                                 |openssl-devel zlib-devel |
|                                 |cyrus-sasl-devel xz-devel|
|                                 |bzip2-devel libcurl-devel|
|                                 |lz4-devel e2fsprogs-devel|
|                                 |krb5-devel openldap-devel|
|                                 |expat-devel cmake        |

### Build steps

#### Debian/Ubuntu

1. Clone this repository and the AWS Software Development Kit for C++  repository
```sh
git clone https://github.com/percona/percona-server-mongodb.git
git clone https://github.com/aws/aws-sdk-cpp.git
```

2. Install the dependencies for your operating system. The following command installs the dependencies for Ubuntu 20.04:
```sh
sudo apt install -y python3 python3-dev python3-pip scons gcc g++ cmake curl libssl-dev libldap2-dev libkrb5-dev libcurl4-openssl-dev libsasl2-dev liblz4-dev libpcap-dev libbz2-dev libsnappy-dev zlib1g-dev libzlcore-dev libsasl2-dev liblzma-dev libext2fs-dev e2fslibs-dev bear
```

3. Switch to the Percona Server for MongoDB branch that you are building and install Python3 modules
```sh
cd percona-server-mongodb && git checkout v5.0
pip3 install --user -r etc/pip/dev-requirements.txt
```

4. Define Percona Server for MongoDB version (5.0.2 for the time of writing this document)
```sh
echo '{"version": "5.0.2"}' > version.json
```

5. Build the AWS Software Development Kit for C++ library
   - Create a directory to store the AWS library
   ```sh
   mkdir -p /tmp/lib/aws
   ```
   - Declare an environment variable ``AWS_LIBS`` for this directory
   ```sh
   export AWS_LIBS=/tmp/lib/aws
   ``` 
   - Percona Server for MongoDB is built with AWS SDK CPP 1.8.56 version. Switch to this version
   ```sh
   cd aws-sdk-cpp && git checkout 1.8.56
   ```
   - It is recommended to keep build files outside the SDK directory. Create a build directory and navigate to it
   ```sh
   mkdir build && cd build
   ```
   - Generate build files using ``cmake``
   ```sh
   cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3;transfer" -DBUILD_SHARED_LIBS=OFF -DMINIMIZE_SIZE=ON -DCMAKE_INSTALL_PREFIX="${AWS_LIBS}"
   ```
   - Install the SDK
   ```sh
   make install
   ```

6. Build Percona Server for MongoDB
   - Change directory to ``percona-server-mongodb``
   ```sh
   cd percona-server-mongodb
   ```
   - Build Percona Server for MongoDB from ``buildscripts/scons.py``.
   ```sh
   buildscripts/scons.py -j$(nproc --all) --jlink=2 --install-mode=legacy --disable-warnings-as-errors --ssl --opt=on --use-sasl-client --wiredtiger --audit --inmemory --hotbackup CPPPATH="${AWS_LIBS}/include" LIBPATH="${AWS_LIBS}/lib" mongod
   ```

This command builds only the database. Other available targets for the ``scons`` command are:
- ``mongod``
- ``mongos``
- ``mongo``
- ``core`` (includes ``mongod``, ``mongos``, ``mongo``)
- ``all``

The built binaries are in the ``percona-server-mongodb`` directory. 

#### Red Hat Enterprise Linux/CentOS

1. Clone this repository and the AWS Software Development Kit for C++  repository
```sh
git clone https://github.com/percona/percona-server-mongodb.git
git clone https://github.com/aws/aws-sdk-cpp.git
```

2. Install the dependencies for your operating system. The following command installs the dependencies for Centos 7:
```sh
sudo yum -y install centos-release-scl epel-release 
sudo yum -y install python3 python3-devel scons gcc gcc-c++ cmake3 openssl-devel cyrus-sasl-devel snappy-devel zlib-devel bzip2-devel libcurl-devel lz4-devel openldap-devel krb5-devel xz-devel e2fsprogs-devel expat-devel devtoolset-8-gcc devtoolset-8-gcc-c++
```

3. Switch to the Percona Server for MongoDB branch that you are building and install Python3 modules
```sh
cd percona-server-mongodb && git checkout v5.0
python3 -m pip install --user -r etc/pip/dev-requirements.txt
```
4. Define Percona Server for MongoDB version (5.0.2 for the time of writing this document)
```sh
echo '{"version": "5.0.2"}' > version.json
```

5. Build a specific `curl` version
   - Fetch the package archive
   ```sh
   wget https://curl.se/download/curl-7.66.0.tar.gz
   ```
   - Unzip the package
   ```sh
   tar -xvzf curl-7.66.0.tar.gz && cd curl-7.66.0
   ```
   - Configure and build the package
   ```sh
   ./configure
   sudo make install
   ```

6. Build the AWS Software Development Kit for C++ library
   - Create a directory to store the AWS library
   ```sh
   mkdir -p /tmp/lib/aws
   ```
   - Declare an environment variable ``AWS_LIBS`` for this directory
   ```sh
   export AWS_LIBS=/tmp/lib/aws
   ``` 
   - Percona Server for MongoDB is built with AWS SDK CPP 1.8.56 version. Switch to this version
   ```sh
   cd aws-sdk-cpp && git checkout 1.8.56
   ```
   - It is recommended to keep build files outside of the SDK directory. Create a build directory and navigate to it
   ```sh
   mkdir build && cd build
   ```
   - Generate build files using ``cmake``

     On RedHat Enterprise Linux CentOS 7:
     
      ```sh
      cmake3 .. -DCMAKE_C_COMPILER=/opt/rh/devtoolset-8/root/usr/bin/gcc  -DCMAKE_CXX_COMPILER=/opt/rh/devtoolset-8/root/usr/bin/g++ -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3;transfer" -DBUILD_SHARED_LIBS=OFF -DMINIMIZE_SIZE=ON -DCMAKE_INSTALL_PREFIX="${AWS_LIBS}"
      ```

      On RedHat Enterprise Linux CentOS 8:

      ```sh
      cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3;transfer" -DBUILD_SHARED_LIBS=OFF -DMINIMIZE_SIZE=ON -DCMAKE_INSTALL_PREFIX="${AWS_LIBS}"
      ```

   - Install the SDK
   ```sh
   make install
   ```

7. Build Percona Server for MongoDB
   - Change directory to ``percona-server-mongodb``
   ```sh
   cd percona-server-mongodb
   ```
   - Build Percona Server for MongoDB from ``buildscripts/scons.py``.
   On RedHat Enterprise Linux / CentOS 7:
   ```sh
   python3 buildscripts/scons.py CC=/opt/rh/devtoolset-8/root/usr/bin/gcc CXX=/opt/rh/devtoolset-8/root/usr/bin/g++ -j$(nproc --all) --jlink=2 --install-mode=legacy --disable-warnings-as-errors --ssl --opt=on --use-sasl-client --wiredtiger --audit --inmemory --hotbackup CPPPATH="${AWS_LIBS}/include" LIBPATH="${AWS_LIBS}/lib" mongod
   ```

   On RedHat Enterprise Linux / CentOS 8:
   ```sh
   buildscripts/scons.py -j$(nproc --all) --jlink=2 --install-mode=legacy --disable-warnings-as-errors --ssl --opt=on --use-sasl-client --wiredtiger --audit --inmemory --hotbackup CPPPATH="${AWS_LIBS}/include" LIBPATH="${AWS_LIBS}/lib64" mongod
   ```

This command builds only the database. Other available targets for the ``scons`` command are:
- ``mongod``
- ``mongos``
- ``mongo``
- ``core`` (includes ``mongod``, ``mongos``, ``mongo``)
- ``all``

The built binaries are in the ``percona-server-mongodb`` directory.  

## Running tests locally

When you work, you should periodically run tests to check that your changes don’t break existing code.

You can run tests on your local machine with whatever operating system you have. After you submit the pull request, we will check your patch on multiple operating systems.

Since testing Percona Server for MongoDB doesn’t differ from testing MongoDB Community Edition, use [these guidelines for running tests](https://github.com/mongodb/mongo/wiki/Test-The-Mongodb-Server)

## After your pull request is merged

Once your pull request is merged, you are an official Percona Community Contributor. Welcome to the community!