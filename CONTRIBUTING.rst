Contributing guide
==================

Welcome to Percona Server for MongoDB!

We’re glad that you would like to become a Percona community member and
participate in keeping open source open.

You can contribute in one of the following ways:

1. Reach us on our `Forums <https://forums.percona.com>`_ and
   `Discord <https://discord.gg/mQEyGPkNbR%5D(https://discord.gg/mQEyGPkNbR)>`_.
2. `Submit a bug report or a feature
   request <https://github.com/percona/percona-server-mongodb/blob/master/README>`_
3. Submit a pull request (PR) with the code patch.

This document describes the workflow for submitting pull requests.

Prerequisites
-------------

Before submitting code contributions, we ask you to complete the
following prerequisites.

1. Sign the CLA
~~~~~~~~~~~~~~~

Before you can contribute, we kindly ask you to sign our `Contributor
License
Agreement <https://cla-assistant.percona.com/percona-server-mongodb>`_
(CLA). You can do this in one click using your GitHub account.

**Note**: You can sign it later, when submitting your first pull
request. The CLA assistant validates the PR and asks you to sign the CLA
to proceed.

2. Code of Conduct
~~~~~~~~~~~~~~~~~~

Please make sure to read and agree to our `Code of
Conduct <https://percona.community/contribute/coc/>`_.

Submitting a pull request
-------------------------

All bug reports, enhancements and feature requests are tracked in Jira.
Though not mandatory, we encourage you to first check for a bug report
among `Jira issues <https://jira.percona.com/projects/PSMDB/issues>`_
and in the `PR
list <https://github.com/percona/percona-server-mongodb/pulls>`_:
perhaps the bug has already been addressed.

For feature requests and enhancements, we ask you to create a Jira
issue, describe your idea and discuss the design with us. This way we
align your ideas with our vision for the product development.

If the bug hasn’t been reported / addressed, or we’ve agreed on the
enhancement implementation with you, do the following:

1. `Fork <https://docs.github.com/en/github/getting-started-with-github/fork-a-repo>`_ this repository

2. Clone this repository on your machine and sync it with upstream.

   There are several active versions of the project. Each version has
   its dedicated branch:

   -  v3.6 (EOL)
   -  v4.0
   -  v4.2
   -  v4.4
   -  v5.0
   -  master - this branch is the source for the next version, should it
      appear. You should not commit your changes to master branch.

3. Create a branch for your changes based on the corresponding version
   branch. Please add the version to the end of the branch’s name
   (e.g. ``<new-branch-4.4>``)

4. Make your changes. Please follow these `code
   guidelines <https://github.com/mongodb/mongo/wiki/Server-Code-Style>`_
   to improve code readability.

5. Test your changes locally. See the `Running tests
   locally <#running-tests-locally>`_ section for more information

6. Commit the changes. Add the Jira issue number at the beginning of
   your message subject so that is reads as
   ``<JIRAISSUE> - My subject``. The `commit message
   guidelines <https://gist.github.com/robertpainsi/b632364184e70900af4ab688decf6f53>`_
   will help you with writing great commit messages

7. Open a pull request to Percona

8. Our team will review your code and if everything is correct, will
   merge it. Otherwise, we will contact you for additional information
   or with the request to make changes.

Building Percona Server for MongoDB
-----------------------------------

Instead of building Percona Server for MongoDB from source, you can
`download <https://www.percona.com/downloads/percona-server-mongodb-4.0/>`_
and use binary tarballs. Follow the `installation
instructions <https://www.percona.com/doc/percona-server-for-mongodb/4.0/install/tarball.html>`_
in our documentation.

To build Percona Server for MongoDB, you will need: - A modern C++
compiler capable of compiling C++17 like GCC 5.4.0 or newer - Amazon AWS
Software Development Kit for C++ library - Python 2.7.x and Pip. - The
set of dependencies for your operating system.

================================ =========================
Linux Distribution               Dependencies
================================ =========================
Debian/Ubuntu                    python2 python2-dev
\                                cmake gcc g++ curl wget
\                                lsb-release scons
\                                patchelf liblz4-dev
\                                devscripts libpcap-dev
\                                libbz2-dev libsnappy-dev
\                                pkg-config zlib1g-dev
\                                libzlcore-dev dh-systemd
\                                libsasl2-dev
\                                libcurl4-openssl-dev
\                                libssl-dev libldap2-dev
\                                libkrb5-dev e2fslibs-dev
RedHat Enterprise Linux/CentOS 7 centos-release-scl
\                                epel-release wget
\                                python-pip python-devel
\                                libpcap-devel gcc make
\                                cmake gcc-c++ scons
\                                openssl-devel
\                                cyrus-sasl-devel
\                                snappy-devel zlib-devel
\                                bzip2-devel rpmlint
\                                rpm-build libopcodes
\                                libcurl-devel lz4-devel
\                                e2fsprogs-devel
\                                expat-devel
\                                openldap-devel krb5-devel
\                                devtoolset-8-gcc
\                                devtoolset-8-gcc-c++
RedHat Enterprise Linux/CentOS 8 python2 python2-devel gcc
\                                gcc-c++ cmake zlib-devel
\                                openssl-devel expat-devel
\                                cyrus-sasl-devel xz-devel
\                                bzip2-devel libcurl-devel
\                                lz4-devel e2fsprogs-devel
\                                krb5-devel openldap-devel
\                                wget
================================ =========================

Build steps
~~~~~~~~~~~

Debian/Ubuntu
^^^^^^^^^^^^^

1. Clone this repository and the AWS Software Development Kit for C++
   repository

.. code:: sh

   git clone https://github.com/percona/percona-server-mongodb.git
   git clone https://github.com/aws/aws-sdk-cpp.git

2. Install the dependencies for your operating system. The following
   command installs the dependencies for Ubuntu 20.04:

.. code:: sh

   sudo apt install -y python2 python2-dev cmake gcc g++ curl wget lsb-release scons patchelf liblz4-dev devscripts libpcap-dev libbz2-dev libsnappy-dev pkg-config zlib1g-dev libzlcore-dev dh-systemd libsasl2-dev libcurl4-openssl-dev libssl-dev libldap2-dev libkrb5-dev e2fslibs-dev

3. Install Python dependencies

   -  Install Pip

   .. code:: sh

      wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
      sudo python2 get-pip.py

   -  Switch to the Percona Server for MongoDB branch that you are
      building and install Python modules

   .. code:: sh

      cd percona-server-mongodb && git checkout v4.0
      pip install --user -r buildscripts/requirements.txt

4. Define Percona Server for MongoDB version (4.0.23 for the time of
   writing this document)

.. code:: sh

   echo '{"version": "4.0.23"}' > version.json

5. Build the AWS Software Development Kit for C++ library

   -  Create a directory to store the AWS library

   .. code:: sh

      mkdir -p /tmp/lib/aws

   -  Declare environment variables ``AWS_LIBS`` and ``AWS_INSTALLDIR``
      for this directory

   .. code:: sh

      export AWS_LIBS=/tmp/lib/aws && export AWS_INSTALLDIR=aws-sdk-cpp

   -  Percona Server for MongoDB is built with AWS SDK CPP 1.8.56
      version. Switch to this version

   .. code:: sh

      cd aws-sdk-cpp && git checkout 1.8.56

   -  It is recommended to keep build files outside the SDK directory.
      Create a build directory and navigate to it

   .. code:: sh

      mkdir build && cd build

   -  Generate build files using ``cmake``

   .. code:: sh

      cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3;transfer" -DBUILD_SHARED_LIBS=OFF -DMINIMIZE_SIZE=ON -DCMAKE_INSTALL_PREFIX="${AWS_LIBS}"

   -  Install the SDK

   .. code:: sh

      make install

6. Build Percona Server for MongoDB

   -  Change directory to ``percona-server-mongodb``

   .. code:: sh

      cd percona-server-mongodb

   -  Build Percona Server for MongoDB from ``buildscripts/scons.py``.

   .. code:: sh

      buildscripts/scons.py -j$(nproc --all) --disable-warnings-as-errors --ssl --opt=on --use-sasl-client --wiredtiger --audit --inmemory --hotbackup CPPPATH="${AWS_LIBS}/include" LIBPATH="${AWS_LIBS}/lib" mongod

This command builds only the database. Other available targets for the
``scons`` command are: - ``mongod`` - ``mongos`` - ``mongo`` - ``core``
(includes ``mongod``, ``mongos``, ``mongo``) - ``all``

The built binaries are in the ``percona-server-mongodb`` directory.

Red Hat Enterprise Linux/CentOS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Clone this repository and the AWS Software Development Kit for C++
   repository

.. code:: sh

   git clone https://github.com/percona/percona-server-mongodb.git
   git clone https://github.com/aws/aws-sdk-cpp.git

2. Install the dependencies for your operating system. The following
   command installs the dependencies for Centos 7:

.. code:: sh

   sudo yum -y install centos-release-scl epel-release
   sudo yum -y install python-pip python-devel libpcap-devel gcc make cmake wget cmake3 gcc-c++ openssl-devel cyrus-sasl-devel snappy-devel zlib-devel bzip2-devel scons rpmlint rpm-build libopcodes libcurl-devel e2fsprogs-devel expat-devel lz4-devel openldap-devel krb5-devel devtoolset-8-gcc devtoolset-8-gcc-c++

3. Install Python dependencies

   -  Install Pip

   .. code:: sh

      wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
      sudo python2 get-pip.py

   -  Switch to the Percona Server for MongoDB branch that you are
      building

   .. code:: sh

      cd percona-server-mongodb && git checkout v4.0

   -  Install Python modules pip install –user setuptools –upgrade pip
      install –user typing pyyaml regex Cheetah Cheetah3 pip install
      –user -r buildscripts/requirements.txt \``\`

4. Define Percona Server for MongoDB version (4.0.23 for the time of
   writing this document)

.. code:: sh

   echo '{"version": "4.0.23"}' > version.json

5. Build a specific ``curl`` version

   -  Return to the home directory

   .. code:: sh

      cd /

   -  Fetch the package archive

   .. code:: sh

      wget https://curl.se/download/curl-7.66.0.tar.gz

   -  Unzip the package

   .. code:: sh

      tar -xvzf curl-7.66.0.tar.gz && cd curl-7.66.0

   -  Configure and build the package

   .. code:: sh

      ./configure
      sudo make install

6. Build the AWS Software Development Kit for C++ library

   -  Create a directory to store the AWS library

   .. code:: sh

      mkdir -p /tmp/lib/aws

   -  Declare an environment variable ``AWS_LIBS`` for this directory

   .. code:: sh

      export AWS_LIBS=/tmp/lib/aws 

   -  Percona Server for MongoDB is built with AWS SDK CPP 1.8.56
      version. Switch to this version

   .. code:: sh

      cd aws-sdk-cpp && git checkout 1.8.56

   -  It is recommended to keep build files outside of the SDK
      directory. Create a build directory and navigate to it

   .. code:: sh

      mkdir build && cd build

   -  Generate build files using ``cmake``

      On RedHat Enterprise Linux / CentOS 7:

      .. code:: sh

         cmake3 .. -DCMAKE_C_COMPILER=/opt/rh/devtoolset-8/root/usr/bin/gcc  -DCMAKE_CXX_COMPILER=/opt/rh/devtoolset-8/root/usr/bin/g++ -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3;transfer" -DBUILD_SHARED_LIBS=OFF -DMINIMIZE_SIZE=ON -DCMAKE_INSTALL_PREFIX="${AWS_LIBS}"

      On RedHat Enterprise Linux / CentOS 8:

      .. code:: sh

         cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3;transfer" -DBUILD_SHARED_LIBS=OFF -DMINIMIZE_SIZE=ON -DCMAKE_INSTALL_PREFIX="${AWS_LIBS}"

   -  Install the SDK

   .. code:: sh

      make install

7. Build Percona Server for MongoDB

   -  Change directory to ``percona-server-mongodb``

   .. code:: sh

      cd percona-server-mongodb

   -  Build Percona Server for MongoDB from ``buildscripts/scons.py``.
      On Red Hat Enterprise Linux / CentOS 7:

   .. code:: sh

      buildscripts/scons.py CC=/opt/rh/devtoolset-8/root/usr/bin/gcc CXX=/opt/rh/devtoolset-8/root/usr/bin/g++ -j$(nproc --all) --disable-warnings-as-errors --ssl --opt=on --use-sasl-client --wiredtiger --audit --inmemory --hotbackup CPPPATH="${AWS_LIBS}/include" LIBPATH="${AWS_LIBS}/lib64" mongod

   On Red Hat Enterprise Linux / CentOS 8:

   .. code:: sh

      buildscripts/scons.py -j$(nproc --all) --disable-warnings-as-errors --ssl --opt=on --use-sasl-client --wiredtiger --audit --inmemory --hotbackup CPPPATH="${AWS_LIBS}/include" LIBPATH="${AWS_LIBS}/lib64" mongod

   This command builds only the database. Other available targets for
   the ``scons`` command are:

-  ``mongod``
-  ``mongos``
-  ``mongo``
-  ``core`` (includes ``mongod``, ``mongos``, ``mongo``)
-  ``all``

The built binaries are in the ``percona-server-mongodb`` directory.

Running tests locally
---------------------

When you work, you should periodically run tests to check that your
changes don’t break existing code.

You can run tests on your local machine with whatever operating system
you have. After you submit the pull request, we will check your patch on
multiple operating systems.

Since testing Percona Server for MongoDB doesn’t differ from testing
MongoDB Community Edition, use `these guidelines for running
tests <https://github.com/mongodb/mongo/wiki/Test-The-Mongodb-Server>`_

After your pull request is merged
---------------------------------

Once your pull request is merged, you are an official Percona Community
Contributor. Welcome to the community!
