Contributing guide
==================

Welcome to Percona Server for MongoDB!

We’re glad that you would like to become a Percona community member and
participate in keeping open source open.

You can contribute in one of the following ways:

1. Reach us on our `Forums`_ and
   `Discord <https://discord.gg/mQEyGPkNbR%5D(https://discord.gg/mQEyGPkNbR)>`_.
2. Submit a bug report or a feature
   request. Read about it in `README`_
3. Submit a pull request (PR) with the code patch.

This document describes the workflow for submitting pull requests.

Prerequisites
-------------

Before submitting code contributions, we ask you to complete the
following prerequisites.

1. **Sign the CLA**. Before you can contribute, we kindly ask you to sign our `Contributor License Agreement`_ (CLA). You can do this in one click using your GitHub account.

    **Note**: You can sign it later, when submitting your first pull
    request. The CLA assistant validates the PR and asks you to sign the CLA
    to proceed.

2. **Code of Conduct**. Please make sure to read and agree to our `Code of
Conduct`_.

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

   -  v6.0
   -  v7.0
   -  v8.0
   -  master - this branch is the source for the next version, should it
      appear. You should not commit your changes to master branch.

3. Create a branch for your changes based on the corresponding version
   branch. Please add the version to the end of the branch’s name
   (e.g. ``<new-branch-v8.0>``)

4. Make your changes. Please follow these `code
   guidelines <https://github.com/mongodb/mongo/wiki/Server-Code-Style>`_
   to improve code readability.

5. Test your changes locally. See the :ref:`Running tests
   locally <tests>` section for more information

6. Commit the changes. Add the Jira issue number at the beginning of
   your message subject so that is reads as
   ``<JIRAISSUE> - My subject``. The `commit message
   guidelines <https://gist.github.com/robertpainsi/b632364184e70900af4ab688decf6f53>`_
   will help you with writing great commit messages

7. Open a pull request to Percona

8. Our team will review your code and if everything is correct, will
   merge it. Otherwise, we will contact you for additional information
   or with the request to make changes.

.. _build:

Building Percona Server for MongoDB
-----------------------------------

Instead of building Percona Server for MongoDB from source, you can
`download <https://www.percona.com/downloads/percona-server-mongodb-5.0/>`_
and use binary tarballs. Follow the `installation
instructions <https://www.percona.com/doc/percona-server-for-mongodb/5.0/install/tarball.html>`_ in our documentation.

To build Percona Server for MongoDB, you will need: 

- A modern C++ compiler capable of compiling C++20. You may use GCC 11.3 or newer 
- Amazon AWS Software Development Kit for C++ library 
- Python 3.10.x and Pip modules. 
- Poetry 1.5.1.
- The set of dependencies for your operating system.
- About 13 GB of disk space for the core binaries (`mongod`, `mongos`, and `mongo`) and about 600 GB for the `install-all` target.

The following table lists dependencies for Ubuntu 22.04 and Red Hat Enterprise 9 and compatible derivatives:

================================ =========================
Linux Distribution               Dependencies
================================ =========================
Debian/Ubuntu                    gcc g++ cmake curl 
                                 libssl-dev libldap2-dev 
                                 libkrb5-dev                 libcurl4-openssl-dev 
                                 libsasl2-dev liblz4-dev 
                                 libpcap-dev libbz2-dev 
                                 libsnappy-dev zlib1g-dev 
                                 libzlcore-dev liblzma-dev 
                                 ibext2fs-dev e2fslibs-dev 
                                 bear
RedHat Enterprise Linux          gcc gcc-c++ cmake curl 
                                 binutils-devel 
                                 openssl-devel 
                                 openldap-devel krb5-devel 
                                 libcurl-devel 
                                 cyrus-sasl-devel 
                                 bzip2-devel zlib-devel 
                                 lz4-devel xz-devel 
                                 e2fsprogs-devel
                                 expat-devel cmake
================================ =========================

Build steps
~~~~~~~~~~~

Install operating system dependencies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Debian/Ubuntu

  The following command installs the dependencies for Ubuntu 22.04:

  .. code:: bash

     $ sudo apt install -y gcc g++ cmake curl libssl-dev libldap2-dev libkrb5-dev libcurl4-openssl-dev libsasl2-dev liblz4-dev libbz2-dev libsnappy-dev zlib1g-dev libzlcore-dev liblzma-dev e2fslibs-dev


* RHEL and derivatives

  The following command installs the dependencies for RHEL 9:

  .. code:: bash

     $ sudo yum -y install gcc gcc-c++ cmake curl openssl-devel openldap-devel krb5-devel libcurl-devel cyrus-sasl-devel bzip2-devel zlib-devel lz4-devel xz-devel e2fsprogs-devel
   

Build AWS Software Development Kit for C++ library
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Clone the AWS Software Development Kit for C++ repository

   .. code:: bash

      $ git clone --recurse-submodules https://github.com/aws/aws-sdk-cpp.git

2. Create a directory to store the AWS library

   .. code:: bash

      $ mkdir -p /tmp/lib/aws

3. Declare an environment variable ``AWS_LIBS`` for this directory
   ``{.bash data-prompt="$"}     $ export AWS_LIBS=/tmp/lib/aws``

4. Percona Server for MongoDB is built with AWS SDK CPP 1.9.379 version.
   Switch to this version

   .. code:: bash

      $ cd aws-sdk-cpp && git checkout 1.9.379

5. It is recommended to keep build files outside the SDK directory.
   Create a build directory and navigate to it

   .. code:: bash

      $ mkdir build && cd build

6. Generate build files using ``cmake``

   .. code:: bash

      $ cmake .. -DCMAKE_BUILD_TYPE=Release '-DBUILD_ONLY=s3;transfer' -DBUILD_SHARED_LIBS=OFF -DMINIMIZE_SIZE=ON -DCMAKE_INSTALL_PREFIX="${AWS_LIBS}"

7. Install the SDK

   .. code:: bash

      $ make install


Install Python and Python modules
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Make sure the `python3`, `python3-dev`, `python3-pip` Python packages are installed on your machine. Otherwise, install them using the package manager of your operating system.

2. Create and activate the virtual environment for Poetry - a Python dependency management and packaging tool for Percona Server for MongoDB. It is a good practice to isolate Poetry from the rest of your system in a virtual environment to ensure that its dependencies are not accidentally upgraded nor uninstalled. Run the following commands and specify the path to your virtual environment in a `<venv_path>`:

.. code:: sh

   $ python3 -m venv <venv_path> --prompt mongo
   $ source <venv_path>/bin/activate 


3. Clone Percona Server for MongoDB repository

   .. code:: sh

      $ git clone https://github.com/percona/percona-server-mongodb.git

4. Switch to the Percona Server for MongoDB branch that you are building
   and install Poetry

   .. code:: sh

      $ cd percona-server-mongodb && git checkout v8.0
      $ python3 -m pip install 'poetry==1.5.1'

5. Install Python dependencies:

   .. code:: sh

      $ python3 -m poetry install --no-root --sync

6. Define Percona Server for MongoDB version (8.0.1 for the time of
   writing this document)

   .. code:: sh

      $ echo '{"version": "8.0.1"}' > version.json

1. Change directory to ``percona-server-mongodb``

   .. code:: bash

      $ cd percona-server-mongodb

2. Build Percona Server for MongoDB from ``buildscripts/scons.py``

   * Basic build

     .. code:: bash

        $ buildscripts/scons.py --disable-warnings-as-errors --release --ssl --opt=on -j$(nproc --all) --use-sasl-client --wiredtiger --audit --inmemory --hotbackup CPPPATH="${AWS_LIBS}/include" LIBPATH="${AWS_LIBS}/lib ${AWS_LIBS}/lib64" install-mongod install-mongos
        

   * Pro build

     .. code:: bash

        $ buildscripts/scons.py --disable-warnings-as-errors --release --ssl --opt=on -j$(nproc --all) --use-sasl-client --wiredtiger --audit --inmemory --hotbackup --full-featured CPPPATH="${AWS_LIBS}/include" LIBPATH="${AWS_LIBS}/lib ${AWS_LIBS}/lib64" install-mongod install-mongos
        

   This command builds core components of the database. Other available
   targets for the ``scons`` command are:

   -  ``install-mongod``
   -  ``install-mongos``
   -  ``install-servers`` (includes mongod and mongos)
   -  ``install-core`` (includes mongod and mongos)
   -  ``install-devcore`` (includes mongod, mongos, and jstestshell
      (formerly mongo shell))
   -  ``install-all``

The built binaries are in the ``percona-server-mongodb`` directory.


.. _tests:

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



.. _Forums: <https://forums.percona.com>
.. _README: <https://github.com/percona/percona-server-mongodb/blob/master/README>
.. _Code of conduct: <https://forums.percona.com>
.. _Contributor License Agreement: <https://forums.percona.com>
