Installation
============

Dependencies
------------
Building libkmip requires the following dependencies:

* `OpenSSL 1.1.0`_

These may come installed by default on your target system or they may require
separate installation procedures. See each individual dependency's
documentation for more details.

.. _building-libkmip-on-linux:

Building libkmip on Linux
-------------------------
You can install libkmip from source via ``git``:

.. code-block:: console

    $ git clone https://github.com/openkmip/libkmip.git
    $ cd libkmip
    $ make
    $ make install

The default build settings will direct ``make`` to install libkmip under
``/usr/local``, which may require ``sudo`` access. There are several different
libkmip components that will be installed, including the documentation, the
source code and header files, the shared library, and the example demo
applications. The following list defines the default install directories and
the files that can be found in them:

* ``/usr/local/bin/kmip``
    Contains demo libkmip applications showing how to use the supported KMIP
    operations.
* ``/usr/local/include/kmip``
    Contains the libkmip header files for use in third-party applications.
* ``/usr/local/lib/kmip``
    Contains the libkmip shared library, ``libkmip.so``.
* ``/usr/local/src/kmip``
    Contains the libkmip source files.
* ``/usr/local/share/doc/kmip/src``
    Contains the libkmip documentation source files.
* ``/usr/local/share/doc/kmip/html``
    Contains the libkmip documentation HTML files `if they have have already
    been built`.

You can override the build defaults when invoking ``make install``. The
following list defines the build variables used by ``make`` and what their
default values are:

* ``PREFIX``
    Defines where libkmip will be installed. Defaults to ``/usr/local``.
* ``KMIP``
    Defines the common name of the libkmip subdirectories that will be created
    under ``PREFIX``. Defaults to ``kmip``.
* ``DESTDIR``
    Defines an alternative root of the file system where libkmip will be
    installed. Used primarily to test the installation process without needing
    to modify the default values of ``PREFIX`` or ``KMIP``. Defaults to the
    empty string.

For example, to install libkmip under your home directory, you could use the
following command:

.. code-block:: console

    $ make PREFIX=$HOME/.local install

This would create all of the normal installation directories (e.g., ``bin``,
``include``, ``lib``) under ``$HOME/.local`` instead of ``/usr/local``.

To ensure that your system is up-to-date after you install libkmip, make sure
to run ``ldconfig`` to update the dynamic linker's run-time bindings.

.. code-block:: console

    $ ldconfig

For more information see the project Makefile (insert link here).

Uninstalling libkmip
--------------------
You can uninstall libkmip using the provided ``make uninstall`` target:

.. code-block:: console

    $ cd libkmip
    $ make uninstall

This will simply remove all of the installation directories and files created
during the above installation process. Like with ``make install``, the default
build settings will direct ``make`` to remove libkmip from under
``/usr/local``, which may require ``sudo`` access. If you customize the
installation settings, be sure to use those same settings when uninstalling.

Like the installation process, run ``ldconfig`` again after uninstall to make
the dynamic linker is up-to-date.

.. _`OpenSSL 1.1.0`: https://www.openssl.org/docs/man1.1.0/