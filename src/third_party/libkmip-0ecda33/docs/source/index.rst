Welcome to libkmip
==================
libkmip is an ISO C11 implementation of the Key Management Interoperability
Protocol (KMIP), an `OASIS`_ communication standard for the management of
objects stored and maintained by key management systems. KMIP defines how key
management operations and operation data should be encoded and communicated
between client and server applications. Supported operations include creating,
retrieving, and destroying keys. Supported object types include:

* symmetric/asymmetric encryption keys

For more information on KMIP, check out the `OASIS KMIP Technical Committee`_
and the `OASIS KMIP Documentation`_.

Installation
------------
You can install libkmip from source using ``make``:

.. code-block:: console

    $ cd libkmip
    $ make
    $ make install

See :doc:`Installation <installation>` for more information.

Layout
------
libkmip provides client functionality, allowing developers to integrate the
key management lifecycle into their projects. For more information, check
out the various articles below:

.. toctree::
   :maxdepth: 2

   installation
   changelog
   faq
   development
   security
   api
   examples

.. _`OASIS`: https://www.oasis-open.org
.. _`OASIS KMIP Technical Committee`: https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip
.. _`OASIS KMIP Documentation`: https://docs.oasis-open.org/kmip/spec
