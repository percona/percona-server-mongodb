=========
Changelog
=========

.. _v0.2:

0.2 - July 12, 2019
~~~~~~~~~~~~~~~~~~~

* Add the BSD 3-clause license to the library
* Add KMIP 2.0 attributes
* Add deep copy utilities for all attribute types
* Upgrade Create support to enable KMIP 2.0 encodings
* Upgrade the unit test suite to use intelligent test tracking
* Upgrade the linked list to support enqueue and double linkage
* Fix an implicit infinite loop in the test suite application
* Fix a usage issue when passing no args to the demo applications
* Fix Travis CI config to redirect OpenSSL install logs to a file 

.. _v0.1:

0.1 - November 15, 2018
~~~~~~~~~~~~~~~~~~~~~~~

* Initial release
* Add encoding/decoding support for Symmetric/Public/Private Keys
* Add encoding/decoding support for Create/Get/Destroy operations
* Add KMIP 1.0 - 1.4 support for all supported KMIP structures
* Add an OpenSSL BIO client to securely connect to KMIP servers
* Add demo applications that show how to use the client API
* Add a unit test suite that covers the encoding/decoding library
* Add library documentation built and managed by Sphinx
* Add a Makefile that can build/install static/shared libraries

.. _`master`: https://github.com/OpenKMIP/libkmip/

