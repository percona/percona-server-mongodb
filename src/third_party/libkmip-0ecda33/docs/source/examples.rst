Examples
========
To demonstrate how to use libkmip, several example applications are built
and deployed with the library to get developers started.

Demos
-----
Three demo applications are included with libkmip, one for each of the
following KMIP operations:

* ``Create``
* ``Get``
* ``Destroy``

If libkmip is built, the demo applications can be found in the local build
directory. If libkmip is installed, the demo applications can also be found
in the bin directory, by default located at ``/usr/local/bin/kmip``.

Run any of the demo applications with the ``-h`` flag to see usage
information.

Create Demo
~~~~~~~~~~~
The ``Create`` demo, ``demo_create.c``, uses the :ref:`low-level-api` to issue
a KMIP request to the KMIP server to create a symmetric key. The application
manually creates the library context and initalizes it. It then manually
builds the request message structure, creating the following attributes for
the symmetric key:

* cryptographic algorithm (AES)
* cryptographic length (256 bits)
* cryptographic usage mask (Encrypt and Decrypt usage)

The demo application encodes the request and then sends it through the
low-level API to retrieve the response encoding. It decodes the response
encoding into the response message structure and then extracts the UUID of
the newly created symmetric key.

Get Demo
~~~~~~~~
The ``Get`` demo, ``demo_get.c``, uses the :ref:`mid-level-api` to issue a
KMIP request to the KMIP server to retrieve a symmetric key. The application
manually creates the library context and initializes it. It sets its own
custom memory handlers to override the default ones supplied by libkmip and
then invokes the mid-level API with the UUID of the symmetric key it wants
to retrieve.

The client API internally builds the corresponding request message, encodes
it, sends it via BIO to the KMIP server, retrieves the response encoding, and
then decodes the response into the corresponding response message structure.
Finally, it extracts the symmetric key bytes and copies them to a separate
block of memory that will be handed back to the demo application. Finally, it
cleans up the buffers used for the encoding and decoding process and cleans
up the response message structure.

Destroy Demo
~~~~~~~~~~~~
The ``Destroy`` demo, ``demo_destroy.c``, use the :ref:`high-level-api` to
issue a KMIP request to the KMIP server to destroy a symmetric key. The
application invokes the high-level API with the UUID of the symmetric key it
wants to destroy.

The client API internally builds the library context along with the
corresponding request message. It encodes the request, sends it via BIO to
the KMIP server, retrieves the response encoding, and then decodes the
response into the corresponding response message structure. Finally, it
extracts the result of the KMIP operation from the response message structure
and returns it.

Tests
-----
A test application is also included with libkmip to exercise the encoding and
decoding capabilities for all support KMIP features. The source code for this
application, ``tests.c``, contains numerous examples of how to build and use
different libkmip structures.

