API
===
libkmip is composed of several components:

* an encoding/decoding library 
* a client library
* a utilities library

The encoding library transforms KMIP message structures to and from the KMIP
binary TTLV encoding format. The client library uses the `OpenSSL BIO library`_
to create secure connections with a KMIP server, sending and receiving
TTLV-encoded messages. Finally, the utilities library is used to create and
manage the library context and its associated structures which are used by the
client library. Together, these components can be used to conduct secure key
management operations.

.. _client-api:

Client API
----------
The libkmip Client API supports varying levels of granularity, allowing parent
applications access to everything from the low-level encoded message buffer
up to high-level KMIP operation functions that handle all of the message
building and encoding details automatically.

The following function signatures define the client API and can be found in
``kmip_bio.h``:

.. code-block:: c

   /* High-level API */
   int kmip_bio_create_symmetric_key(BIO *, TemplateAttribute *, char **, int *);
   int kmip_bio_get_symmetric_key(BIO *, char *, int, char **, int *);
   int kmip_bio_destroy_symmetric_key(BIO *, char *, int);
   
   /* Mid-level API */
   int kmip_bio_create_symmetric_key_with_context(KMIP *, BIO *, TemplateAttribute *, char **, int *);
   int kmip_bio_get_symmetric_key_with_context(KMIP *, BIO *, char *, int, char **, int *);
   int kmip_bio_destroy_symmetric_key_with_context(KMIP *, BIO *, char *, size_t);

   /* Low-level API */
   int kmip_bio_send_request_encoding(KMIP *, BIO *, char *, int, char **, int *); 

.. _high-level-api:

High-level API
~~~~~~~~~~~~~~
The high-level client API contains KMIP operation functions that simply
require the inputs for a specific KMIP operation. Using these functions, the
library will automatically:

* create the libkmip library context (see :ref:`the-libkmip-context`)
* create the request message structure
* encode the request message structure into a request encoding
* send the request encoding to the BIO-connected KMIP server
* receive the response encoding back from the BIO-connected KMIP server
* decode the response encoding into the response message structure
* extract the relevant output from the response message structure
* clean up the library context and the encoding buffers
* handle any errors that occur throughout the request/response process

Because the library context and encoding processes are handled internally, the
parent application has no access to additional debugging or error information
when the KMIP operation fails. There is also no way to control or manage the
dynamic memory allocation process required for the encoding buffers and the
decoding process. If this information and/or capability is needed by the
parent application, consider switching to use the :ref:`mid-level-api` or
:ref:`low-level-api` which provide these capabilities.

The function header details for each of the high-level API functions are
provided below.

.. c:function:: int kmip_bio_create_symmetric_key(BIO *, TemplateAttribute *, char **, int *)

    Create a symmetric key with the attributes provided in the
    ``TemplateAttribute`` structure.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to the
        KMIP server that will create the symmetric key.
    :param TemplateAttribute*: A libkmip ``TemplateAttribute`` structure
        containing the attributes for the symmetric key (e.g., cryptographic
        algorithm, cryptographic length).
    :param char**: A double pointer that can be used to access the UUID of the
        newly created symmetric key.

        .. note::
           This pointer will point to a newly allocated block of memory. The
           parent application is responsible for clearing and freeing this
           memory once it is done using the UUID.

    :param int*: A pointer that can be used to access the length of the UUID
        string pointed to by the above double pointer.

    :return: A status code indicating success or failure of the operation. A
        negative status code indicates a libkmip error occurred while
        processing the request. A positive status code indicates a KMIP error
        occurred while the KMIP server processed the request. A status code
        of 0 indicates the operation succeeded.

        The following codes are returned explicitly by this function. If the
        code returned is negative and is not listed here, it is the result of
        the request encoding or response decoding process. See
        :ref:`status-codes` for all possible status code values.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``TemplateAttribute`` pointer is set to ``NULL``
            * the ``char **`` UUID double pointer is set to ``NULL``
            * the ``int *`` UUID size pointer is set to ``NULL``

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during the key creation call. This
            failure can occur during any of the following steps:

            * creation/resizing of the encoding buffer
            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during the key creation call. This
            failure can occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the default libkmip
            library context. Switching to the :ref:`mid-level-api` will
            allow the parent application to set the max message size in the
            library context directly.

        * ``KMIP_MALFORMED_RESPONSE``
            The received response message from the KMIP server is malformed
            and does not contain valid operation result information.

.. c:function:: int kmip_bio_get_symmetric_key(BIO *, char *, int, char **, int *)

    Retrieve a symmetric key identified by a specific UUID.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to
        the KMIP server that stores the symmetric key.
    :param char*: A string containing the UUID of the symmetric key to retrieve.
    :param int: The length of the above UUID string.
    :param char**: A double pointer that can be used to access the bytes of
        the retrieved symmetric key.

        .. note::
           This pointer will point to a newly allocated block of memory. The
           parent application is responsible for clearing and freeing this
           memory once it is done using the symmetric key.

    :param int*: A pointer that can be used to access the length of the
        symmetric key pointed to by the above double pointer.

    :return: A status code indicating success or failure of the operation. A
        negative status code indicates a libkmip error occurred while
        processing the request. A positive status code indicates a KMIP error
        occurred while the KMIP server processed the request. A status code
        of 0 indicates the operation succeeded.

        The following codes are returned explicitly by this function. If the
        code returned is negative and is not listed here, it is the result of
        the request encoding or response decoding process. See
        :ref:`status-codes` for all possible status code values.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``char *`` UUID pointer is set to ``NULL``
            * the ``int`` UUID size argument is set to a non-positive integer
            * the ``char **`` bytes double pointer is set to ``NULL``
            * the ``int *`` bytes size pointer is set to ``NULL``

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during the key retrieval call. This
            failure can occur during any of the following steps:

            * creation/resizing of the encoding buffer
            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during the key retrieval call. This
            failure can occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the default libkmip
            library context. Switching to the :ref:`mid-level-api` will
            allow the parent application to set the max message size in the
            library context directly.

        * ``KMIP_MALFORMED_RESPONSE``
            The received response message from the KMIP server is malformed
            and does not contain valid operation result information.

.. c:function:: int kmip_bio_destroy_symmetric_key(BIO *, char *, int)

    Destroy a symmetric key identified by a specific UUID.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to
        the KMIP server that stores the symmetric key.
    :param char*: A string containing the UUID of the symmetric key to destroy.
    :param int: The length of the above UUID string.

    :return: A status code indicating success or failure of the operation. A
        negative status code indicates a libkmip error occurred while
        processing the request. A positive status code indicates a KMIP error
        occurred while the KMIP server processed the request. A status code
        of 0 indicates the operation succeeded.

        The following codes are returned explicitly by this function. If the
        code returned is negative and is not listed here, it is the result of
        the request encoding or response decoding process. See
        :ref:`status-codes` for all possible status code values.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``char *`` UUID pointer is set to ``NULL``
            * the ``int`` UUID size argument is set to a non-positive integer

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during the key destruction call. This
            failure can occur during any of the following steps:

            * creation/resizing of the encoding buffer
            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during the key destruction call. This
            failure can occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the default libkmip
            library context. Switching to the :ref:`mid-level-api` will
            allow the parent application to set the max message size in the
            library context directly.

        * ``KMIP_MALFORMED_RESPONSE``
            The received response message from the KMIP server is malformed
            and does not contain valid operation result information.

.. _mid-level-api:

Mid-level API
~~~~~~~~~~~~~
The mid-level client API is similar to the high-level API except that it
allows the parent application to create and supply the library context to
each KMIP operation function. This allows the parent application to set the
KMIP message settings relevant to its own use case, including the KMIP version
to use for message encoding, the maximum message size to accept from the KMIP
server, and the list of credentials to use when sending a KMIP request
message. The application can also substitute its own memory management system
using the standard memory function hooks provided in the context.

Should an error occur during the request encoding or response decoding
process, error information, including an error message and a stack trace
detailing the function call path triggering the error, can be obtained from
the library context. For more information on the context, see
:ref:`the-libkmip-context`.

Using these functions, the library will automatically:

* create the request message structure
* encode the request message structure into a request encoding
* send the request encoding to the BIO-connected KMIP server
* receive the response encoding back from the BIO-connected KMIP server
* decode the response encoding into the response message structure
* extract the relevant output from the response message structure
* clean up the encoding buffers
* handle any errors that occur throughout the request/response process

The function header details for each of the mid-level API functions are
provided below.

.. c:function:: int kmip_bio_create_symmetric_key_with_context(KMIP *, BIO *, TemplateAttribute *, char **, int *)

    Create a symmetric key with the attributes provided in the
    ``TemplateAttribute`` structure.

    :param KMIP*: A libkmip ``KMIP`` structure containing the context
        information needed to encode and decode message structures.

        .. note::
           This structure should be properly destroyed by the parent
           application once it is done conducting KMIP operations. See
           :ref:`the-libkmip-context` and :ref:`context-functions` for more
           information.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to the
        KMIP server that will create the symmetric key.
    :param TemplateAttribute*: A libkmip :class:`TemplateAttribute` structure
        containing the attributes for the symmetric key (e.g., cryptographic
        algorithm, cryptographic length).
    :param char**: A double pointer that can be used to access the UUID of the
        newly created symmetric key.

        .. note::
           This pointer will point to a newly allocated block of memory. The
           parent application is responsible for clearing and freeing this
           memory once it is done using the UUID.

    :param int*: A pointer that can be used to access the length of the UUID
        string pointed to by the above double pointer.

    :return: A status code indicating success or failure of the operation. A
        negative status code indicates a libkmip error occurred while
        processing the request. A positive status code indicates a KMIP error
        occurred while the KMIP server processed the request. A status code
        of 0 indicates the operation succeeded.

        The following codes are returned explicitly by this function. If the
        code returned is negative and is not listed here, it is the result of
        the request encoding or response decoding process. See
        :ref:`status-codes` for all possible status code values.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the libkmip ``KMIP`` pointer is set to ``NULL``
            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``TemplateAttribute`` pointer is set to ``NULL``
            * the ``char **`` UUID double pointer is set to ``NULL``
            * the ``int *`` UUID size pointer is set to ``NULL``

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during the key creation call. This
            failure can occur during any of the following steps:

            * creation/resizing of the encoding buffer
            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during the key creation call. This
            failure can occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the provided libkmip
            library context.

        * ``KMIP_MALFORMED_RESPONSE``
            The received response message from the KMIP server is malformed
            and does not contain valid operation result information.

.. c:function:: int kmip_bio_get_symmetric_key_with_context(KMIP *, BIO *, char *, int, char **, int *)

    Retrieve a symmetric key identified by a specific UUID.

    :param KMIP*: A libkmip ``KMIP`` structure containing the context
        information needed to encode and decode message structures.

        .. note::
           This structure should be properly destroyed by the parent
           application once it is done conducting KMIP operations. See
           :ref:`the-libkmip-context` and :ref:`context-functions` for more
           information.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to
        the KMIP server that stores the symmetric key.
    :param char*: A string containing the UUID of the symmetric key to retrieve.
    :param int: The length of the above UUID string.
    :param char**: A double pointer that can be used to access the bytes of
        the retrieved symmetric key.

        .. note::
           This pointer will point to a newly allocated block of memory. The
           parent application is responsible for clearing and freeing this
           memory once it is done using the symmetric key.

    :param int*: A pointer that can be used to access the length of the
        symmetric key pointed to by the above double pointer.

    :return: A status code indicating success or failure of the operation. A
        negative status code indicates a libkmip error occurred while
        processing the request. A positive status code indicates a KMIP error
        occurred while the KMIP server processed the request. A status code
        of 0 indicates the operation succeeded.

        The following codes are returned explicitly by this function. If the
        code returned is negative and is not listed here, it is the result of
        the request encoding or response decoding process. See
        :ref:`status-codes` for all possible status code values.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the libkmip ``KMIP`` pointer is set to ``NULL``
            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``char *`` UUID pointer is set to ``NULL``
            * the ``int`` UUID size argument is set to a non-positive integer
            * the ``char **`` bytes double pointer is set to ``NULL``
            * the ``int *`` bytes size pointer is set to ``NULL``

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during the key retrieval call. This
            failure can occur during any of the following steps:

            * creation/resizing of the encoding buffer
            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during the key retrieval call. This
            failure can occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the provided libkmip
            library context.

        * ``KMIP_MALFORMED_RESPONSE``
            The received response message from the KMIP server is malformed
            and does not contain valid operation result information.

.. c:function:: int kmip_bio_destroy_symmetric_key_with_context(KMIP *, BIO *, char *, int)

    Destroy a symmetric key identified by a specific UUID.

    :param KMIP*: A libkmip ``KMIP`` structure containing the context
        information needed to encode and decode message structures.

        .. note::
           This structure should be properly destroyed by the parent
           application once it is done conducting KMIP operations. See
           :ref:`the-libkmip-context` and :ref:`context-functions` for more
           information.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to
        the KMIP server that stores the KMIP managed object.
    :param char*: A string containing the UUID of the KMIP managed object to
        destroy.
    :param int: The length of the above UUID string.

    :return: A status code indicating success or failure of the operation. A
        negative status code indicates a libkmip error occurred while
        processing the request. A positive status code indicates a KMIP error
        occurred while the KMIP server processed the request. A status code
        of 0 indicates the operation succeeded.

        The following codes are returned explicitly by this function. If the
        code returned is negative and is not listed here, it is the result of
        the request encoding or response decoding process. See
        :ref:`status-codes` for all possible status code values.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the libkmip ``KMIP`` pointer is set to ``NULL``
            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``char *`` UUID pointer is set to ``NULL``
            * the ``int`` UUID size argument is set to a non-positive integer

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during the key destruction call. This
            failure can occur during any of the following steps:

            * creation/resizing of the encoding buffer
            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during the key destruction call. This
            failure can occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the provided libkmip
            library context.

        * ``KMIP_MALFORMED_RESPONSE``
            The received response message from the KMIP server is malformed
            and does not contain valid operation result information.

.. _low-level-api:

Low-level API
~~~~~~~~~~~~~
The low-level client API differs from the mid and high-level APIs. It provides
a single function that is used to send and receive encoded KMIP messages. The
request message structure construction and encoding, along with the response
message structure decoding, is left up to the parent application. This provides
the parent application complete control over KMIP message processing.

Using this function, the library will automatically:

* send the request encoding to the BIO-connected KMIP server
* receive the response encoding back from the BIO-connected KMIP server
* handle any errors that occur throughout the send/receive process

The function header details for the low-level API function is provided below.

.. c:function:: int kmip_bio_send_request_encoding(KMIP *, BIO *, char *, int, char **, int *)

    Send a KMIP encoded request message to the KMIP server.

    :param KMIP*: A libkmip ``KMIP`` structure containing the context
        information needed to encode and decode message structures. Primarily
        used here to control the maximum response message size.

        .. note::
           This structure should be properly destroyed by the parent
           application once it is done conducting KMIP operations. See
           :ref:`the-libkmip-context` and :ref:`context-functions` for more
           information.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to
        the KMIP server.
    :param char*: A string containing the KMIP encoded request message bytes.
    :param int: The length of the above encoded request message.
    :param char**: A double pointer that can be used to access the bytes of
        the received KMIP encoded response message.

        .. note::
           This pointer will point to a newly allocated block of memory. The
           parent application is responsible for clearing and freeing this
           memory once it is done processing the encoded response message.

    :param int*: A pointer that can be used to access the length of the
        encoded response message pointed to by the above double pointer.

    :return: A status code indicating success or failure of the operation. A
        negative status code indicates a libkmip error occurred while
        processing the request. A positive status code indicates a KMIP error
        occurred while the KMIP server processed the operation. A status code
        of 0 indicates the operation succeeded. The following codes are
        returned explicitly by this function.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the libkmip ``KMIP`` pointer is set to ``NULL``
            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``char *`` encoded request message bytes pointer is set to
              ``NULL``
            * the ``int`` encoded request message bytes size argument is set
              to a non-positive integer
            * the ``char **`` encoded response message bytes double pointer is
              set to ``NULL``
            * the ``int *`` encoded response message bytes size pointer is set
              to ``NULL``

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during message handling. This failure can
            occur during the following step:

            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during message handling. This failure can
            occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the provided libkmip
            library context.

.. _status-codes:

Status Codes
~~~~~~~~~~~~
The following tables list the status codes that can be returned by the client
API functions. The first table lists the status codes related to the
functioning of libkmip.

============================  =====
Status Code                   Value
============================  =====
KMIP_OK                       0
KMIP_NOT_IMPLEMENTED          -1
KMIP_ERROR_BUFFER_FULL        -2
KMIP_ERROR_ATTR_UNSUPPORTED   -3
KMIP_TAG_MISMATCH             -4
KMIP_TYPE_MISMATCH            -5
KMIP_LENGTH_MISMATCH          -6
KMIP_PADDING_MISMATCH         -7
KMIP_BOOLEAN_MISMATCH         -8
KMIP_ENUM_MISMATCH            -9
KMIP_ENUM_UNSUPPORTED         -10
KMIP_INVALID_FOR_VERSION      -11
KMIP_MEMORY_ALLOC_FAILED      -12
KMIP_IO_FAILURE               -13
KMIP_EXCEED_MAX_MESSAGE_SIZE  -14
KMIP_MALFORMED_RESPONSE       -15
KMIP_OBJECT_MISMATCH          -16
============================  =====

The second table lists the operation result status codes that can be returned
by a KMIP server as the result of a successful or unsuccessful operation.

=============================  =====
Status Code                    Value
=============================  =====
KMIP_STATUS_SUCCESS            0
KMIP_STATUS_OPERATION_FAILED   1
KMIP_STATUS_OPERATION_PENDING  2
KMIP_STATUS_OPERATION_UNDONE   3
=============================  =====

.. _encoding-api:

Encoding API
------------
The libkmip Encoding API supports encoding and decoding a variety of message
structures and substructures to and from the KMIP TTLV encoding format. The
:ref:`client-api` functions use the resulting encoded messages to communicate
KMIP operation instructions to the KMIP server. While each substructure
contained in a request or response message structure has its own corresponding
set of encoding and decoding functions, parent applications using libkmip
should only need to use the encoding and decoding functions for request and
response messages respectively.

The following function signatures define the encoding API and can be found in
``kmip.h``:

.. code-block:: c

   int kmip_encode_request_message(KMIP *, const RequestMessage *);
   int kmip_decode_response_message(KMIP *, ResponseMessage *);

The function header details for each of the encoding API functions are
provided below.

.. c:function:: int kmip_encode_request_message(KMIP *, const RequestMessage *)

    Encode the request message and store the encoding in the library context.

    :param KMIP*: A libkmip ``KMIP`` structure containing the context
        information needed to encode and decode message structures.
    :param RequestMessage*: A libkmip ``RequestMessage`` structure containing
        the request message information that will be encoded. The structure
        will not be modified during the encoding process.

    :return: A status code indicating success or failure of the encoding
        process. See :ref:`status-codes` for all possible status code values.
        If ``KMIP_OK`` is returned, the encoding succeeded.

.. c:function:: int kmip_decode_response_message(KMIP *, ResponseMessage *)

    Decode the encoding in the library context into the response message.

    :param KMIP*: A libkmip ``KMIP`` structure containing the context
        information needed to encode and decode message structures.
    :param ResponseMessage*: A libkmip ``ResponseMessage`` structure
        that will be filled out by the decoding process.

        .. note::
           This structure will contain pointers to newly allocated
           substructures created during the decoding process. The calling
           function is responsible for clearing and freeing these
           substructures once it is done processing the response message.
           See (ref here) for more information.

        .. warning::
           Any attributes set in the structure before it is passed in to this
           decoding function will be overwritten and lost during the decoding
           process. Best practice is to pass in a pointer to a freshly
           initialized, empty structure to ensure this does not cause
           application errors.

    :return: A status code indicating success or failure of the decoding
        process. See :ref:`status-codes` for all possible status code values.
        If ``KMIP_OK`` is returned, the decoding succeeded.

.. _utilities-api:

Utilities API
-------------
The libkmip Utilities API supports a wide variety of helper functions and
structures that are used throughout libkmip, ranging from the core library
context structure that is used for all encoding and decoding operations to
structure initializers, deallocators, and debugging aides.

.. warning::
   Additional capabilities are included in libkmip that may not be discussed
   here. These capabilities are generally for internal library use only and
   are subject to change in any release. Parent applications that use these
   undocumented features should not expect API stability.

.. _the-libkmip-context:

The libkmip Context
~~~~~~~~~~~~~~~~~~~
The libkmip library context is a structure that contains all of the settings
and controls needed to create KMIP message encodings. It is defined in
``kmip.h``:

.. code-block:: c

   typedef struct kmip
   {
       /* Encoding buffer */
       uint8 *buffer;
       uint8 *index;
       size_t size;

       /* KMIP message settings */
       enum kmip_version version;
       int max_message_size;
       LinkedList *credentials;

       /* Error handling information */
       char *error_message;
       size_t error_message_size;
       LinkedList *error_frames;

       /* Memory management function pointers */
       void *(*calloc_func)(void *state, size_t num, size_t size);
       void *(*realloc_func)(void *state, void *ptr, size_t size);
       void  (*free_func)(void *state, void *ptr);
       void *(*memset_func)(void *ptr, int value, size_t size);
       void *state;
   } KMIP;

The structure includes the encoding/decoding buffer, KMIP message settings,
error information, and memory management hooks.

The Encoding/Decoding Buffer
````````````````````````````
The library context contains a pointer to the main target buffer, ``buffer``,
used for both encoding and decoding KMIP messages. This buffer should only
be set and accessed using the defined context utility functions defined below.
It should never be accessed or manipulated directly.

KMIP Message Settings
`````````````````````
The library context contains several attributes that are used throughout the
encoding and decoding process.

The ``version`` enum attribute is used to control what KMIP structures are
included in operation request and response messages. It should be set by the
parent application to the desired KMIP version:

.. code-block:: c

   enum kmip_version
   {
       KMIP_1_0 = 0,
       KMIP_1_1 = 1,
       KMIP_1_2 = 2,
       KMIP_1_3 = 3,
       KMIP_1_4 = 4
   };

The ``max_message_size`` attribute defines the maximum size allowed for
incoming response messages. Since KMIP message encodings define the total size
of the message at the beginning of the encoding, it is important for the 
parent application to set this attribute to a reasonable default suitable for
its operation.

The ``credentials`` list is intended to store a set of authentication
credentials that should be included in any request message created with the
library context. This is primarily intended for use with the
:ref:`mid-level-api`.

Each of these attributes will be set to reasonable defaults by the
``kmip_init`` context utility and can be overridden as needed.

Error Information
`````````````````
The library context contains several attributes that are used to track and
store error information. These are only used when errors occur during the
encoding or decoding process. Once an error is detected, a libkmip stack
trace will be constructed, with each frame in the stack containing the
function name and source line number where the error occurred to facilitate
debugging.

.. code-block:: c

   typedef struct error_frame
   {
       char *function;
       int line;
   } ErrorFrame;

The original error message will be captured in the ``error_message``
attribute for use in logging or user-facing status messages.

See the context functions below for using and accessing this error
information.

Memory Management
`````````````````
The library context contains several function pointers that can be used to
wrap or substitute common memory management utilities. All memory management
done by libkmip is done through these function pointers, allowing the calling
application to easily substitute its own memory management system. Note
specifically the ``void *state`` attribute in the library context; it is
intended to contain a reference to the parent application's custom memory
management system, if one exists. This attribute is passed to every call made
through the context's memory management hooks, allowing the parent application
complete control of the memory allocation process. By default, the ``state``
attribute is ignored in the default memory management hooks. The ``kmip_init``
utility function will automatically set these hooks to the default memory
management functions if any of them are unset.

.. _context-functions:

Utility Functions
~~~~~~~~~~~~~~~~~
The following function signatures define the Utilities API and can be found
in ``kmip.h``:

.. code-block:: c

   /* Library context utilities */
   void kmip_clear_errors(KMIP *);
   void kmip_init(KMIP *, void *, size_t, enum kmip_version);
   void kmip_init_error_message(KMIP *);
   int  kmip_add_credential(KMIP *, Credential *);
   void kmip_remove_credentials(KMIP *);
   void kmip_reset(KMIP *);
   void kmip_rewind(KMIP *);
   void kmip_set_buffer(KMIP *, void *, size_t);
   void kmip_destroy(KMIP *);
   void kmip_push_error_frame(KMIP *, const char *, const int);

   /* Message structure initializers */
   void kmip_init_protocol_version(ProtocolVersion *, enum kmip_version);
   void kmip_init_attribute(Attribute *);
   void kmip_init_request_header(RequestHeader *);
   void kmip_init_response_header(ResponseHeader *);

   /* Message structure deallocators */
   void kmip_free_request_message(KMIP *, RequestMessage *);
   void kmip_free_response_message(KMIP *, ResponseMessage *);

   /* Message structure debugging utilities */
   void kmip_print_request_message(RequestMessage *);
   void kmip_print_response_message(ResponseMessage *);

Library Context Utilities
`````````````````````````
The libkmip context contains various fields and attributes used in various
ways throughout the encoding and decoding process. In general, the context
fields should not be modified directly. All modifications should be done
using one of the context utility functions described below.

The function header details for each of the relevant context utility functions
are provided below.

.. c:function:: void kmip_init(KMIP *, void *, size_t, enum kmip_version)

    Initialize the ``KMIP`` context.

    This function initializes the different fields and attributes used by the
    context to encode and decode KMIP messages. Reasonable defaults are chosen
    for certain fields, like the maximum message size and the error message
    size. If any of the memory allocation function hooks are ``NULL``, they
    will be set to system defaults.

    :param KMIP*: The libkmip ``KMIP`` context to be initialized. If ``NULL``,
        the function does nothing and returns.
    :param void*: A ``void`` pointer to a buffer to be used for encoding and
        decoding KMIP messages. If setting up the context for use with the
        :ref:`mid-level-api` it is fine to use ``NULL`` here.
    :param size_t: The size of the above buffer. If setting up the context for
        use with the :ref:`mid-level-api` it is fine to use 0 here.
    :param enum kmip_version: A KMIP version enumeration that will be used by
        the context to decide how to encode and decode messages.

    :return: None

.. c:function:: void kmip_clear_errors(KMIP *)

    Clean up any error-related information stored in the ``KMIP`` context.

    This function clears and frees any error-related information or structures
    contained in the context, should any exist. It is intended to be used
    between encoding or decoding operations so that repeated use of the
    context is possible without causing errors. It is often used by other
    context handling utilities. See the utility source code for more details.

    :param KMIP*: The libkmip ``KMIP`` context containing error-related
        information to be cleared.

    :return: None

.. c:function:: void kmip_init_error_message(KMIP *)

    Initialize the error message field of the ``KMIP`` context.

    This function allocates memory required to store the error message string
    in the library context. If an error message string already exists, nothing
    is done. Primarily used internally by other utility functions.

    :param KMIP*: The libkmip ``KMIP`` context whose error message memory
        should be allocated.

    :return: None

.. c:function:: int kmip_add_credential(KMIP *, Credential *)

    Add a ``Credential`` structure to the list of credentials used by the
    ``KMIP`` context.

    This function dynamically adds a node to the ``LinkedList`` of
    ``Credential`` structures stored by the context. These credentials are
    used automatically by the :ref:`mid-level-api` when creating KMIP
    operation requests.

    :param KMIP*: The libkmip ``KMIP`` context to add a credential to.
    :param Credential*: The libkmip ``Credential`` structure to add to the
        list of credentials stored by the context.

    :return: A status code indicating if the credential was added to the
        context. The code will be one of the following:

        * ``KMIP_OK``
            The credential was added successfully.
        * ``KMIP_UNSET``
            The credential was not added successfully.

.. c:function:: void kmip_remove_credentials(KMIP *)

    Remove all ``Credential`` structures stored by the ``KMIP`` context.

    This function clears and frees all of the ``LinkedList`` nodes used to
    store the ``Credential`` structures associated with the context.

    .. note:: 
        If the underlying ``Credential`` structures were themselves
        dynamically allocatted, they must be freed separately by the parent
        application.

    :param KMIP*: The libkmip ``KMIP`` context containing credentials to
        be removed.

    :return: None

.. c:function:: void kmip_reset(KMIP *)

    Reset the ``KMIP`` context buffer so that encoding can be reattempted.

    This function resets the context buffer to its initial empty starting
    state, allowing the context to be used for another encoding attempt if
    the prior attempt failed. The buffer will be overwritten with zeros to
    ensure that no information leaks across encoding attempts. This function
    also calls ``kmip_clear_errors`` to clear out any error information that
    was generated by the encoding failure.

    :param KMIP*: The libkmip ``KMIP`` context that contains the buffer
        needing to be reset.

    :return: None

.. c:function:: void kmip_rewind(KMIP *)

    Rewind the ``KMIP`` context buffer so that decoding can be reattempted.

    This function rewinds the context buffer to its initial starting state,
    allowing the context to be used for another decoding attempt if the
    prior attempt failed. This function also calls ``kmip_clear_errors`` to
    clear out any error information that was generated by the decoding
    failure.

    :param KMIP*: The libkmip ``KMIP`` context that contains the buffer
        needing to be rewound.

    :return: None

.. c:function:: void kmip_set_buffer(KMIP *, void *, size_t)

    Set the encoding buffer used by the ``KMIP`` context.

    :param KMIP*: The libkmip ``KMIP`` context that will contain the buffer.
    :param void*: A ``void`` pointer to a buffer to be used for encoding and
        decoding KMIP messages.
    :param size_t: The size of the above buffer.

    :return: None

.. c:function:: void kmip_destroy(KMIP *)

    Deallocate the content of the ``KMIP`` context.

    This function resets and deallocates all of the fields contained in the
    context. It calls ``kmip_reset`` and ``kmip_set_buffer`` to clear the
    buffer and overwrite any leftover pointers to it. It calls
    ``kmip_clear_credentials`` to clear out any referenced credential
    information. It also unsets all of the memory allocation function hooks.

    .. note::
       The buffer memory itself will not be deallocated by this function, nor
       will any of the ``Credential`` structures if they are dynamically
       allocatted. The parent application is responsible for clearing and
       deallocating those segments of memory.

.. c:function:: void kmip_push_error_frame(KMIP *, const char *, const int)

    Add an error frame to the stack trace contained in the ``KMIP`` context.

    This function dynamically adds a new error frame to the context stack
    trace, using the information provided to record where an error occurred.

    :param KMIP*: The libkmip ``KMIP`` context containing the stack trace.
    :param char*: The string containing the function name for the new
        stack trace error frame.
    :param int: The line number for the new stack trace error frame.

    :return: None

Message Structure Initializers
``````````````````````````````
There are many different KMIP message structures and substructures that are
defined and supported by libkmip. In general, the parent application should
zero initialize any libkmip structures before using them, like so:

.. code-block:: c

   RequestMessage message = {0};

In most cases, optional fields in KMIP substructures are excluded from the
encoding process when set to 0. However, in some cases 0 is a valid value
for a specific optional field. In these cases, we set these values to
``KMIP_UNSET``. The parent application should never need to worry about
manually initialize these types of fields. Instead, the following initializer
functions should be used for the associated structures to handle properly
setting default field values.

The function header details for each of the relevant initializer functions
are provided below.

.. c:function:: void kmip_init_protocol_version(ProtocolVersion *, enum kmip_version)

    Initialize a ``ProtocolVersion`` structure with a KMIP version
    enumeration.

    :param ProtocolVersion*: A libkmip ``ProtocolVersion`` structure to be
        initialized.
    :param enum kmip_version: A KMIP version enumeration whose value will be
        used to initialize the ProtocolVersion structure.

    :return: None

.. c:function:: void kmip_init_attribute(Attribute *)

    Initialize an ``Attribute`` structure.

    :param Attribute*: A libkmip ``Attribute`` structure to be initialized.

    :return: None

.. c:function:: void kmip_init_request_header(RequestHeader *)

    Initialize a ``RequestHeader`` structure.

    :param RequestHeader*: A libkmip ``RequestHeader`` structure to be
        initialized.

    :return: None

.. c:function:: void kmip_init_response_header(ResponseHeader *)

    Initialize a ``ResponseHeader`` structure.

    :param ResponseHeader*: A libkmip ``ResponseHeader`` structure to be
        initialized.

    :return: None

Message Structure Deallocators
``````````````````````````````
Along with structure initializers, there are corresponding structure
deallocators for every supported KMIP structure. The deallocator behaves
like the initializer; it takes in a pointer to a specific libkmip structure
and will set all structure fields to safe, initial defaults. If a structure
field is a non ``NULL`` pointer, the deallocator will attempt to clear and
free the associated memory.

.. note::
   A deallocator will not free the actual structure passed to it. It will
   only attempt to free memory referenced by the structure fields. The parent
   application is responsible for freeing the structure memory if it was
   dynamically allocated and should set any pointers to the structure to
   ``NULL`` once it is done with the structure.

Given how deallocators handle memory, they should only ever be used on
structures that are created from the decoding process (i.e., structures
created on the heap). The decoding process dynamically allocates memory to
build out the message structure in the target encoding and it is beyond the
capabilities of the client API or the parent application to manually free
all of this memory directly.

.. warning::
   If you use a deallocator on a structure allocated fully or in part on the
   stack, the deallocator will attempt to free stack memory and will trigger
   undefined behavior. This can lead to program instability and may cause
   the application to crash.

While there are deallocators for every supported structure, parent
applications should only need to use the deallocators for request and response
messages. Given these are the root KMIP structures, using these will free
all associated substructures used to represent the message.

The function header details for each of the deallocator functions are provided
below.

.. c:function:: void kmip_free_request_message(KMIP *, RequestMessage *)

    Deallocate the content of a ``RequestMessage`` structure.

    :param KMIP*: A libkmip ``KMIP`` structure containing the context
        information needed to encode and decode message structures. Primarily
        used here for memory handlers.
    :param RequestMessage*: A libkmip ``RequestMessage`` structure whose
        content should be reset and/or freed.

    :return: None

.. c:function:: void kmip_free_response_message(KMIP *, ResponseMessage *)

    Deallocate the content of a ``ResponseMessage`` structure.

    :param KMIP*: A libkmip ``KMIP`` structure containing the context
        information needed to encode and decode message structures. Primarily
        used here for memory handlers.
    :param ResponseMessage*: A libkmip ``ResponseMessage`` structure whose
        content should be reset and/or freed.

    :return: None

Message Structure Debugging Utilities
`````````````````````````````````````
If the parent application is using the :ref:`low-level-api`, it will have
access to the ``RequestMessage`` and ``ResponseMessage`` structures used to
generate the KMIP operation encodings. These structures can be used with
basic printing utilities to display the content of these structures in an
easy to view and debug format.

The function header details for each of the printing utilities are provided
below.

.. c:function:: void kmip_print_request_message(RequestMessage *)

    Print the contents of a ``RequestMessage`` structure.

    :param RequestMessage*: A libkmip ``RequestMessage`` structure to be
        displayed.

    :return: None

.. c:function:: void kmip_print_response_message(ResponseMessage *)

    Print the contents of a ``ResponseMessage`` structure.

    :param ResponseMessage*: A libkmip ``ResponseMessage`` structure to be
        displayed.

    :return: None

.. _`OpenSSL BIO library`: https://www.openssl.org/docs/man1.1.0/crypto/bio.html