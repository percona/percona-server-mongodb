# libkmip

libkmip is an ISO C11 implementation of the Key Management Interoperability
Protocol (KMIP), an [OASIS][oasis] communication standard for the management
of objects stored and maintained by key management systems. KMIP defines how
key management operations and operation data should be encoded and
communicated, between client and server applications. Supported operations
include creating, retrieving, and destroying keys. Supported object types
include:

* symmetric and asymmetric encryption keys

For more information on KMIP, check out the
[OASIS KMIP Technical Committee][kmip] and the
[OASIS KMIP Documentation][spec].

For more information on libkmip, check out the project [Documentation][docs].

## Installation

You can install libkmip from source using `make`:

```
$ cd libkmip
$ make
$ make install
```

See [Installation][install] for more information.

[docs]: https://libkmip.readthedocs.io/en/latest/index.html
[install]: https://libkmip.readthedocs.io/en/latest/installation.html
[kmip]: https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip
[oasis]: https://www.oasis-open.org
[spec]: https://docs.oasis-open.org/kmip/spec
