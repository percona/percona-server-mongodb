Security
========
The security of libkmip is the top priority for the project. Use the
information provided below to inform your security posture.

Handling Sensitive Data
-----------------------
Given that libkmip is an ISO C11 implementation of a key management protocol,
the most sensitive aspect of the library is its handling of memory containing
cryptographic material. All memory allocation and deallocation routines
explicitly zero memory to prevent inadvertent leaks of sensitive data. This
approach relies on the use of the standard ``memset_s`` function
(see `memset_s`_) included in C11 Annex K. If ``memset_s`` is unavailable at
build time, memory clearing is done through a volatile function pointer to
prevent the optimizer from optimizing away the clearing operation.

.. warning::
   Despite the precautions taken here, it is possible that your build system
   will still optimize away the memory clearing operation. If this occurs,
   sensitive cryptographic material will be left behind in memory during and
   after application execution. Examine your application binary directly to
   determine if this is true for your setup.

Other security concerns, such as locking memory pages, are left up to the
parent application and are not the domain of libkmip.

Reporting a Security Issue
--------------------------
Please do not report security issues to the normal GitHub project issue
tracker. Contact the project maintainers directly via email to report
and discuss security issues.

When reporting a security issue, please include as much detail as possible.
This includes a high-level description of the issue, information on how to
cause or reproduce the issue, and any details on specific portions of the
project code base related to the issue.

Once you have submitted an issue, you should receive an acknowledgement.
Depending upon the severity of the issue, the project maintainers will
respond to collect additional information and work with you to address the
security issue. If applicable, a new library subrelease will be produced
across all actively supported releases to address and fix the issue.

.. _`memset_s`: https://en.cppreference.com/w/c/string/byte/memset