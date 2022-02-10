Development
===========
Development for libkmip is open to all contributors. Use the information
provided here to inform your contributions and help the project maintainers
review and accept your work.

Getting Started
---------------
File a new issue on the project `issue tracker`_ on GitHub describing the
work you intend on doing. This is especially recommended for any sizable
contributions, like adding support for a new KMIP operation or object type.
Provide as much information on your feature request as possible, using
information from the KMIP specifications or existing feature support in
libkmip where applicable.

The issue number for your new issue should be included at the end of the
commit message of each patch related to that issue.

If you simply want to request a new feature but do not intend on working on
it, file your issue as normal and the project maintainers will triage it for
future work.

.. _writing-code:

Writing Code
------------
New code should be written in its own ``git`` branch, ideally branched from
``HEAD`` on ``master``. If other commits are merged into ``master`` after your
branch was created, be sure to rebase your work on the current state of
``master`` before submitting a pull request to GitHub.

New code should generally follow the style used in the surrounding libkmip
codebase.

.. _writing-docs:

Writing Documentation
---------------------
Like new code, new documentation should be written in its own ``git`` branch.
All libkmip documentation is written in `RST`_ format and managed using
``sphinx``. It can be found under ``docs/source``.

If you are interested in contributing to the project documentation, install
the project documentation requirements:

.. code:: console

    $ pip install -r doc-requirements.txt

To build the documentation, navigate into the ``docs`` directory and run:

.. code:: console

    $ make html

This will build the libkmip documentation as HTML and place it under the new
``docs/build/html`` directory. View it using your preferred web browser.

Commit Messages
---------------
Commit messages should include a single line title (75 characters max) followed
by a blank line and a description of the change, including feature details,
testing and documentation updates, feature limitations, known issues, etc.

The issue number for the issue associated with the commit should be included
at the end of the commit message, if it exists. If the commit is the final one
for a specific issue, use ``Closes #XXX`` or ``Fixes #XXX`` to link the issue
and close it simultaneously.

Bug Fixes
---------
If you have found a bug in libkmip, file a new issue and use the title format
``Bug: <brief description here>``. In the body of the issue please provide as
much information as you can, including platform, compiler version, dependency
version, and any stacktraces or error information produced by libkmip related
to the bug. See `What to put in your bug report`_ for a breakdown of bug
reporting best practices.

If you are working on a bug fix for a bug in ``master``, follow the general
guidelines above for branching and code development (see :ref:`writing-code`).

If you are working on a bug fix for an older version of libkmip, your branch
should be based on the latest commit of the repository branch for the version
of libkmip the bug applies to (e.g., branch ``release-0.1.0`` for libkmip 0.1).
The pull request for your bug fix should also target the version branch in
question. If appliable, it will be pulled forward to newer versions of libkmip,
up to and including ``master``.

.. running-tests:

Running Tests
-------------
libkmip comes with its own testing application that primarily covers the
encoding/decoding functionality of the library. It is built with the default
``make`` target and can be run locally by invoking the ``tests`` binary:

.. code-block:: console

    $ cd libkmip
    $ make
    $ ./tests

.. _`issue tracker`: https://github.com/openkmip/libkmip/issues
.. _`RST`: http://docutils.sourceforge.net/rst.html
.. _`What to put in your bug report`: http://www.contribution-guide.org/#What-to-put-in-your-bug-report
