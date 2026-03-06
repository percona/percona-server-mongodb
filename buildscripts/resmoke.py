#!/usr/bin/env python3
"""Command line utility for executing MongoDB tests of all kinds."""

import os.path
import sys

# Get relative imports to work when the package is not installed on the PYTHONPATH.
if __name__ == "__main__" and __package__ is None:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from buildscripts.resmokelib import cli
except Exception as ex:
    if not os.getenv("VIRTUAL_ENV") and not os.getenv("BUILD_WORKSPACE_DIRECTORY"):
        venv_not_activated = "You need to activate your virtual environment"
        # Python versions >= 3.11 support an add_note() function on exceptions so this
        # message shows up _after_ the stack trace (more likely to be seen by a dev)
        if sys.version_info.major == 3 and sys.version_info.minor >= 11:
            ex.add_note(venv_not_activated)
        else:
            print(venv_not_activated)
    raise


# Entrypoint
def entrypoint():
    cli.main(sys.argv)


if __name__ == "__main__":
    entrypoint()
