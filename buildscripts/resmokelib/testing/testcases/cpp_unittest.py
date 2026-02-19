"""The unittest.TestCase for C++ unit tests."""

import os
from typing import Optional

from buildscripts.resmokelib import core, logging, utils
from buildscripts.resmokelib.testing.testcases import interface


class CPPUnitTestCase(interface.ProcessTestCase):
    """A C++ unit test to execute."""

    REGISTERED_NAME = "cpp_unit_test"

    def __init__(
        self,
        logger: logging.Logger,
        program_executables: list[str],
        program_options: Optional[dict] = None,
    ):
        """Initialize the CPPUnitTestCase with the executable to run."""

        assert len(program_executables) == 1
        interface.ProcessTestCase.__init__(self, logger, "C++ unit test", program_executables[0])

        self.program_executable = program_executables[0]
        self.program_options = utils.default_if_none(program_options, {}).copy()

        interface.append_process_tracking_options(self.program_options, self._id)

        # Automatically set RUNFILES_DIR for Bazel tests if not already set
        self._set_runfiles_dir_if_needed()

    def _set_runfiles_dir_if_needed(self):
        """Set RUNFILES_DIR environment variable for Bazel tests if needed."""
        # Check if RUNFILES_DIR is already set in program_options
        env_vars = self.program_options.get("env_vars", {})
        if "RUNFILES_DIR" in env_vars:
            return  # Already set, don't override

        # Check if this looks like a Bazel binary (in bazel-bin directory)
        executable_path = os.path.abspath(self.program_executable)
        if "bazel-bin" not in os.path.normpath(executable_path).split(os.sep):
            return  # Not a Bazel binary, skip

        # Check if executable path is a symlink and resolve it into resolved_path
        resolved_path = executable_path
        if os.path.islink(executable_path):
            resolved_path = os.path.realpath(executable_path)

        # Check if .runfiles directory exists next to the binary but take binary name from the symlink name
        # Take base dir from resolved_path
        base_dir = os.path.dirname(resolved_path)
        # Take binary name from executable_path
        binary_name = os.path.basename(executable_path)

        runfiles_dir = os.path.join(base_dir, binary_name + ".runfiles")
        if not os.path.isdir(runfiles_dir):
            # Runfiles directory doesn't exist (e.g. built with --nobuild_runfile_links).
            # Try to create it from the manifest file that Bazel still produces.
            manifest_file = runfiles_dir + "_manifest"
            if os.path.isfile(manifest_file):
                self._create_runfiles_from_manifest(runfiles_dir, manifest_file)

        if os.path.isdir(runfiles_dir):
            # Set RUNFILES_DIR in env_vars
            if "env_vars" not in self.program_options:
                self.program_options["env_vars"] = {}
            self.program_options["env_vars"]["RUNFILES_DIR"] = runfiles_dir
            self.logger.debug(
                "Automatically set RUNFILES_DIR=%s for Bazel test %s",
                runfiles_dir,
                executable_path,
            )

    def _create_runfiles_from_manifest(self, runfiles_dir, manifest_file):
        """Create a runfiles symlink tree from a Bazel runfiles manifest.

        Bazel produces a <binary>.runfiles_manifest even when --nobuild_runfile_links
        is set. Each line of the manifest has the form:
            <runfile-relative-path> <absolute-source-path>
        This method creates the corresponding directory tree under runfiles_dir
        using symlinks so that the test binary can find its data dependencies.
        """
        self.logger.debug(
            "Creating runfiles directory %s from manifest %s", runfiles_dir, manifest_file
        )
        try:
            os.makedirs(runfiles_dir, exist_ok=True)
            with open(manifest_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    parts = line.split(" ", 1)
                    if len(parts) != 2:
                        continue
                    rel_path, src_path = parts
                    if not src_path:
                        continue
                    dest_path = os.path.join(runfiles_dir, rel_path)
                    dest_dir = os.path.dirname(dest_path)
                    os.makedirs(dest_dir, exist_ok=True)
                    if os.path.lexists(dest_path):
                        continue
                    try:
                        os.symlink(src_path, dest_path)
                    except OSError as e:
                        self.logger.error(
                            "Failed to create runfiles symlink %s -> %s: %s",
                            dest_path,
                            src_path,
                            e,
                        )
        except OSError as e:
            self.logger.error("Failed to create runfiles directory %s: %s", runfiles_dir, e)

    def _make_process(self):
        return core.programs.make_process(
            self.logger,
            [self.program_executable, "--enhancedReporter=false"],
            **self.program_options,
        )
