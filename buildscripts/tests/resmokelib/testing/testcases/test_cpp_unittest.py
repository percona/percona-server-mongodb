"""Tests for building the runfiles tree of C++ unit tests from the Bazel manifest."""

import logging
import os
import tempfile
import unittest
from pathlib import Path

from buildscripts.resmokelib.testing.testcases import cpp_unittest


class TestRunfilesFromManifest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.bin_dir = self.root / "bazel-bin"
        self.bin_dir.mkdir()
        self.binary = self.bin_dir / "some_test"
        self.binary.touch()
        self.runfiles = self.bin_dir / "some_test.runfiles"
        self.manifest = self.bin_dir / "some_test.runfiles_manifest"

    def _write_manifest(self, *names):
        lines = []
        for name in names:
            src = self.root / name
            src.touch()
            lines.append(f"_main/data/{name} {src}\n")
        self.manifest.write_text("".join(lines))

    def _make_testcase(self):
        return cpp_unittest.CPPUnitTestCase(logging.getLogger(self.id()), [str(self.binary)])

    def test_creates_tree_when_missing(self):
        self._write_manifest("a.so")
        tc = self._make_testcase()
        self.assertTrue((self.runfiles / "_main/data/a.so").is_symlink())
        self.assertEqual(tc.program_options["env_vars"]["RUNFILES_DIR"], str(self.runfiles))

    def test_rebuilds_stale_tree_when_manifest_is_newer(self):
        self._write_manifest("a.so")
        self._make_testcase()
        old = os.path.getmtime(self.runfiles) - 100
        os.utime(self.runfiles, (old, old))

        self._write_manifest("a.so", "b.so")
        self._make_testcase()
        self.assertTrue((self.runfiles / "_main/data/b.so").is_symlink())

    def test_keeps_tree_when_up_to_date(self):
        self._write_manifest("a.so")
        self._make_testcase()
        marker = self.runfiles / "marker"
        marker.touch()
        os.utime(self.runfiles, (os.path.getmtime(self.manifest) + 100,) * 2)

        self._make_testcase()
        self.assertTrue(marker.exists())


if __name__ == "__main__":
    unittest.main()
