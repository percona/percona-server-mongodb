"""Tests for OWNERS auto-approver generation behavior."""

import importlib.util
import os
import sys
import types
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

CODEOWNERS_ROOT = Path(__file__).resolve().parents[1] / "bazel_rules_mongo" / "codeowners"
PARSERS_ROOT = CODEOWNERS_ROOT / "parsers"


def _load_module(module_name: str, module_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load module spec for {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


codeowners_package = types.ModuleType("codeowners")
parsers_package = types.ModuleType("codeowners.parsers")
sys.modules.setdefault("codeowners", codeowners_package)
sys.modules.setdefault("codeowners.parsers", parsers_package)

owners_v1_module = _load_module("codeowners.parsers.owners_v1", PARSERS_ROOT / "owners_v1.py")
sys.modules["codeowners.parsers.owners_v1"] = owners_v1_module
OwnersParserV1 = owners_v1_module.OwnersParserV1

owners_v2_module = _load_module("codeowners.parsers.owners_v2", PARSERS_ROOT / "owners_v2.py")
sys.modules["codeowners.parsers.owners_v2"] = owners_v2_module
OwnersParserV2 = owners_v2_module.OwnersParserV2


class _TestOwnersParserV1(OwnersParserV1):
    def test_pattern(self, pattern: str) -> bool:
        return True


class _TestOwnersParserV2(OwnersParserV2):
    def test_pattern(self, pattern: str) -> bool:
        return True


class TestCodeownersAutoApprover(unittest.TestCase):
    def setUp(self) -> None:
        self.contents = {
            "filters": [
                {
                    "*": None,
                    "approvers": ["example-user"],
                }
            ]
        }

    def test_adds_auto_approver_without_opt_out(self) -> None:
        with patch.dict(os.environ, {"ADD_AUTO_APPROVE_USER": "true"}, clear=False):
            for parser_cls in (_TestOwnersParserV1, _TestOwnersParserV2):
                with self.subTest(parser=parser_cls.__name__):
                    parser = parser_cls()
                    result = parser.parse(
                        "buildscripts/copybara",
                        "buildscripts/copybara/OWNERS.yml",
                        deepcopy(self.contents),
                    )
                    self.assertEqual(len(result), 1)
                    self.assertIn("@example-user", result[0])
                    self.assertIn("@svc-auto-approve-bot", result[0])

    def test_skips_auto_approver_when_owners_file_opts_out(self) -> None:
        contents = deepcopy(self.contents)
        contents["options"] = {"no_auto_approver": True}

        with patch.dict(os.environ, {"ADD_AUTO_APPROVE_USER": "true"}, clear=False):
            for parser_cls in (_TestOwnersParserV1, _TestOwnersParserV2):
                with self.subTest(parser=parser_cls.__name__):
                    parser = parser_cls()
                    result = parser.parse(
                        "buildscripts/copybara",
                        "buildscripts/copybara/OWNERS.yml",
                        deepcopy(contents),
                    )
                    self.assertEqual(len(result), 1)
                    self.assertIn("@example-user", result[0])
                    self.assertNotIn("@svc-auto-approve-bot", result[0])


if __name__ == "__main__":
    unittest.main()
