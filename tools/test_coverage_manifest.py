#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("coverage_manifest.py")
SPEC = importlib.util.spec_from_file_location("coverage_manifest", MODULE_PATH)
assert SPEC and SPEC.loader
MANIFEST = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MANIFEST
SPEC.loader.exec_module(MANIFEST)


class CoveragePolicyTests(unittest.TestCase):
    def test_only_issue_118_hard_commands_are_excluded(self):
        actual = {
            name
            for name in MANIFEST.EXCLUDED_COMMANDS
            if MANIFEST.command_disposition(name) == "excluded-community"
        }
        self.assertEqual(actual, MANIFEST.EXCLUDED_COMMANDS)
        self.assertEqual(len(actual), 15)

    def test_dispositions_are_mutually_exclusive(self):
        classes = [
            MANIFEST.EXCLUDED_COMMANDS,
            MANIFEST.CONDITIONAL_COMMANDS,
            MANIFEST.NIGHTLY_COMMANDS,
            MANIFEST.ISOLATED_COMMANDS,
        ]
        for index, left in enumerate(classes):
            for right in classes[index + 1 :]:
                self.assertFalse(left & right)

    def test_helper_only_variants_are_explicit_exclusions(self):
        self.assertEqual(
            set(MANIFEST.EXTRA_HELPERS),
            {
                "create_agent_group_task",
                "create_container_image_task",
                "create_container_task",
                "create_oci_image_target_task",
            },
        )
        self.assertTrue(
            all(
                disposition == "excluded-community"
                for _, disposition in MANIFEST.EXTRA_HELPERS.values()
            )
        )


if __name__ == "__main__":
    unittest.main()
