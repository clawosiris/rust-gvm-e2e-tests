# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("validate_compose_workspace.py")
SPEC = importlib.util.spec_from_file_location("validate_compose_workspace", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ValidateComposeWorkspaceTests(unittest.TestCase):
    def test_returns_the_single_workspace_bind_source(self):
        config = {
            "services": {
                "rust-gvm-e2e": {
                    "volumes": [
                        {
                            "type": "bind",
                            "source": "/checkout",
                            "target": "/workspace",
                        }
                    ]
                }
            }
        }
        self.assertEqual(
            MODULE.resolved_workspace_source(config), Path("/checkout")
        )

    def test_rejects_missing_workspace_bind(self):
        config = {"services": {"rust-gvm-e2e": {"volumes": []}}}
        with self.assertRaisesRegex(ValueError, "expected exactly one bind"):
            MODULE.resolved_workspace_source(config)

    def test_rejects_duplicate_workspace_binds(self):
        bind = {"type": "bind", "source": "/checkout", "target": "/workspace"}
        config = {
            "services": {"rust-gvm-e2e": {"volumes": [bind, dict(bind)]}}
        }
        with self.assertRaisesRegex(ValueError, "expected exactly one bind"):
            MODULE.resolved_workspace_source(config)


if __name__ == "__main__":
    unittest.main()
