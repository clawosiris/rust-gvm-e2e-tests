#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("coverage_manifest.py")
SPEC = importlib.util.spec_from_file_location("coverage_manifest", MODULE_PATH)
assert SPEC and SPEC.loader
MANIFEST = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MANIFEST
SPEC.loader.exec_module(MANIFEST)


class CoveragePolicyTests(unittest.TestCase):
    def test_policy_sha_override_changes_only_manifest_metadata(self):
        manifest = {
            "rust_gvm_sha": "a" * 40,
            "commands": [{"name": "get_version"}],
        }
        MANIFEST.apply_policy_sha(manifest, "b" * 40)
        self.assertEqual(manifest["rust_gvm_sha"], "b" * 40)
        self.assertEqual(manifest["commands"], [{"name": "get_version"}])

    def test_policy_sha_override_rejects_moving_or_malformed_refs(self):
        for invalid in ("main", "A" * 40, "abc123"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    MANIFEST.apply_policy_sha({"rust_gvm_sha": "a" * 40}, invalid)

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
            MANIFEST.KNOWN_UPSTREAM_BUG_COMMANDS,
            MANIFEST.CONDITIONAL_COMMANDS,
            MANIFEST.NIGHTLY_COMMANDS,
            MANIFEST.ISOLATED_COMMANDS,
        ]
        for index, left in enumerate(classes):
            for right in classes[index + 1 :]:
                self.assertFalse(left & right)

    def test_report_config_mutations_are_known_upstream_bugs_not_isolated_live(self):
        expected = {
            "create_report_config",
            "delete_report_config",
            "modify_report_config",
        }
        self.assertEqual(MANIFEST.KNOWN_UPSTREAM_BUG_COMMANDS, expected)
        for name in expected:
            self.assertEqual(MANIFEST.command_disposition(name), "known-upstream-bug")
            self.assertEqual(MANIFEST.lane_for("known-upstream-bug"), "none")
            self.assertIn("greenbone/gvmd#3165", MANIFEST.rationale_for(name, "known-upstream-bug"))
        self.assertEqual(MANIFEST.command_disposition("get_report_configs"), "isolated-live")

    def test_helper_only_variants_retain_explicit_exclusion_policy(self):
        self.assertEqual(
            set(MANIFEST.EXTRA_HELPERS),
            {
                "create_agent_group_task",
                "create_container_image_task",
                "create_container_task",
                "create_oci_image_target_task",
            },
        )
        self.assertEqual(
            MANIFEST.REMOVED_HELPERS,
            {"sync_scan_config"},
        )
        self.assertEqual(
            MANIFEST.command_disposition("sync_config"),
            "conditional-community",
        )

    def test_typed_helper_discovery_recurses_into_module_files(self):
        self.assertEqual(MANIFEST.DIRECT_CLIENT_HELPERS, set())
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            typed = source / "crates/gvm-client/src/typed"
            typed.mkdir(parents=True)
            (typed.parent / "typed.rs").write_text(
                "    pub async fn root_helper(&mut self) {}\n", encoding="utf-8"
            )
            (typed / "reports.rs").write_text(
                "    pub async fn get_scan_report(&mut self) {}\n", encoding="utf-8"
            )
            self.assertEqual(
                MANIFEST.typed_helpers(source),
                ["get_scan_report", "root_helper"],
            )
        self.assertEqual(
            MANIFEST.command_disposition("get_scan_report"),
            "conditional-community",
        )

    def test_semantic_report_export_helpers_retain_conditional_policy(self):
        for helper in ("get_report_export", "get_report_export_with_opts"):
            self.assertEqual(
                MANIFEST.HELPER_DISPOSITION_OVERRIDES[helper],
                "conditional-community",
            )
        self.assertTrue(
            all(
                disposition == "excluded-community"
                for _, disposition in MANIFEST.EXTRA_HELPERS.values()
            )
        )

    def test_async_report_export_is_conditional_until_cleanup_is_typed(self):
        self.assertIn("export_scan_report", MANIFEST.CONDITIONAL_COMMANDS)
        self.assertEqual(
            MANIFEST.command_disposition("export_scan_report"),
            "conditional-community",
        )
        self.assertIn(
            "cleanup-safe export reconciliation",
            MANIFEST.rationale_for("export_scan_report", "conditional-community"),
        )

    def test_disappeared_facade_is_replaced_when_wire_command_remains(self):
        migrations = MANIFEST.classify_helper_migrations(
            [{"name": "get_targets", "wire_command": "get_targets"}],
            set(),
            {"get_targets"},
        )
        self.assertEqual(len(migrations), 1)
        self.assertEqual(migrations[0].status, "replaced")
        self.assertIn("GmpClient::execute", migrations[0].replacement)

    def test_disappeared_surface_is_removed_without_supported_replacement(self):
        migrations = MANIFEST.classify_helper_migrations(
            [
                {
                    "name": "old_unknown_helper",
                    "wire_command": "removed_wire_command",
                }
            ],
            set(),
            {"create_task"},
        )
        self.assertEqual(len(migrations), 1)
        self.assertEqual(migrations[0].status, "removed")
        self.assertIsNone(migrations[0].replacement)

    def test_registry_only_sync_surface_is_removed_not_replaced(self):
        migrations = MANIFEST.classify_helper_migrations(
            [{"name": "sync_scan_config", "wire_command": "sync_config"}],
            set(),
            {"sync_config"},
        )
        self.assertEqual(len(migrations), 1)
        self.assertEqual(migrations[0].status, "removed")
        self.assertIsNone(migrations[0].replacement)

    def test_current_helper_is_not_reported_as_migrated(self):
        self.assertEqual(
            MANIFEST.classify_helper_migrations(
                [{"name": "get_scan_report", "wire_command": "get_scan_report"}],
                {"get_scan_report"},
                {"get_scan_report"},
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
