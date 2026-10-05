# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("runtime_images.py")
SPEC = importlib.util.spec_from_file_location("runtime_images", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class RuntimeImagesTests(unittest.TestCase):
    def test_compose_command_preserves_file_relative_path_resolution(self):
        self.assertEqual(
            MODULE.build_compose_command(["docker/docker-compose.yml"]),
            ["docker", "compose", "-f", "docker/docker-compose.yml"],
        )

    def test_compose_command_accepts_explicit_project_directory(self):
        self.assertEqual(
            MODULE.build_compose_command(
                ["base.yml", "override.yml"], "/provider/project"
            ),
            [
                "docker",
                "compose",
                "--project-directory",
                "/provider/project",
                "-f",
                "base.yml",
                "-f",
                "override.yml",
            ],
        )

    def test_accepts_compose_array_and_records_digest(self):
        rows = MODULE.parse_compose_images(
            '[{"Service":"gvmd","Repository":"example/gvmd","Tag":"stable","ID":"sha256:1"}]'
        )
        actual = MODULE.normalize(rows, lambda _: ["example/gvmd@sha256:abc"])
        self.assertEqual(actual[0]["service"], "gvmd")
        self.assertEqual(actual[0]["digest"], "example/gvmd@sha256:abc")

    def test_accepts_newline_delimited_compose_output(self):
        rows = MODULE.parse_compose_images(
            '{"Service":"z","ID":"z"}\n{"Service":"a","ID":"a"}\n'
        )
        actual = MODULE.normalize(rows, lambda image_id: [f"repo@{image_id}"])
        self.assertEqual([row["service"] for row in actual], ["a", "z"])

    def test_derives_service_from_compose_container_name(self):
        rows = MODULE.parse_compose_images(
            '[{"ContainerName":"rust-gvm-e2e-ospd-openvas-1",'
            '"Repository":"example/ospd","Tag":"stable","ID":"sha256:2"}]'
        )
        actual = MODULE.normalize(
            rows,
            lambda _: ["example/ospd@sha256:def"],
            ["gvmd", "ospd-openvas"],
        )
        self.assertEqual(actual[0]["service"], "ospd-openvas")

    def test_preserves_unmatched_container_name_as_evidence(self):
        row = {"ContainerName": "unmatched-container"}
        self.assertEqual(
            MODULE.service_name(row, ["gvmd"]),
            "unmatched-container",
        )

    def test_external_gvmd_provenance_accepts_only_a_complete_canonical_row(self):
        row = {
            "service": "gvmd",
            "repository": "registry.community.greenbone.net/community/gvmd",
            "version": "26.40.2",
            "digest": "registry.community.greenbone.net/community/gvmd@sha256:" + "a" * 64,
        }
        self.assertEqual(
            MODULE.external_gvmd_provenance([row]),
            {
                "version": "26.40.2",
                "source_revision": "",
                "digest": "registry.community.greenbone.net/community/gvmd@sha256:" + "a" * 64,
                "source_specific_image": False,
            },
        )

    def test_external_gvmd_provenance_requires_revision_for_source_specific_image(self):
        row = {
            "service": "gvmd",
            "repository": "ghcr.io/greenbone/gvmd",
            "version": "26.40.2",
            "digest": "ghcr.io/greenbone/gvmd@sha256:" + "b" * 64,
        }
        with self.assertRaisesRegex(ValueError, "source-specific"):
            MODULE.external_gvmd_provenance([row])
        row["source_revision"] = "c" * 40
        self.assertTrue(MODULE.external_gvmd_provenance([row])["source_specific_image"])

    def test_external_gvmd_provenance_rejects_missing_or_ambiguous_gvmd_rows(self):
        with self.assertRaisesRegex(ValueError, "exactly one gvmd"):
            MODULE.external_gvmd_provenance([])
        row = {
            "service": "gvmd",
            "repository": "registry.community.greenbone.net/community/gvmd",
            "version": "26.40.2",
            "digest": "sha256:" + "d" * 64,
        }
        with self.assertRaisesRegex(ValueError, "exactly one gvmd"):
            MODULE.external_gvmd_provenance([row, row.copy()])


if __name__ == "__main__":
    unittest.main()
