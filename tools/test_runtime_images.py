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


if __name__ == "__main__":
    unittest.main()
