#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import tempfile
import unittest
from pathlib import Path

from prepare_rust_gvm_candidate import rewrite_manifest, verify_lock


PIN = "b85443167a9fd642b2d91f6f347db048de5aba9c"
CANDIDATE = "bc7f3474efd2f1f05904b73ea7fe223e102ebade"
CANONICAL = "https://github.com/greenbone-hive/rust-gvm.git"


def dependency(name: str) -> str:
    return f'{name} = {{ git = "{CANONICAL}", rev = "{PIN}" }}'


class PrepareRustGvmCandidateTests(unittest.TestCase):
    def test_rewrites_exactly_four_canonical_dependencies(self):
        source = "\n".join(
            dependency(name)
            for name in ("gvm-client", "gvm-connection", "gvm-gmp", "gvm-protocol")
        )
        rewritten, names = rewrite_manifest(source, CANDIDATE)
        self.assertEqual(len(names), 4)
        self.assertEqual(rewritten.count(CANDIDATE), 4)
        self.assertNotIn(PIN, rewritten)

    def test_rejects_moving_ref_and_incomplete_manifest(self):
        with self.assertRaises(ValueError):
            rewrite_manifest(dependency("gvm-client"), "main")
        with self.assertRaises(ValueError):
            rewrite_manifest(dependency("gvm-client"), CANDIDATE)

    def test_lock_verification_requires_exact_candidate_for_all_packages(self):
        packages = "\n".join(
            f'''[[package]]
name = "{name}"
version = "0.1.0"
source = "git+{CANONICAL}?rev={CANDIDATE}#{CANDIDATE}"
'''
            for name in ("gvm-client", "gvm-connection", "gvm-gmp", "gvm-protocol")
        )
        with tempfile.TemporaryDirectory() as temporary:
            lockfile = Path(temporary) / "Cargo.lock"
            lockfile.write_text(f"version = 4\n\n{packages}", encoding="utf-8")
            verify_lock(lockfile, CANDIDATE)
            with self.assertRaises(ValueError):
                verify_lock(lockfile, PIN)


if __name__ == "__main__":
    unittest.main()
