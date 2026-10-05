#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import unittest

from resolve_component_refs import resolve


PIN = "cd4689cab8875ea1a0d7b35cd5a5038416f0e8e0"
CANDIDATE = "bc7f3474efd2f1f05904b73ea7fe223e102ebade"


class ResolveComponentRefsTests(unittest.TestCase):
    def test_non_dispatch_events_keep_reviewed_pin(self):
        for event in ("pull_request", "schedule"):
            with self.subTest(event=event):
                refs = resolve(event_name=event, default_rust_gvm_sha=PIN)
                self.assertEqual(refs.rust_gvm_sha, PIN)
                self.assertEqual(refs.gvm_rools_ref, "main")
                self.assertEqual(refs.gvm_version, "stable")

    def test_workflow_dispatch_accepts_exact_candidate_sha(self):
        refs = resolve(
            event_name="workflow_dispatch",
            default_rust_gvm_sha=PIN,
            dispatch_rust_gvm_ref=CANDIDATE,
            dispatch_gvm_rools_ref="main",
            dispatch_gvm_version="stable",
        )
        self.assertEqual(refs.rust_gvm_ref, CANDIDATE)
        self.assertEqual(refs.rust_gvm_sha, CANDIDATE)

    def test_rust_gvm_repository_dispatch_requires_exact_sha(self):
        refs = resolve(
            event_name="repository_dispatch",
            default_rust_gvm_sha=PIN,
            payload_component="rust-gvm",
            payload_ref=CANDIDATE,
        )
        self.assertEqual(refs.rust_gvm_sha, CANDIDATE)

        for invalid in ("", "main", "BC7F3474EFD2F1F05904B73EA7FE223E102EBADE", "abc123"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    resolve(
                        event_name="repository_dispatch",
                        default_rust_gvm_sha=PIN,
                        payload_component="rust-gvm",
                        payload_ref=invalid,
                    )

    def test_gvm_rools_dispatch_preserves_rust_gvm_pin(self):
        refs = resolve(
            event_name="repository_dispatch",
            default_rust_gvm_sha=PIN,
            payload_component="gvm-rools",
            payload_ref="main",
            payload_gvm_version="26.40.1",
        )
        self.assertEqual(refs.rust_gvm_sha, PIN)
        self.assertEqual(refs.gvm_rools_ref, "main")
        self.assertEqual(refs.gvm_version, "26.40.1")

    def test_unknown_repository_dispatch_component_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve(
                event_name="repository_dispatch",
                default_rust_gvm_sha=PIN,
                payload_component="unknown",
                payload_ref=CANDIDATE,
            )

    def test_output_fields_reject_multiline_or_unsafe_values(self):
        with self.assertRaises(ValueError):
            resolve(
                event_name="workflow_dispatch",
                default_rust_gvm_sha=PIN,
                dispatch_gvm_rools_ref="main\ninjected=value",
            )
        with self.assertRaises(ValueError):
            resolve(
                event_name="workflow_dispatch",
                default_rust_gvm_sha=PIN,
                dispatch_gvm_version="stable\ninjected=value",
            )


if __name__ == "__main__":
    unittest.main()
