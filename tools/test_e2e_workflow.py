#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import re
import unittest
from pathlib import Path


WORKFLOW = Path(__file__).parents[1] / ".github/workflows/e2e.yml"
SELF_HOSTED_LANES = {
    "devel-fast",
    "devel-scan",
    "devel-isolated",
    "devel-transport",
    "differential",
}


class CommunityCheckoutPolicyTests(unittest.TestCase):
    def test_only_self_hosted_lane_checkouts_disable_clean(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        jobs = dict(
            re.findall(
                r"^  ([a-z][a-z0-9-]+):\n(.*?)(?=^  [a-z][a-z0-9-]+:|\Z)",
                workflow,
                re.MULTILINE | re.DOTALL,
            )
        )
        checkout_clean_settings = {}
        for job, body in jobs.items():
            checkouts = re.findall(
                r"- uses: actions/checkout@.*?(?=^      - |\Z)",
                body,
                re.MULTILINE | re.DOTALL,
            )
            if checkouts:
                checkout_clean_settings[job] = [
                    bool(re.search(r"^          clean: false$", checkout, re.MULTILINE))
                    for checkout in checkouts
                ]

        self.assertEqual(
            {job for job, settings in checkout_clean_settings.items() if all(settings)},
            SELF_HOSTED_LANES,
        )
        for job, settings in checkout_clean_settings.items():
            self.assertEqual(all(settings), job in SELF_HOSTED_LANES)


if __name__ == "__main__":
    unittest.main()
