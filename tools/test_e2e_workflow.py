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
    @staticmethod
    def jobs():
        workflow = WORKFLOW.read_text(encoding="utf-8")
        return dict(
            re.findall(
                r"^  ([a-z][a-z0-9-]+):\n(.*?)(?=^  [a-z][a-z0-9-]+:|\Z)",
                workflow,
                re.MULTILINE | re.DOTALL,
            )
        )

    def test_only_self_hosted_lane_checkouts_disable_clean(self):
        checkout_clean_settings = {}
        for job, body in self.jobs().items():
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

    def test_self_hosted_lanes_repair_artifacts_before_checkout(self):
        for job in SELF_HOSTED_LANES:
            body = self.jobs()[job]
            download = body.index("- uses: actions/download-artifact@")
            load = body.index("- name: Load exact Community runner image")
            repair = body.index("- name: Restore artifacts directory ownership")
            checkout = body.index("- uses: actions/checkout@")
            lane = body.index(
                f"- run: bash docker/scripts/run-community-lane.sh {job}"
            )
            self.assertLess(download, load)
            self.assertLess(load, repair)
            self.assertLess(repair, checkout)
            self.assertLess(checkout, lane)

            bootstrap = body[download:checkout]
            self.assertIn(
                "path: ${{ runner.temp }}/community-runner-${{ github.run_id }}",
                bootstrap,
            )
            self.assertIn('docker load --input "${runner_tar}"', bootstrap)
            self.assertIn(
                "runner_image_id=\"$(docker image inspect --format '{{.Id}}' "
                '"${RUNNER_IMAGE_NAME}:${RUNNER_IMAGE_TAG}")"',
                bootstrap,
            )
            self.assertIn(
                "RUNNER_IMAGE_ID: ${{ steps.runner-image.outputs.image-id }}",
                bootstrap,
            )
            self.assertIn('artifacts_dir="${GITHUB_WORKSPACE}/artifacts"', bootstrap)
            self.assertIn(
                'if [[ -d "${artifacts_dir}" && ! -L "${artifacts_dir}" ]]; then',
                bootstrap,
            )
            self.assertIn("--user 0:0", bootstrap)
            self.assertIn(
                '--mount "type=bind,src=${artifacts_dir},dst=/workspace/artifacts"',
                bootstrap,
            )
            self.assertIn("--entrypoint /bin/chown", bootstrap)
            self.assertIn(
                '"${RUNNER_IMAGE_ID}" "${host_uid}:${host_gid}" '
                "/workspace/artifacts",
                bootstrap,
            )
            for forbidden in ("sudo", "chown -R", "eval ", "rm -rf", "artifacts/*"):
                self.assertNotIn(forbidden, bootstrap)

    def test_hosted_jobs_do_not_use_checkout_recovery(self):
        for job in ("inventory", "build-runner"):
            body = self.jobs()[job]
            self.assertNotIn("Restore artifacts directory ownership", body)
            self.assertNotIn("${{ runner.temp }}", body)


if __name__ == "__main__":
    unittest.main()
