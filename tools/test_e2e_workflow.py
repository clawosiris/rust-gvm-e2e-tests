#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

import re
import unittest
from pathlib import Path


WORKFLOW = Path(__file__).parents[1] / ".github/workflows/e2e.yml"
DOCKERFILE = Path(__file__).parents[1] / "docker/Dockerfile.runner"
LANE_SCRIPT = Path(__file__).parents[1] / "docker/scripts/run-deployment-lane.sh"
RUNTIME_IMAGES_SCRIPT = Path(__file__).parents[1] / "tools/runtime_images.py"
POSTGRES_BOOTSTRAP_SCRIPT = (
    Path(__file__).parents[1] / "docker/scripts/postgres-bootstrap.sh"
)
REUSABLE_WORKFLOW = Path(__file__).parents[1] / ".github/workflows/deployment-e2e.yml"
WAIT_SCRIPT = Path(__file__).parents[1] / "docker/scripts/wait-ready.sh"
COMPOSE_FILE = Path(__file__).parents[1] / "docker/docker-compose.yml"
CARGO_MANIFEST = Path(__file__).parents[1] / "tests/library/Cargo.toml"
LOCKFILE = Path(__file__).parents[1] / "Cargo.lock"
SUPPORTED_RUST_GVM_SHA = "b85443167a9fd642b2d91f6f347db048de5aba9c"
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
                f"- run: bash docker/scripts/run-deployment-lane.sh {job}"
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
                "org.opencontainers.image.revision", bootstrap
            )
            self.assertIn('= "${E2E_RUST_GVM_SHA}"', bootstrap)
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
        for job in ("resolve-refs", "inventory", "build-runner"):
            body = self.jobs()[job]
            self.assertNotIn("Restore artifacts directory ownership", body)
            self.assertNotIn("${{ runner.temp }}", body)

    def test_external_actions_are_immutable(self):
        workflow = WORKFLOW.read_text(encoding="utf-8") + REUSABLE_WORKFLOW.read_text(encoding="utf-8")
        actions = re.findall(r"uses:\s+([^\s]+)", workflow)
        self.assertTrue(actions)
        for action in actions:
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

    def test_reusable_workflow_has_generic_provider_contract(self):
        workflow = REUSABLE_WORKFLOW.read_text(encoding="utf-8")
        lane_script = LANE_SCRIPT.read_text(encoding="utf-8")
        for value in (
            "workflow_call:",
            "harness-ref:",
            "deployment-id:",
            "contract-path:",
            "fixture-descriptor-path:",
            "provider-mode:",
            "provider-descriptor-path:",
            "compose-files:",
            "runtime-image-version:",
            "scan-target-host:",
            "oci-image-reference:",
            "readiness-timeout-seconds:",
            "task-progress-timeout-seconds:",
            "E2E (${{ inputs.deployment-id }}/${{ matrix.lane }})",
            "run-deployment-lane.sh",
        ):
            self.assertIn(value, workflow)
        self.assertNotIn("enterprise image", workflow.lower())
        self.assertNotIn("registry password", workflow.lower())
        self.assertRegex(
            workflow,
            r"ref: \$\{\{ github\.sha \}\}\n\s+path: provider\n\s+clean: false",
        )
        self.assertIn("org.opencontainers.image.revision", lane_script)
        self.assertIn("runner image rust-gvm revision does not match", lane_script)

    def test_workflow_keeps_reviewed_default_and_supports_exact_candidates(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")

        self.assertIn(f"RUST_GVM_SHA: {SUPPORTED_RUST_GVM_SHA}", workflow)
        self.assertIn(f"default: {SUPPORTED_RUST_GVM_SHA}", workflow)
        self.assertIn(
            "RUST_GVM_SHA=${{ steps.refs.outputs.rust-gvm-sha }}", workflow
        )
        self.assertIn("resolve-refs:", workflow)
        self.assertIn("needs: resolve-refs", workflow)
        self.assertIn("needs: [resolve-refs, inventory]", workflow)
        self.assertIn("python3 tools/resolve_component_refs.py", workflow)
        self.assertIn(
            'git -C /tmp/rust-gvm fetch --depth 1 origin "${RESOLVED_RUST_GVM_SHA}"',
            workflow,
        )
        self.assertIn(
            '--policy-rust-gvm-sha "${RUST_GVM_SHA}"',
            workflow,
        )
        self.assertIn(
            'python3 tools/prepare_rust_gvm_candidate.py \\\n'
            '            --workspace-manifest Cargo.toml \\\n'
            '            --library-manifest tests/library/Cargo.toml \\\n'
            '            --lockfile Cargo.lock \\\n'
            '            --sha "${RESOLVED_RUST_GVM_SHA}"',
            workflow,
        )
        self.assertIn(
            f"ARG RUST_GVM_SHA={SUPPORTED_RUST_GVM_SHA}", dockerfile
        )
        self.assertIn("prepare_rust_gvm_candidate.py", dockerfile)
        self.assertIn("FROM rust:1.89", dockerfile)
        self.assertNotIn("RUST_GVM_REF", dockerfile)
        self.assertNotIn("default: devel\n", workflow)
        self.assertNotIn("rust-gvm/devel", workflow)

        manifest = CARGO_MANIFEST.read_text(encoding="utf-8")
        lockfile = LOCKFILE.read_text(encoding="utf-8")
        canonical = "https://github.com/greenbone-hive/rust-gvm.git"
        self.assertEqual(manifest.count(f'git = "{canonical}"'), 4)
        self.assertEqual(manifest.count(f'rev = "{SUPPORTED_RUST_GVM_SHA}"'), 4)
        lock_source = f"source = \"git+{canonical}?rev={SUPPORTED_RUST_GVM_SHA}#{SUPPORTED_RUST_GVM_SHA}\""
        self.assertEqual(lockfile.count(lock_source), 4)
        self.assertNotIn("clawosiris/rust-gvm.git", manifest)
        self.assertNotIn("clawosiris/rust-gvm.git", lockfile)

    def test_repaired_main_shared_state_and_readiness_contract_is_preserved(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        lane_script = LANE_SCRIPT.read_text(encoding="utf-8")
        runtime_images_script = RUNTIME_IMAGES_SCRIPT.read_text(encoding="utf-8")
        postgres_bootstrap_script = POSTGRES_BOOTSTRAP_SCRIPT.read_text(
            encoding="utf-8"
        )
        wait_script = WAIT_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("branches: [main]", workflow)
        self.assertIn("group: rust-gvm-e2e-shared-compose-state", workflow)
        for job in SELF_HOSTED_LANES:
            self.assertIn("timeout-minutes: 420", self.jobs()[job])
        self.assertIn("deployment_compose up -d pg-gvm", lane_script)
        self.assertNotIn("up -d --wait --wait-timeout 300 pg-gvm", lane_script)
        self.assertIn("wait_for_postgres_bootstrap", lane_script)
        self.assertNotIn('--project-directory "$(pwd)"', lane_script)
        self.assertIn("validate_compose_workspace.py", workflow)
        self.assertIn("--expected-workspace \"$(pwd -P)\"", workflow)
        self.assertIn(
            'parser.add_argument("--project-directory")', runtime_images_script
        )
        self.assertIn(
            "ALTER SYSTEM SET max_wal_size = '16GB'", postgres_bootstrap_script
        )
        self.assertIn(
            "ALTER SYSTEM SET checkpoint_timeout = '30min'",
            postgres_bootstrap_script,
        )
        self.assertIn("CHECKPOINT;", lane_script)
        self.assertIn(
            'READINESS_TIMEOUT_SECS="${E2E_READINESS_TIMEOUT_SECS:-21000}"',
            wait_script,
        )
        self.assertIn('remaining=$((READINESS_TIMEOUT_SECS - elapsed))', wait_script)
        self.assertIn('-e E2E_READINESS_TIMEOUT_SECS="$remaining"', wait_script)

    def test_shared_volume_feed_producers_are_serialized(self):
        compose = COMPOSE_FILE.read_text(encoding="utf-8")

        for producer, prerequisite in (
            ("dfn-cert-data", "cert-bund-data"),
            ("report-formats", "data-objects"),
        ):
            service = re.search(
                rf"^  {re.escape(producer)}:\n(.*?)(?=^  [a-z0-9][a-z0-9-]*:|\Z)",
                compose,
                re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(service)
            self.assertRegex(
                service.group(1),
                rf"depends_on:\n\s+{re.escape(prerequisite)}:\n"
                r"\s+condition: service_healthy",
            )
            self.assertNotRegex(
                service.group(1),
                rf"{re.escape(prerequisite)}:\n"
                r"\s+condition: service_started",
            )


if __name__ == "__main__":
    unittest.main()
