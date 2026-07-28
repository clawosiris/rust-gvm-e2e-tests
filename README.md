# rust-gvm-e2e-tests

Real-stack conformance tests for rust-gvm against Greenbone Community Edition.
The harness talks directly to `gvmd`, validates public typed response models,
and cross-checks deterministic behavior with gvm-tools/python-gvm.

## Community coverage architecture

Coverage policy has one source of truth:

- [coverage/manifest.json](coverage/manifest.json) is the machine inventory;
- [docs/community-coverage.md](docs/community-coverage.md) is generated from it;
- `tests/library/src/generated_manifest.rs` compile-references every typed
  helper and compares all registered wire commands with
  `COMMAND_CAPABILITIES`;
- [baselines/community-stable.json](baselines/community-stable.json) pins the
  Community tag, GMP version, rust-gvm SHA, features, and conditional
  availability discovered from version/features/help.

Regenerate or check against a current rust-gvm checkout:

```bash
python3 tools/coverage_manifest.py --rust-gvm-source ../rust-gvm
python3 tools/coverage_manifest.py --check --rust-gvm-source ../rust-gvm
```

Adding/removing a registry command or public typed helper without updating the
policy fails generation, compilation, or inventory tests.

## Executable lanes

| Lane | Role | Volumes |
|---|---|---|
| `devel-fast` | Blocking typed discovery, safe reads, reversible CRUD, CLI | Warm shared |
| `devel-scan` | Deterministic TCP fixture scan, task state, report/result/export | Warm shared |
| `devel-isolated` | Admin, global setting restore, trashcan operations | Separate project |
| `devel-transport` | Explicit TLS, mTLS, SSH endpoints | Opt-in |
| `differential` | Blocking semantic parity with python-gvm | Opt-in |

Ordinary fast and scan jobs intentionally reuse warm feed volumes. Initializing
a fresh feed is known to exceed the normal two-hour readiness budget. Volume
deletion happens only with the explicit `clean` workflow input.

Before checkout, each self-hosted lane loads the run's already-built runner
image from runner-temporary storage and uses that exact image as root to restore
host ownership of an existing, non-symlink `artifacts` directory itself.
Checkout then runs with `clean: false`; the lane script retains responsibility
for deleting only the selected lane's known artifact files.

The test details are in [docs/test-cases.md](docs/test-cases.md). Each lane
publishes structured JSON with pass/fail/known-upstream-bug/conditional/excluded
counts, exact rust-gvm SHA, GMP version, runtime tags/digests, feature/help
evidence, and all observations.

## Run locally on a Docker host

Build the runner, start the warm stack, and execute a lane:

```bash
docker build -f docker/Dockerfile.runner \
  --build-arg RUST_GVM_REF=04da5996bc7b08640c15e20e85d768960b36d939 \
  -t rust-gvm-e2e-runner:ci .
bash docker/scripts/run-community-lane.sh devel-fast
```

The lane script uses a unique `E2E_RUN_ID`, records exact images, and always
stops containers while preserving volumes. Override `E2E_RUN_ID` for
reproduction. Set `E2E_RECORD_BASELINE=1` only to produce a reviewed candidate
artifact; normal runs enforce the checked-in baseline.

## Cleanup safety

Every created entity begins with `rust-gvm-e2e-<run-id>-`. Preflight cleanup
only selects that namespace (plus the historical fixed names from issue #7).
Deletion is dependency ordered: tickets/tasks before targets/configs/scanners,
then access/report resources and supporting entities. Final cleanup
authenticates independently, accepts only explicit success/already-absent
statuses, and also runs during unwind.

## Community boundary

Agent management and OCI/container-image target management/scanning are never
required. Those exact issue #118 capabilities are visible as
`excluded-community`; all other uncertain Community functionality is probed
and recorded conditionally. The `scan-fixture` Nginx container is an ordinary
network service target, not an OCI image target.

## Validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
python3 -m unittest discover -s tools -p 'test_*.py'
bash -n docker/scripts/*.sh tests/cli/*.sh
bash docker/scripts/test-community-lane-artifacts.sh
docker compose -f docker/docker-compose.yml config --quiet
```

The authoritative live validation runs on the repository’s self-hosted Docker
runner through [Community E2E](.github/workflows/e2e.yml).

## License

AGPL-3.0-or-later
