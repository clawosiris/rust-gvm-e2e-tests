# rust-gvm-e2e-tests

Real-stack conformance tests for
[rust-gvm](https://github.com/greenbone-hive/rust-gvm) against GMP deployments,
including the repository-owned Community stack and caller-owned providers.
The harness talks directly to `gvmd`, validates public typed response models,
and cross-checks deterministic behavior with gvm-tools/python-gvm.

## Deployment coverage architecture

Coverage policy has one source of truth:

- [coverage/manifest.json](coverage/manifest.json) is the machine inventory;
- [docs/community-coverage.md](docs/community-coverage.md) is generated from it;
- `tests/library/src/generated_manifest.rs` compile-references every typed
  helper and compares all registered wire commands with
  `COMMAND_CAPABILITIES`;
- [coverage/feature-catalog.json](coverage/feature-catalog.json) maps feature
  flags to command, helper, probe, fixture, and scenario requirements;
- [contracts/community-stable.json](contracts/community-stable.json) declares
  the Community provider's required, optional, and forbidden expectations.

The old exact [Community baseline](baselines/community-stable.json) remains
historical qualification evidence, not a runtime selection gate. Complete
observed snapshots are emitted per lane for drift review.

Regenerate or check against the supported rust-gvm checkout at
`b85443167a9fd642b2d91f6f347db048de5aba9c`:

```bash
python3 tools/coverage_manifest.py --rust-gvm-source ../rust-gvm
python3 tools/coverage_manifest.py --check --rust-gvm-source ../rust-gvm
```

Cross-repository qualification may supply a different exact 40-character
commit SHA from the canonical `greenbone-hive/rust-gvm` repository. The
workflow verifies that commit on a GitHub-hosted runner, checks its complete
command/helper surface against the reviewed coverage policy, and builds all
four client crates from that same SHA. Pull requests, schedules, and manual
runs without an override continue to use the reviewed pin. Branch and tag
names are rejected for rust-gvm so a moving ref cannot weaken provenance.

Adding/removing a registry command or public typed helper without updating the
policy fails generation, compilation, or inventory tests. Removed helper
surfaces and helpers replaced by canonical request values are recorded
separately; generated files are never edited by hand.

## Executable lanes

| Lane | Role | Volumes |
|---|---|---|
| `devel-fast` | Blocking typed discovery, safe reads, reversible CRUD, CLI | Warm shared |
| `devel-scan` | Deterministic TCP fixture scan, task state, report/result/export | Warm shared |
| `devel-isolated` | Admin, global setting restore, trashcan operations | Separate project |
| `devel-transport` | Explicit TLS, mTLS, SSH endpoints | Opt-in |
| `differential` | Blocking semantic parity with python-gvm | Opt-in |

Ordinary fast and scan jobs intentionally reuse warm feed volumes. Initializing
a fresh feed can consume most of the shared 21,000-second readiness budget. Volume
deletion happens only with the explicit `clean` workflow input.

Before checkout, each self-hosted lane loads the run's already-built runner
image from runner-temporary storage and uses that exact image as root to restore
host ownership of an existing, non-symlink `artifacts` directory itself.
Checkout then runs with `clean: false`; the lane script retains responsibility
for deleting only the selected lane's known artifact files.

The test details are in [docs/test-cases.md](docs/test-cases.md). Each lane
publishes the capability snapshot, exact contract, deterministic pre-mutation
plan, reconciled results, runtime tags/digests, GMP version, and exact rust-gvm
SHA. Optional unavailable or typed-version-ineligible capabilities are explicit
`not-selected` entries. Reconciled passes come from the exact runtime path that
executed each selected surface, never from lane completion alone.

## Run locally on a Docker host

Build the runner, start the warm stack, and execute a lane:

```bash
docker build -f docker/Dockerfile.runner \
  --build-arg RUST_GVM_SHA=b85443167a9fd642b2d91f6f347db048de5aba9c \
  -t rust-gvm-e2e-runner:ci .
bash docker/scripts/run-deployment-lane.sh devel-fast
```

The build prepares an ephemeral Cargo manifest and lockfile for the selected
exact SHA. It never rewrites the checked-in reviewed dependency pin.

The Compose provider uses a unique `E2E_RUN_ID`, records exact images, and
always stops containers while preserving volumes. Discovery and contract
validation complete before preflight cleanup or mutation. See
[deployment providers](docs/deployment-providers.md) for external mode and the
reusable workflow.

## Cleanup safety

Every created entity begins with `rust-gvm-e2e-<run-id>-`. Preflight cleanup
only selects that namespace (plus the historical fixed names from issue #7).
Deletion is dependency ordered: tickets/reports/tasks before targets/configs/scanners,
then access/report resources and supporting entities. Final cleanup
authenticates independently, accepts only explicit success/already-absent
statuses, and also runs during unwind.

## Dynamic capability boundary

Agent and OCI/container-image operations are no longer hard-coded Community
exclusions. Community emits them as `not-selected`; a deployment that enables
them must advertise the mapped commands and pass safe readiness and fixture
probes. Implemented agent-group and OCI-target lifecycles retain namespace,
cleanup, and exactly-once safeguards. Enabled entries without a cleanup-safe
public execution path fail as coverage gaps.

Report-config mutation is separately dispositioned as a known upstream crash:
the safe typed list read remains in `devel-isolated`, while create/clone/modify/
delete are not executed against Community stable pending
[greenbone/gvmd#3165](https://github.com/greenbone/gvmd/issues/3165). See
[the test cases](docs/test-cases.md#devel-isolated) and the generated inventory
for the exact reproducibility evidence.

## Validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 -m unittest discover -s tools -p 'test_*.py'
bash -n docker/scripts/*.sh tests/cli/*.sh
bash docker/scripts/test-community-lane-artifacts.sh
bash docker/scripts/test-deployment-lane-artifacts.sh
docker compose -f docker/docker-compose.yml config --quiet
```

The authoritative live validation runs on the repository’s self-hosted Docker
runner through [Community E2E](.github/workflows/e2e.yml).

## Convergence qualification

The coverage-rich harness is qualified on `main`; issue #148 records the
authoritative Community all-lane evidence. The checked-in dependency pin
remains the reviewed source default, while exact-source candidate dispatches
provide ongoing compatibility evidence. Private external deployment
qualification remains external rollout evidence and is not claimed here.

## License

AGPL-3.0-or-later
