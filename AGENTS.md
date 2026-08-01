# AGENTS.md

This repository is the live-system integration harness for the `rust-gvm`
ecosystem. It runs Rust and CLI clients against a real Greenbone Community
container stack. Changes that look small can consume hours of runner time or
leave persistent gvmd state behind, so use this guide before exploring broadly.

## Ten-minute orientation

Read these in order:

1. `README.md` — current purpose, supported suites, workflow inputs, and layout.
2. `.github/workflows/e2e.yml` — authoritative CI orchestration and trigger
   behavior.
3. `tests/library/src/main.rs` — authoritative Rust test behavior, assertions,
   and cleanup semantics.
4. `docker/docker-compose.yml` — the live stack, shared volumes, and runner
   wiring.
5. `docker/Dockerfile.runner` — how exact `rust-gvm` and `gvm-rools` revisions
   become the binaries under test.
6. `docs/test-cases.md` — human-readable coverage inventory; update it when
   externally visible coverage changes.

Files under `spec/`, `journal/`, and some older prose in `docker/README.md`
record design history. They are useful context, but they can lag the executable
workflow and source. When they disagree, prefer the workflow, Compose file,
Dockerfile, and test code, then correct stale documentation in the same change.

## What runs where

```text
GitHub-hosted runner
  builds docker/Dockerfile.runner
    ├─ gvm-community-e2e from tests/library
    └─ gvm-cli from gvm-rools
  exports the image as a short-lived artifact

Self-hosted runner
  loads that image
  starts docker/docker-compose.yml
    ├─ gvmd + PostgreSQL + Redis
    ├─ ospd-openvas + openvasd
    └─ feed/data containers
  waits for socket and feed readiness
  runs Rust, CLI, CRUD, SecInfo, and optional differential/scan coverage
  stops containers but normally preserves named volumes
```

The client path under test is the gvmd Unix socket mounted read-only into the
runner container at `/run/gvmd/gvmd.sock`. This repository does not own the
REST E2E suite in `rust-gvm-api`.

## Branch contract

- `main` validates the released/mainline dependency path. All four `rust-gvm`
  crates in `tests/library/Cargo.toml` normally point to the canonical
  `greenbone-hive/rust-gvm` `main` branch.
- Other product branches can carry broader or newer coverage. Do not copy an
  API or assumption from another branch without reconciling it with the target
  branch's lockfile, workflow defaults, and supported gvmd/GMP baseline.
- Keep all `rust-gvm` crate declarations on one revision. A mixed revision can
  compile misleadingly or test an impossible dependency combination.
- `Cargo.lock` is part of the reproducible runner input. Update and review it
  whenever dependency declarations change.

`docker/Dockerfile.runner` rewrites every `branch = "main"` rust-gvm dependency
to the workflow-selected revision. Hex strings of 7–40 characters become Cargo
`rev` pins; other non-`main` values become Cargo branch pins. If the manifest
shape or ref rules change, update the Dockerfile and workflow together.

## Source map and ownership

| Area | Source of truth | Change here when |
| --- | --- | --- |
| Workflow inputs, triggers, jobs, timeouts | `.github/workflows/e2e.yml` | Orchestration or CI policy changes |
| Community services, volumes, capabilities | `docker/docker-compose.yml` | Runtime topology or image wiring changes |
| Client revisions and installed tools | `docker/Dockerfile.runner` | Build inputs or binary packaging changes |
| Rust GMP behavior | `tests/library/src/main.rs` | Library smoke, CRUD, SecInfo, scan, or differential coverage changes |
| CLI behavior | `tests/cli/smoke.sh` | `gvm-cli` syntax, output, or failure behavior changes |
| Suite sequencing | `docker/scripts/run-smoke.sh` | Library/CLI layer ordering changes |
| Socket/feed readiness | `docker/scripts/wait-ready.sh` and Rust `wait_ready` | Startup or feed readiness semantics change |
| Python reference diagnostics | `docker/scripts/validate-against-gvm-tools.py` | Failure classification checks change |
| Cross-client normalization | `docker/scripts/differential-helper.py` plus Rust differential code | Rust/python parity coverage changes |
| User-facing coverage inventory | `docs/test-cases.md` | Tests or acceptance semantics change |

The Rust harness is intentionally a single binary. Navigate it by the suite
entry points rather than reading it linearly:

- `async_main` and `Mode` select execution.
- `EnvConfig` defines runtime inputs and defaults.
- `CleanupTracker` owns resources created by the harness.
- `run_smoke_suite`, `run_scan_suite`, `run_crud_suite`, and
  `run_secinfo_suite` own their respective assertions.
- `run_differential_suite` and the `compare_*` helpers normalize and compare
  rust-gvm with python-gvm.
- The helpers near the end parse response IDs/elements, assert status, and
  produce stable log output.

## Harness modes and entry points

The installed Rust binary accepts:

```text
gvm-community-e2e --mode smoke
gvm-community-e2e --mode wait-ready
gvm-community-e2e --suite smoke
gvm-community-e2e --suite crud
gvm-community-e2e --suite secinfo
gvm-community-e2e --suite differential
gvm-community-e2e --suite all
```

No arguments currently means smoke mode. The main environment variables are:

- `GVM_ADMIN_USER` / `GVM_ADMIN_PASS` — defaults to `admin` / `admin`.
- `GVM_SOCKET_PATH` — defaults to `/run/gvmd/gvmd.sock`.
- `E2E_RUN_SCAN` — `1`, `true`, or `yes` enables the extended scan from smoke.
- `E2E_TASK_PROGRESS_TIMEOUT_SECS` — scan progress timeout; defaults to 90.
- `GVM_VERSION` — Compose runtime image tag; defaults to `stable`.

Use `docker compose -f docker/docker-compose.yml ...` from the repository root.
The `rust-gvm-e2e` service is behind the `runner` profile.

## Correctness rules for live mutations

1. Use unique, clearly E2E-owned names for created gvmd resources.
2. Track a returned resource ID in `CleanupTracker` immediately after a
   successful create response, before any later assertion can fail.
3. Delete dependants before dependencies. Tasks precede targets; attached
   resources must not strand their parents.
4. Keep normal cleanup explicit with `cleanup_now`; the `Drop` path is a safety
   net, not the primary success path.
5. Do not replay a mutation after an ambiguous transport failure. Reconnect and
   reconcile with a read when possible; blind retries can duplicate resources.
6. A test that accepts a backend limitation must identify the exact expected
   status/error. Do not turn arbitrary failures into skips or warnings.
7. Differential mismatches are currently diagnostic warnings by design. Do not
   silently promote or demote them without updating the coverage contract and
   docs.
8. Never run destructive cleanup against an unscoped/shared production gvmd.
   The harness assumes an isolated E2E stack.

When adding a new lifecycle, update the tracker with both storage and deletion
logic in the same change. A passing assertion with leaked state is a failed E2E
design.

## Readiness and persistent-state realities

Readiness has two distinct gates:

1. `docker/scripts/wait-ready.sh` probes gvmd over the Unix socket.
2. `gvm-community-e2e --mode wait-ready` authenticates and waits for usable
   feed-backed data such as scan configs.

Do not replace both with a container-health or socket-file check. A present
socket does not mean gvmd is responsive, and a responsive gvmd does not mean
the feed import is usable.

The self-hosted runner normally preserves named volumes. Consequences:

- A warm run is much faster than a clean bootstrap.
- `clean=true` destroys database and feed state and can take well over an hour
  before tests start. Use it when a clean-state claim is required or when
  switching incompatible GVM versions.
- Stale PostgreSQL recovery or leftover E2E resources can fail unchanged code.
  Inspect run provenance and service logs before blaming the tested revision.
- The Compose project and volumes are shared by repository-root invocations.
  Avoid concurrent manual runs against the same host/project.
- `docker compose down` preserves volumes. `docker/scripts/reset.sh` removes
  them and is deliberately destructive.

## Choosing the right validation

Start with cheap checks and escalate according to the changed surface.
Run independent checks separately so one known baseline failure does not hide
later results. If a target-branch check already fails before your change,
record the exact baseline failure and do not fold unrelated cleanup into a
scoped patch.

### Documentation only

```bash
git diff --check
```

Verify every referenced path and command against the current tree. Do not run a
multi-hour live matrix merely for prose unless the documentation makes a new
runtime claim that needs proof.

### Rust harness or dependency changes

```bash
cargo fmt --all -- --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

These checks prove compilation and static behavior only; they do not replace a
live gvmd run for protocol semantics.

### Shell changes

```bash
bash -n docker/scripts/*.sh tests/cli/*.sh
```

If ShellCheck is available, run it and assess findings rather than applying
mechanical rewrites that alter command/error semantics.

### Python diagnostics

```bash
python3 -m py_compile docker/scripts/*.py
```

Remove generated `__pycache__` directories before committing.

### Compose or workflow changes

```bash
docker compose -f docker/docker-compose.yml config --quiet
```

Review `.github/workflows/e2e.yml` path filters when adding or moving executable
files. A file outside `tests/**`, `docker/**`, or the workflow itself does not
currently trigger the pull-request E2E job.

### Live evidence

Use `workflow_dispatch` for the authoritative stack test and record:

- exact E2E commit;
- exact rust-gvm and gvm-rools refs;
- `GVM_VERSION`;
- `clean`, `run-scan`, differential, and gvm-tools settings;
- run URL and per-stage conclusions.

A green build-runner job proves only image construction. A green E2E job must
reach the intended suite; skipped stages are not coverage.

## Common traps

- Treating `spec/e2e-test-spec.md` as executable truth even when its paths or
  phase status differ from the current workflow.
- Changing only one of the four rust-gvm git dependencies.
- Updating `Cargo.toml` without reviewing `Cargo.lock` and Dockerfile ref
  rewriting.
- Assuming `get_version` success means feed-dependent fixtures are ready.
- Using `clean=true` as a casual retry; it discards expensive persistent state.
- Adding a create path without cleanup tracking and failure-path cleanup.
- Parsing XML with brittle global string matches when a typed rust-gvm response
  or scoped quick-xml traversal exists.
- Calling python-gvm the source of protocol truth. It is a differential oracle;
  authoritative gvmd behavior and schema still win when clients disagree.
- Reporting a transport or optional lane as covered when no corresponding test
  actually ran.
- Diagnosing self-hosted environment failures from aggregate status alone;
  inspect gvmd, PostgreSQL, scanner, and readiness logs.

## Change discipline

- Keep a change scoped to one behavior or operational concern.
- Update executable coverage and `docs/test-cases.md` together.
- Preserve stable `[pass]`, warning, and cleanup logs where automation or humans
  use them as evidence.
- Pin external GitHub Actions by immutable commit SHA.
- Do not commit credentials, runner addresses, tokens, live scan data, or
  unsanitized gvmd responses.
- Prefer exact revision evidence over statements such as "latest" or "current".
- Before pushing, rebase onto the target branch, resolve conflicts completely,
  and rerun the proportionate checks on the rebased tree.

When uncertain whether a failure belongs to rust-gvm or the Community stack,
run the matching check through
`docker/scripts/validate-against-gvm-tools.py`. If both clients fail, investigate
the stack first; if only rust-gvm fails, inspect its request/response contract.
