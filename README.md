# rust-gvm-e2e-tests

End-to-end integration tests for the [rust-gvm](https://github.com/clawosiris/rust-gvm) ecosystem — validating Rust GVM/OpenVAS tooling against a real Greenbone Community Edition container stack.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   rust-gvm-e2e-tests                     │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Layer 1       │  │ Layer 2       │  │ Validation    │  │
│  │ rust-gvm lib  │  │ gvm-rools CLI │  │ gvm-tools     │  │
│  │ (GMP socket)  │  │ (gvm-cli)     │  │ (cross-check) │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬────────┘  │
│         └────────┬────────┘                  │           │
│                  ▼                           ▼           │
│  ┌─────────────────────────────────────────────────────┐ │
│  │           GVM Community Stack (Docker Compose)       │ │
│  │  gvmd · ospd-openvas · openvasd · PostgreSQL · Redis │ │
│  │  + feed containers (VTs, SCAP, CERT, data-objects)   │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## What This Tests

This repo validates the **full stack** — from Rust client code through CLI tools down to a real gvmd instance with real feed data. It catches issues that unit tests and mock servers cannot:

- Feed-dependent behavior (scan configs only exist after feed sync)
- Server-side validation quirks (e.g., `PORT_LIST` required for `create_target`)
- Real PostgreSQL state management
- Scanner registration and scan execution
- Protocol compatibility with actual gvmd versions

## Test Suites

### Suite 1: Smoke Tests (rust-gvm library)
Core protocol validation via Unix socket connection to gvmd.

| Test | Description |
|------|-------------|
| 01 | Version negotiation (GMP 22.7+) |
| 02 | Authentication |
| 03 | List scan configs (feed-dependent) |
| 04 | List scanners |
| 05 | List report formats |
| 06 | List port lists |
| 07 | Create target (with port list) |
| 08 | Get target by UUID |
| 09 | Delete target |
| 10 | Verify deletion |

Extended (opt-in with `run-scan: true`):
- Create task with real scan config → start → poll → stop → get report

### Suite 2: CRUD Tests
Full create → get → delete → verify-absent lifecycle for:
- Port lists, Credentials, Schedules, Filters
- Tasks, Notes, Overrides, Tags, Alerts

### Suite 3: SecInfo Tests
Read-only queries against feed data:
- `get_feeds` — feed status
- `get_cves`, `get_cpes` — vulnerability data
- `get_cert_bund_advisories`, `get_dfn_cert_advisories` — CERT data
- `get_nvts` — vulnerability tests

### Suite 4: CLI Tests (gvm-rools)
Tests `gvm-cli` command-line tool end-to-end.

| Test | Description |
|------|-------------|
| 01 | `get_version` (unauthenticated) |
| 02 | Authenticated `get_scanners` |
| 03 | Pretty-print `get_scan_configs` |
| 04 | Create target via XML |
| 05 | Delete target |
| 06 | `--duration` timing output |
| 07 | Wrong password non-zero exit |
| 08 | `--raw` XML passthrough |
| 09 | Non-existent socket error |

### Validation: gvm-tools Cross-Check
By default, all test results are validated against python `gvm-tools` to ensure consistency between implementations. This runs on success (configurable) and always on failure for fault isolation.

## Running

### Manual (GitHub Actions)
Trigger via **workflow_dispatch** at [Actions → E2E Tests → Run workflow](../../actions/workflows/e2e.yml):

| Input | Default | Description |
|-------|---------|-------------|
| `rust-gvm-ref` | `main` | rust-gvm branch/tag/SHA to test |
| `gvm-rools-ref` | `main` | gvm-rools branch/tag/SHA to test |
| `run-scan` | `false` | Run extended scan test (~10min+) |
| `clean` | `false` | Destroy volumes for fresh environment |
| `validate-gvm-tools` | `true` | Cross-validate results with gvm-tools |

### Cross-Repo Triggering
Component repos can trigger E2E tests via `repository_dispatch`:

```bash
gh api repos/clawosiris/rust-gvm-e2e-tests/dispatches \
  -f event_type=component-updated \
  -f client_payload='{"component":"rust-gvm","ref":"my-branch"}'
```

## Infrastructure

### Self-Hosted Runner
Tests run on a permanent Hetzner VPS runner with Docker. Persistent volumes keep GVM feed data between runs:
- **Clean run** (`clean=true`): Full feed sync (~60-90 min)
- **Warm run** (`clean=false`): Reuses cached feed data (~13 min)

### Runner Image
A custom Docker image (`rust-gvm-e2e-runner`) is built in CI with:
- Pre-compiled `gvm-community-e2e` binary (Rust test harness)
- Pre-compiled `gvm-cli` from gvm-rools (CLI tests)
- `python-gvm` / `gvm-tools` for validation cross-checks

### GVM Community Stack
Standard Greenbone Community Edition containers:
- `gvmd` — vulnerability manager (core)
- `ospd-openvas` — scanner daemon
- `openvasd` — notus service
- `pg-gvm` — PostgreSQL backend
- `redis-server` — scanner KV store
- Feed containers — VTs, SCAP, CERT, data-objects, report-formats

## Repository Structure

```
rust-gvm-e2e-tests/
├── .github/workflows/
│   └── e2e.yml                 # CI workflow
├── docker/
│   ├── docker-compose.yml      # GVM Community stack
│   ├── Dockerfile.runner       # Test runner image
│   └── scripts/
│       ├── wait-ready.sh       # Stack readiness check
│       ├── run-smoke.sh        # Test orchestrator
│       └── validate-against-gvm-tools.py  # Cross-validation
├── tests/
│   ├── library/                # Rust test harness
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   └── cli/                    # CLI bash tests
│       └── smoke.sh
├── spec/
│   └── e2e-test-spec.md        # Design specification
├── journal/
│   └── *.md                    # Development journal
├── Cargo.toml                  # Workspace root
└── README.md
```

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **1** | ✅ Done | Library + CLI tests via Unix socket |
| **2** | 🔜 Planned | Multi-version GVM stack testing ([#16](../../issues/16)) |
| **3** | Planned | REST/gRPC API tests (rust-gvm-api) |
| **4** | Planned | MCP server tests (openvas-mcp-server) |

## License

AGPL-3.0-or-later
