# rust-gvm-e2e-tests

End-to-end integration tests for the [rust-gvm](https://github.com/clawosiris/rust-gvm) ecosystem — validating Rust GVM/OpenVAS tooling against a real Greenbone Community Edition container stack.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   rust-gvm-e2e-tests                     │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Layer 1       │  │ Layer 2       │  │ Diagnostic    │  │
│  │ rust-gvm lib  │  │ gvm-rools CLI │  │ python-gvm    │  │
│  │ (GMP socket)  │  │ (gvm-cli)     │  │ (fault isol.) │  │
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

## Test Layers

### Layer 1: Library Tests (rust-gvm)
Tests the Rust GMP client library directly via Unix socket connection to gvmd.

| Test | Description |
|------|-------------|
| 01 | Version negotiation (GMP 22.7) |
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

### Layer 2: CLI Tests (gvm-rools)
Tests `gvm-cli` command-line tool end-to-end.

| Test | Description |
|------|-------------|
| 01 | `get_version` (unauthenticated) |
| 02 | Authenticated `get_scanners` |
| 03 | Pretty-print `get_scan_configs` |
| 04 | Create target via XML |
| 05 | Delete target |

### Diagnostic: gvm-tools Cross-Check
When tests fail, automatically re-runs the same GMP queries via python `gvm-tools` to isolate whether the failure is in rust-gvm or in the GVM stack itself.

## Running

### Manual (GitHub Actions)
Trigger via **workflow_dispatch** at [Actions → E2E Tests → Run workflow](../../actions/workflows/e2e.yml):

| Input | Default | Description |
|-------|---------|-------------|
| `rust-gvm-ref` | `main` | rust-gvm branch/tag/SHA to test |
| `gvm-rools-ref` | `main` | gvm-rools branch/tag/SHA to test |
| `run-scan` | `false` | Run extended scan test (~10min+) |
| `clean` | `false` | Destroy volumes for fresh environment |

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
- **First run**: Full feed sync (~20 min)
- **Subsequent runs**: Delta sync only (~2-3 min)

### Runner Image
A custom Docker image (`rust-gvm-e2e-runner`) is built in CI with:
- Pre-compiled `gvm-community-e2e` binary (Layer 1 tests)
- Pre-compiled `gvm-cli` from gvm-rools (Layer 2 tests)
- `python-gvm` for diagnostic cross-checks

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
│       └── validate-against-gvm-tools.py  # Diagnostic fallback
├── tests/
│   ├── library/                # Layer 1: rust-gvm binary crate
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   └── cli/                    # Layer 2: gvm-rools bash tests
│       └── smoke.sh
├── spec/
│   └── e2e-test-spec.md        # Design specification
├── journal/
│   └── 2026-03-23.md           # Development journal
├── Cargo.toml                  # Workspace root
└── README.md
```

## Phased Roadmap

| Phase | Status | What |
|-------|--------|------|
| **1** | ✅ Active | Library (rust-gvm) + CLI (gvm-rools) via Unix socket |
| **2** | Planned | REST/gRPC API (rust-gvm-api) + SSH transport |
| **3** | Planned | MCP server (openvas-mcp-server) |
| **4** | Planned | Cross-client differential validation (rust-gvm vs python-gvm) |

## History

This repo was extracted from [`clawosiris/rust-gvm`](https://github.com/clawosiris/rust-gvm) using `git-filter-repo` to preserve commit history. See [journal/2026-03-23.md](journal/2026-03-23.md) for the full migration story.

## License

AGPL-3.0-or-later
