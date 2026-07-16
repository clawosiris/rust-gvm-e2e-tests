# E2E Test Suite — Specification

## Overview

A standalone integration test suite that validates the rust-gvm ecosystem against a real Greenbone Community Edition container stack. Developed in phases as components mature.

## Phases

| Phase | Layers | Components | Status |
|-------|--------|------------|--------|
| **1** | Library + CLI | rust-gvm, gvm-rools | 🔧 Active |
| **2** | REST + gRPC API | rust-gvm-api | Planned (when API is implemented) |
| **3** | MCP Server | openvas-mcp-server | Planned (when MCP is production-ready) |
| **4** | Cross-client validation | python-gvm differential | Planned |

---

## Phase 1: Library + CLI (Current Focus)

### Goals

1. **Validate protocol correctness** — rust-gvm speaks correct GMP against a real gvmd
2. **Validate CLI user experience** — gvm-rools commands work end-to-end
3. **Catch regressions early** — triggered on PRs to rust-gvm and gvm-rools
4. **Migrate existing E2E infra** from rust-gvm repo into this standalone repo

### Infrastructure

#### GVM Community Stack (Docker Compose)

Based on the official Greenbone Community Edition compose file, adapted for testing:

| Service | Image | Purpose |
|---------|-------|---------|
| gvmd | `community/gvmd:${GVM_VERSION:-stable}` | Core vulnerability manager |
| ospd-openvas | `community/ospd-openvas:${GVM_VERSION:-stable}` | Scanner daemon |
| openvasd | `community/openvas-scanner:${GVM_VERSION:-stable}` | Notus service mode |
| pg-gvm | `community/pg-gvm:${GVM_VERSION:-stable}` | PostgreSQL backend |
| redis-server | `community/redis-server:${GVM_VERSION:-stable}` | Scanner KV store |
| Feed containers | Various | VTs, SCAP, CERT, data-objects, report-formats |

#### Runner

A self-hosted GitHub Actions runner (Hetzner VPS) with:
- Docker / Docker Compose
- Persistent volumes (feed data survives between runs — delta sync ~2-3 min vs full sync ~20 min)
- Runner labels: `[self-hosted, docker]`

#### Volume Strategy

- **Persistent between runs**: Feed data (VTs, SCAP, CERT), PostgreSQL data, scan configs
- **First run**: Full feed sync (~20 min)
- **Subsequent runs**: Delta sync only (~2-3 min)
- **Optional clean**: `clean: true` workflow input forces `docker compose down -v`
- **Version selection**: `gvm-version` workflow input sets `GVM_VERSION` for runtime image tags and defaults to `stable`

### Layer 1: Library Tests (rust-gvm)

Tests the Rust GMP client library directly via Unix socket.

**Smoke tests (fast, always run):**
- Connect + authenticate
- `get_version` — verify GMP version negotiation
- `get_scan_configs` — confirm feed data loaded
- `get_scanners` — verify scanner registration
- `get_report_formats` — confirm report format availability
- `get_port_lists` — verify port list presence
- Create target → verify → delete (write path validation)
- Create/delete with all supported entity types

**Extended tests (opt-in via `E2E_RUN_SCAN=1`):**
- Create target + task with real scan config
- Start task, poll status, stop task
- Retrieve report, verify structure
- Cleanup all created resources

**Readiness checks:**
- Phase 1 (bash): Wait for gvmd socket to accept connections (socat probe)
- Phase 2 (rust-gvm): Poll `get_version` + `authenticate` until success
- Phase 3 (rust-gvm): Poll `get_scan_configs` until ≥1 config available (feed sync complete)

### Layer 2: CLI Tests (gvm-rools)

Tests the `gvm-cli` command-line tool against the same stack.

**Tests:**
- `gvm-cli socket --xml '<get_version/>'` — basic connectivity
- `gvm-cli socket --gmp-username admin --gmp-password admin --xml '<get_scanners/>'` — authenticated request
- `gvm-cli socket --pretty --xml '<get_scan_configs/>'` — output formatting
- Create/delete target via CLI XML
- Error handling: invalid XML, wrong credentials, non-existent socket

### Workflow Design (Phase 1)

```yaml
on:
  workflow_dispatch:
    inputs:
      rust-gvm-ref: { default: "main" }
      gvm-rools-ref: { default: "main" }
      run-scan: { type: boolean, default: false }
      clean: { type: boolean, default: false }
  repository_dispatch:
    types: [component-updated]
```

#### Job Structure

```
prepare:       Pull images, start GVM stack, wait for readiness
test-library:  Layer 1 (rust-gvm) — needs: prepare
test-cli:      Layer 2 (gvm-rools) — needs: prepare
cleanup:       Stop containers (keep volumes) — always
```

Layers 1 and 2 run in parallel after the stack is ready.

### Directory Structure (Phase 1)

```
rust-gvm-e2e-tests/
├── README.md
├── spec/
│   └── e2e-test-spec.md          # This document
├── docker/
│   ├── docker-compose.yml        # GVM Community stack
│   ├── Dockerfile.runner         # Test runner image
│   └── scripts/
│       ├── wait-ready.sh         # Stack readiness check
│       └── cleanup.sh            # Post-test cleanup
├── tests/
│   ├── library/                  # Layer 1: rust-gvm tests
│   │   └── smoke.rs
│   └── cli/                      # Layer 2: gvm-rools tests
│       └── smoke.sh
├── .github/
│   └── workflows/
│       ├── e2e.yml               # Main E2E workflow (reusable)
│       └── e2e-trigger.yml       # Trigger on push/PR/dispatch
└── Cargo.toml                    # Workspace for Rust test binaries
```

### Cross-Repo Triggering (Phase 1)

Component repos trigger E2E tests via `repository_dispatch`:

```yaml
# In rust-gvm or gvm-rools CI:
- name: Trigger E2E tests
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  run: |
    gh api repos/clawosiris/rust-gvm-e2e-tests/dispatches \
      -f event_type=component-updated \
      -f client_payload='{"component":"rust-gvm","ref":"${{ github.sha }}"}'
```

### Migration Path

1. ✅ Create repo with spec (this document)
2. Move docker-compose.yml + scripts from rust-gvm `tests/e2e/gvm-community/`
3. Port Layer 1 tests (existing rust-gvm E2E binary)
4. Add Layer 2 tests (gvm-rools CLI)
5. Add cross-repo dispatch triggers to rust-gvm and gvm-rools
6. Remove E2E infrastructure from rust-gvm (keep as deprecated until migration verified)

---

## Phase 2: REST + gRPC API (Future)

*To be specified when rust-gvm-api implementation reaches Phase 2+.*

### Transport expansion (include SSH)

Once Phase 1 is stable on the Unix-socket path, extend validation to GMP-over-SSH:

- Connect via SSH tunnel to gvmd socket (`direct-streamlocal@openssh.com`)
- Authenticate + `get_version` over SSH
- CRUD target over SSH
- Validate both SSH agent auth and password auth paths
- Error handling: wrong host key, invalid credentials, unreachable host

Infrastructure note: add an SSH sidecar container (or enable SSH access) that exposes the gvmd Unix socket for port-forwarding.

### Layer 3: REST API Tests

- Health check, version, CRUD cycles
- Authentication (JWT + API keys)
- Pagination, filtering, error responses
- OpenAPI spec compliance validation

### Layer 4: gRPC API Tests

- Unary RPCs: version, CRUD
- Server-streaming: `WatchTaskStatus`, `StreamReportResults`
- Auth interceptor validation
- Proto contract testing

### Additional Infrastructure

- Start `gvm-rest-api` and `gvm-grpc-api` servers as additional services in docker-compose
- Both connect to gvmd via shared socket volume

---

## Phase 3: MCP Server (Future)

*To be specified when openvas-mcp-server is production-ready.*

### Layer 5: MCP Server Tests

- Tool discovery and schema validation
- GVM operations via MCP tool calls
- Error propagation and handling

---

## Phase 4: Cross-Client Validation (Future)

*Optional differential testing.*

- Same GMP command sent via rust-gvm and python-gvm (gvm-tools)
- Response structure and content compared
- Differences flagged as potential compatibility issues
- Opt-in via `E2E_DIFFERENTIAL=1`

---

## Failure Handling (All Phases)

- **Stack startup failure**: Collect container logs, report, skip tests
- **Individual test failure**: Continue other layers, collect all results
- **Feed sync timeout**: Configurable (default 150 min for cold start)
- **Flaky tests**: Mark with `#[ignore]` + re-run annotation; track in issues

## Version Coordination

- Default: test against `main` of each component
- Override: specify branch/tag/SHA per component via workflow inputs
- Release validation: test against release tags before publishing
