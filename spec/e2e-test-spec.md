# E2E Test Suite — Specification

## Overview

A standalone integration test suite that validates the entire rust-gvm ecosystem against a real Greenbone Community Edition container stack. Tests all interface layers: library (GMP), CLI, REST API, gRPC API, and MCP server.

## Goals

1. **Validate protocol correctness** — rust-gvm speaks correct GMP against a real gvmd
2. **Validate CLI user experience** — gvm-rools commands work end-to-end
3. **Validate API layers** — REST and gRPC endpoints behave correctly
4. **Validate MCP integration** — openvas-mcp-server tools function against live infrastructure
5. **Catch regressions early** — triggered on PRs to any component repo
6. **Extensible** — new protocols and interfaces can be added without restructuring

## Infrastructure

### GVM Community Stack (Docker Compose)

Based on the official Greenbone Community Edition compose file, adapted for testing:

| Service | Image | Purpose |
|---------|-------|---------|
| gvmd | `community/gvmd:stable` | Core vulnerability manager |
| ospd-openvas | `community/ospd-openvas:stable` | Scanner daemon |
| openvasd | `community/openvas-scanner:stable` | Notus service mode |
| pg-gvm | `community/pg-gvm:stable` | PostgreSQL backend |
| redis-server | `community/redis-server` | Scanner KV store |
| gsad | `community/gsad:stable` | API gateway (optional) |
| Feed containers | Various | VTs, SCAP, CERT, data-objects, report-formats |

### Runner

A self-hosted GitHub Actions runner (Hetzner VPS) with:
- Docker / Docker Compose
- Persistent volumes (feed data survives between runs — delta sync ~2-3 min vs full sync ~20 min)
- Runner labels: `[self-hosted, docker]`

### Volume Strategy

- **Persistent between runs**: Feed data (VTs, SCAP, CERT), PostgreSQL data, scan configs
- **First run**: Full feed sync (~20 min)
- **Subsequent runs**: Delta sync only (~2-3 min)
- **Optional clean**: `clean: true` workflow input forces `docker compose down -v`

## Test Layers

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

### Layer 3: REST API Tests (rust-gvm-api)

Tests the REST API server against the GVM stack.

**Prerequisites:** Start `gvm-rest-api` server connected to gvmd socket.

**Tests:**
- `GET /health` — server health check
- `GET /api/v1/version` — GMP version
- `GET /api/v1/scan-configs` — list configs (paginated)
- `POST /api/v1/targets` → `GET` → `DELETE` — CRUD cycle
- `POST /api/v1/tasks` → start → stop → `GET` report — full scan lifecycle (extended)
- Authentication: JWT token flow, invalid token rejection
- Error responses: 400, 401, 404, 500 format validation

### Layer 4: gRPC API Tests (rust-gvm-api)

Tests the gRPC API server.

**Prerequisites:** Start `gvm-grpc-api` server connected to gvmd socket.

**Tests:**
- `SystemService.GetVersion` — health + version
- `TargetService.Create` → `Get` → `Delete` — CRUD
- `ScanConfigService.List` — streaming response
- `TaskService.Create` → `Start` → `WatchStatus` (server-streaming) → `Stop` (extended)
- Auth interceptor: valid/invalid JWT, mTLS (when configured)

### Layer 5: MCP Server Tests (openvas-mcp-server)

Tests the MCP server tools against the GVM stack.

**Prerequisites:** Start openvas-mcp-server connected to gvmd.

**Tests:**
- Tool discovery: list available tools
- `get_version` tool — basic connectivity
- `list_scan_configs` tool — feed data
- `create_target` → `delete_target` tool — write operations
- Error handling: invalid parameters, connection failures

## Differential Validation

For critical operations, cross-check rust-gvm results against python-gvm (gvm-tools):
- Same GMP command sent via both clients
- Response structure and content compared
- Differences flagged as potential compatibility issues

This is opt-in via `E2E_DIFFERENTIAL=1`.

## Workflow Design

```yaml
# Trigger: push/PR to any component repo, or manual dispatch
on:
  workflow_dispatch:
    inputs:
      rust-gvm-ref: { default: "main" }
      gvm-rools-ref: { default: "main" }
      rust-gvm-api-ref: { default: "main" }
      openvas-mcp-server-ref: { default: "main" }
      run-scan: { type: boolean, default: false }
      clean: { type: boolean, default: false }
      differential: { type: boolean, default: false }
  repository_dispatch:
    types: [component-updated]
```

### Job Structure

```
prepare:     Pull images, start GVM stack, wait for readiness
test-library: Layer 1 (rust-gvm)
test-cli:     Layer 2 (gvm-rools) — needs: prepare
test-rest:    Layer 3 (REST API) — needs: prepare
test-grpc:    Layer 4 (gRPC API) — needs: prepare
test-mcp:     Layer 5 (MCP server) — needs: prepare
report:       Collect results, post summary
cleanup:      Stop containers (keep volumes)
```

Layers 1-5 run in parallel after the stack is ready.

## Directory Structure

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
│   ├── cli/                      # Layer 2: gvm-rools tests
│   │   └── smoke.sh
│   ├── rest/                     # Layer 3: REST API tests
│   │   └── smoke.rs
│   ├── grpc/                     # Layer 4: gRPC API tests
│   │   └── smoke.rs
│   ├── mcp/                      # Layer 5: MCP server tests
│   │   └── smoke.py
│   └── differential/             # Cross-client validation
│       └── validate.py
├── .github/
│   └── workflows/
│       ├── e2e.yml               # Main E2E workflow (reusable)
│       └── e2e-trigger.yml       # Trigger on push/PR/dispatch
└── Cargo.toml                    # Workspace for Rust test binaries
```

## Cross-Repo Triggering

Component repos can trigger E2E tests via `repository_dispatch`:

```yaml
# In component repo CI (e.g., rust-gvm ci.yml):
- name: Trigger E2E tests
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  run: |
    gh api repos/clawosiris/rust-gvm-e2e-tests/dispatches \
      -f event_type=component-updated \
      -f client_payload='{"component":"rust-gvm","ref":"${{ github.sha }}"}'
```

## Version Coordination

- Default: test against `main` of each component
- Override: specify branch/tag/SHA per component via workflow inputs
- Release validation: test against release tags before publishing

## Failure Handling

- **Stack startup failure**: Collect container logs, report, skip tests
- **Individual test failure**: Continue other layers, collect all results
- **Feed sync timeout**: Configurable (default 150 min for cold start)
- **Flaky tests**: Mark with `#[ignore]` + re-run annotation; track in issues

## Migration Path

1. ✅ Create repo with spec (this document)
2. Move docker-compose.yml + scripts from rust-gvm `tests/e2e/gvm-community/`
3. Port Layer 1 tests (existing rust-gvm E2E binary)
4. Add Layer 2 tests (gvm-rools CLI)
5. Add cross-repo dispatch triggers to component repos
6. Remove E2E infrastructure from rust-gvm (keep as deprecated until migration verified)
7. Add Layers 3-5 as those components mature
