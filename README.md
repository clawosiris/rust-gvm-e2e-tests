# rust-gvm-e2e-tests

End-to-end integration tests for the rust-gvm ecosystem.

Validates the full stack — from Rust client library through CLI, REST/gRPC API, and MCP server — against a real Greenbone Community Edition container deployment.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                 rust-gvm-e2e-tests                   │
├──────────┬──────────┬──────────┬────────────────────┤
│ rust-gvm │gvm-rools │rust-gvm  │ openvas-mcp-server │
│ (library)│  (CLI)   │  -api    │      (MCP)         │
├──────────┴──────────┴──────────┴────────────────────┤
│              GVM Community Stack                     │
│     (gvmd + ospd-openvas + PostgreSQL + feeds)       │
└─────────────────────────────────────────────────────┘
```

## Status

- **Phase 1** (active): Library (rust-gvm) + CLI (gvm-rools) — migrated from rust-gvm repo with preserved git history
- **Phase 2** (planned): REST + gRPC API + SSH transport
- **Phase 3** (planned): MCP Server
- **Phase 4** (planned): Cross-client differential validation

## License

AGPL-3.0-or-later
