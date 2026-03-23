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

🚧 Under construction — see [spec/e2e-test-spec.md](spec/e2e-test-spec.md) for the design.

## License

AGPL-3.0-or-later
