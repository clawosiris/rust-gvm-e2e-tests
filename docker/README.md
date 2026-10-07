# GVM deployment E2E harness

This harness runs the Rust GMP client against a real Greenbone Community container stack over the shared `gvmd.sock` Unix socket.

The compose file is based on the current Greenbone Community container docs at `https://greenbone.github.io/docs/latest/22.4/container/`, trimmed to the services needed for `gvmd`, feed data, `ospd-openvas`, and the optional `gsad` API frontend.

## Prerequisites

- Docker Engine
- Docker Compose v2 (`docker compose`)
- Enough local resources for the Greenbone stack. Greenbone documents 4 GB RAM / 20 GB disk as a minimum and recommends more for smoother runs.

## First run expectations

The first `docker compose up -d` is slow. The feed containers download and unpack vulnerability tests, SCAP data, CERT data, and report formats before `gvmd` becomes responsive. A clean SCAP/CPE aggregation can take hours; the coordinated readiness budget is 21,000 seconds.

Named volumes keep feed and database state between runs. Use
`docker compose -f docker/docker-compose.yml down` to preserve those caches.
`docker/scripts/reset.sh` removes everything and forces a clean bootstrap; do
not use it as a casual retry.

## Quick start

From the repository root, build the pinned runner and use the lane wrapper:

```bash
docker build -f docker/Dockerfile.runner \
  --build-arg RUST_GVM_SHA=3039246a1835954287ddbe5817f067addb4a059e \
  -t rust-gvm-e2e-runner:ci .
bash docker/scripts/run-deployment-lane.sh devel-fast
```

The wrapper starts and tunes PostgreSQL before gvmd, applies both socket and
authenticated feed readiness gates, and checkpoints before stopping the stack.

To test a different published GVM runtime image tag, set `GVM_VERSION` before pulling or starting the stack:

```bash
GVM_VERSION=edge docker compose -f docker/docker-compose.yml pull
GVM_VERSION=edge docker compose -f docker/docker-compose.yml up -d
```

The default is `stable`, which is the regular CI baseline. Non-default tags are compatibility targets and must be present for all runtime images (`gvmd`, `ospd-openvas`, `openvas-scanner`, `pg-gvm`, `redis-server`, `gpg-data`, and `gsad`). When switching between stack versions on the same host, remove the existing volumes first with `./scripts/reset.sh` or use a separate compose project to avoid mixing database/feed state across versions.

To stop the stack but keep cached feed data:

```bash
docker compose -f docker/docker-compose.yml down
```

To stop the stack and drop all named volumes:

```bash
docker/scripts/reset.sh
```

## Environment variables

- `GVM_ADMIN_USER`: GMP username. Default `admin`.
- `GVM_ADMIN_PASS`: GMP password. Default `admin`.
- `GVM_SOCKET_PATH`: Socket path inside the runner container. Default `/run/gvmd/gvmd.sock`.
- `E2E_READINESS_TIMEOUT_SECS`: Combined socket, scan-config, SCAP/CPE, and
  CERT readiness budget. Default `21000`.
- `E2E_READINESS_POLL_INTERVAL_SECS`: Authenticated feed poll interval.
  Default `30`.
- `E2E_READINESS_MAX_RECONNECTS`: Bounded connection-loss retries. Default
  `12`.
- `E2E_REPORT_EXPORT_TIMEOUT_SECS`: Bounded asynchronous report-export state
  reconciliation budget. Default `300`.
- `E2E_REPORT_EXPORT_POLL_INTERVAL_SECS`: Report-export state poll interval.
  Default `1`.
- `GVM_VERSION`: GVM runtime image tag. Default `stable`.
- `E2E_RUN_SCAN`: Set to `1` to run the slower scan lifecycle test in addition to the smoke checks.

## Rust binary

The harness is the `gvm-community-e2e` workspace binary:

```bash
cargo build --locked --bin gvm-community-e2e
cargo run --locked --bin gvm-community-e2e -- --mode smoke
cargo run --locked --bin gvm-community-e2e -- --mode wait-ready
```

## Troubleshooting

- If `wait-ready.sh` fails on socket detection, inspect the stack with `docker compose ps` and `docker compose logs gvmd pg-gvm ospd-openvas`.
- If the socket exists but `get_version` keeps failing, `gvmd` is usually still importing feed or waiting on PostgreSQL. Keep the data volumes and retry once the logs quiet down.
- If GMP authentication succeeds but scan configurations stay empty, confirm
  that `gvmd` started only after the `data-objects` and `report-formats`
  containers became healthy. The stock entrypoint performs the configuration
  import once; a `service_started` dependency can race the initial volume copy,
  and waiting longer inside the already-running `gvmd` does not rerun it.
- Keep `report-formats` gated on healthy `data-objects`, and `dfn-cert-data`
  gated on healthy `cert-bund-data`. Each pair writes one shared volume; the
  prerequisite initializer clears that mount before copying and can otherwise
  delete the dependent producer's readiness marker after it has been created.
- The SCAP producer copies roughly 10 GiB before creating its health marker.
  Keep its Compose start period long enough for that copy; the image default
  can mark it unhealthy after about two minutes even though the copy is still
  making progress.
- If `pg-gvm` repeatedly exits with `pg_ctl: server did not start in time`
  while an end-of-recovery checkpoint is active, stop the retry loop. The stock
  image's startup wait can interrupt the same recovery repeatedly; recover the
  volume with one uninterrupted PostgreSQL start or use an explicitly
  authorized clean bootstrap. Increasing the gvmd readiness timeout does not
  repair that state.
- If the extended scan flow fails quickly, confirm the container host permits raw socket capabilities for `ospd-openvas`.
- On harness failure, capture logs with:

```bash
docker compose logs gvmd ospd-openvas openvasd > e2e-failure.log
```
