#!/usr/bin/env bash
# Wait for gvmd readiness.
# Phase 1 (bash): Wait for gvmd to accept connections on socket (inside container)
# Phase 2 (rust): Poll feeds + scan configs via GMP (inside runner container)
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker/docker-compose.yml}"
SOCKET_PATH="/run/gvmd/gvmd.sock"

echo "=== Waiting for gvmd to accept connections ==="
for i in $(seq 1 600); do
  # Check that gvmd is actually listening, not just that the socket file exists
  if docker compose -f "$COMPOSE_FILE" exec -T gvmd \
      bash -c "echo '<get_version/>' | socat - UNIX-CONNECT:${SOCKET_PATH} 2>/dev/null | grep -q 'get_version_response'" 2>/dev/null; then
    echo "gvmd responding on socket after ${i}s"
    break
  fi
  if (( i % 60 == 0 )); then
    echo "Still waiting for gvmd... (${i}s)"
    docker compose -f "$COMPOSE_FILE" logs --tail=3 gvmd 2>&1 | tail -3 || true
  fi
  sleep 1
done

echo "=== Running GMP readiness check via rust-gvm ==="
docker compose -f "$COMPOSE_FILE" --profile runner run --rm -T \
  --entrypoint "" \
  -e GVM_ADMIN_USER="${GVM_ADMIN_USER:-admin}" \
  -e GVM_ADMIN_PASS="${GVM_ADMIN_PASS:-admin}" \
  -e GVM_SOCKET_PATH="${GVM_SOCKET_PATH:-/run/gvmd/gvmd.sock}" \
  rust-gvm-e2e \
  gvm-community-e2e --mode wait-ready

echo "=== gvmd is ready ==="
