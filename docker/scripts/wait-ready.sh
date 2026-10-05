#!/usr/bin/env bash
# Wait for gvmd readiness.
# Phase 1 (bash): Wait for gvmd to accept connections on socket (inside container)
# Phase 2 (bash): Wait for the VT data container, then allow OSPd to load the copied VTs
# Phase 3 (rust): Poll scan configs + SCAP/CERT databases via GMP (inside runner container)
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker/docker-compose.yml}"
SOCKET_PATH="/run/gvmd/gvmd.sock"
READINESS_TIMEOUT_SECS="${E2E_READINESS_TIMEOUT_SECS:-21000}"
SCANNER_SETTLE_SECS="${E2E_SCANNER_SETTLE_SECS:-60}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/scanner-readiness.sh"

IFS=':' read -r -a compose_files <<< "${COMPOSE_FILE}"
compose_args=()
for file in "${compose_files[@]}"; do compose_args+=(-f "${file}"); done
deployment_compose() { docker compose "${compose_args[@]}" "$@"; }

if ! [[ "${READINESS_TIMEOUT_SECS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: E2E_READINESS_TIMEOUT_SECS must be a positive integer" >&2
  exit 2
fi
if ! [[ "${SCANNER_SETTLE_SECS}" =~ ^[0-9]+$ ]]; then
  echo "ERROR: E2E_SCANNER_SETTLE_SECS must be a non-negative integer" >&2
  exit 2
fi

STARTED_AT=$(date +%s)
NEXT_STATUS_AT=60

echo "=== Waiting for gvmd to accept connections ==="
ready=false
while true; do
  elapsed=$(( $(date +%s) - STARTED_AT ))
  if (( elapsed >= READINESS_TIMEOUT_SECS )); then
    break
  fi
  # Check that gvmd is actually listening, not just that the socket file exists
  if deployment_compose exec -T gvmd \
      bash -c "echo '<get_version/>' | socat - UNIX-CONNECT:${SOCKET_PATH} 2>/dev/null | grep -q 'get_version_response'" 2>/dev/null; then
    echo "gvmd responding on socket after ${elapsed}s"
    ready=true
    break
  fi
  if (( elapsed >= NEXT_STATUS_AT )); then
    echo "Still waiting for gvmd... (${elapsed}s)"
    deployment_compose logs --tail=3 gvmd 2>&1 | tail -3 || true
    NEXT_STATUS_AT=$((elapsed + 60))
  fi
  sleep 1
done

if [ "$ready" != "true" ]; then
  echo "ERROR: gvmd did not respond within the ${READINESS_TIMEOUT_SECS}s readiness budget"
  deployment_compose logs --tail=20 gvmd 2>&1 || true
  deployment_compose logs --tail=10 pg-gvm 2>&1 || true
  exit 1
fi

elapsed=$(( $(date +%s) - STARTED_AT ))
remaining=$((READINESS_TIMEOUT_SECS - elapsed))
if (( remaining <= 0 )); then
  echo "ERROR: no readiness budget remains for feed validation" >&2
  exit 1
fi

echo "=== Waiting for vulnerability-test data copy ==="
wait_for_compose_service_health vulnerability-tests "$remaining" 5

elapsed=$(( $(date +%s) - STARTED_AT ))
remaining=$((READINESS_TIMEOUT_SECS - elapsed))
if (( remaining <= SCANNER_SETTLE_SECS )); then
  echo "ERROR: no readiness budget remains for scanner VT loading" >&2
  exit 1
fi
if (( SCANNER_SETTLE_SECS > 0 )); then
  echo "=== Allowing OSPd ${SCANNER_SETTLE_SECS}s to load copied vulnerability tests ==="
  sleep "${SCANNER_SETTLE_SECS}"
fi

elapsed=$(( $(date +%s) - STARTED_AT ))
remaining=$((READINESS_TIMEOUT_SECS - elapsed))
if (( remaining <= 0 )); then
  echo "ERROR: no readiness budget remains for feed validation" >&2
  exit 1
fi

echo "=== Running GMP readiness check via rust-gvm (polling for feed-backed data) ==="
echo "Feed readiness budget: ${remaining}s (${elapsed}s already used for deployment readiness)"
deployment_compose --profile runner run --no-deps --rm -T \
  --entrypoint "" \
  -e GVM_ADMIN_USER="${GVM_ADMIN_USER:-admin}" \
  -e GVM_ADMIN_PASS="${GVM_ADMIN_PASS:-admin}" \
  -e GVM_SOCKET_PATH="${GVM_SOCKET_PATH:-/run/gvmd/gvmd.sock}" \
  -e E2E_READINESS_TIMEOUT_SECS="$remaining" \
  rust-gvm-e2e \
  gvm-community-e2e --mode wait-ready

echo "=== gvmd and scanner are ready (VT copy settled; scan configs, SCAP, and CERT available) ==="
