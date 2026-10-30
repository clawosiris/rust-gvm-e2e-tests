#!/usr/bin/env bash

# Containers whose only runtime responsibility is to materialize a feed volume.
# They remain stopped after their health markers prove that the mounted snapshot
# is complete, preventing a later image refresh from changing that snapshot.
readonly -a FEED_MATERIALIZER_SERVICES=(
  vulnerability-tests
  notus-data
  scap-data
  cert-bund-data
  dfn-cert-data
  data-objects
  report-formats
  gpg-data
)

# Runtime services that must remain up while the immutable snapshot is used.
readonly -a FEED_SNAPSHOT_CONSUMER_SERVICES=(
  redis-server
  pg-gvm
  gvmd
  openvasd
  ospd-openvas
  gsad
  scan-fixture
)

remaining_feed_snapshot_budget() {
  local deadline_epoch="${1:?deadline epoch is required}"
  local remaining

  [[ "${deadline_epoch}" =~ ^[1-9][0-9]*$ ]] || {
    echo "ERROR: feed snapshot deadline must be a positive epoch" >&2
    return 2
  }
  remaining=$((deadline_epoch - $(date +%s)))
  if (( remaining <= 0 )); then
    echo "ERROR: no readiness budget remains for feed snapshot materialization" >&2
    return 1
  fi
  printf '%s\n' "${remaining}"
}

read_feed_materializer_state() {
  local service="${1:?service name is required}"
  local container_id

  container_id="$(deployment_compose ps --all --quiet "${service}" 2>/dev/null || true)"
  if [[ -z "${container_id}" ]]; then
    printf 'missing|0|missing\n'
    return 0
  fi
  docker inspect --format \
    '{{.State.Status}}|{{.State.ExitCode}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
    "${container_id}" 2>/dev/null || printf 'missing|0|missing\n'
}

wait_for_feed_materializer_completion() {
  local service="${1:?service name is required}"
  local timeout_secs="${2:?timeout is required}"
  local poll_interval_secs="${3:-5}"
  local started_at elapsed state runtime_status exit_code health_status

  [[ "${timeout_secs}" =~ ^[1-9][0-9]*$ ]] || {
    echo "ERROR: materializer timeout must be a positive integer" >&2
    return 2
  }
  [[ "${poll_interval_secs}" =~ ^[1-9][0-9]*$ ]] || {
    echo "ERROR: materializer poll interval must be a positive integer" >&2
    return 2
  }

  started_at=$(date +%s)
  while true; do
    elapsed=$(( $(date +%s) - started_at ))
    if (( elapsed >= timeout_secs )); then
      echo "ERROR: ${service} did not finish materializing within ${timeout_secs}s" >&2
      return 1
    fi

    state="$(read_feed_materializer_state "${service}")"
    IFS='|' read -r runtime_status exit_code health_status <<< "${state}"
    if [[ "${health_status}" == "healthy" ]]; then
      echo "${service} materializer is healthy after ${elapsed}s"
      return 0
    fi
    if [[ "${runtime_status}" == "exited" && "${exit_code}" == "0" ]]; then
      echo "${service} materializer completed successfully after ${elapsed}s"
      return 0
    fi
    if [[ "${runtime_status}" == "exited" ]]; then
      echo "ERROR: ${service} materializer exited with status ${exit_code}" >&2
      return 1
    fi

    sleep "${poll_interval_secs}"
  done
}

require_snapshot_service_running() {
  local service="${1:?service name is required}"
  local container_id

  container_id="$(deployment_compose ps --status running --quiet "${service}" 2>/dev/null || true)"
  if [[ -z "${container_id}" ]]; then
    echo "ERROR: feed snapshot consumer ${service} is not running" >&2
    return 1
  fi
}

freeze_feed_snapshot() {
  local deadline_epoch="${1:?deadline epoch is required}"
  local poll_interval_secs="${2:-5}"
  local service remaining running_id

  echo "=== Waiting for complete feed-volume materialization ==="
  for service in "${FEED_MATERIALIZER_SERVICES[@]}"; do
    remaining="$(remaining_feed_snapshot_budget "${deadline_epoch}")"
    wait_for_feed_materializer_completion "${service}" "${remaining}" "${poll_interval_secs}"
  done

  echo "=== Verifying runtime consumers before freezing the feed snapshot ==="
  for service in "${FEED_SNAPSHOT_CONSUMER_SERVICES[@]}"; do
    require_snapshot_service_running "${service}"
  done

  echo "=== Freezing immutable feed snapshot (materializers only) ==="
  # Materializers are idle after their completion markers are present. Keep
  # this grace period short because Compose applies it per service.
  deployment_compose stop --timeout 10 "${FEED_MATERIALIZER_SERVICES[@]}"

  for service in "${FEED_MATERIALIZER_SERVICES[@]}"; do
    running_id="$(deployment_compose ps --status running --quiet "${service}" 2>/dev/null || true)"
    if [[ -n "${running_id}" ]]; then
      echo "ERROR: feed materializer ${service} remained running after snapshot freeze" >&2
      return 1
    fi
  done
  for service in "${FEED_SNAPSHOT_CONSUMER_SERVICES[@]}"; do
    require_snapshot_service_running "${service}"
  done

  echo "Feed snapshot frozen; all runtime consumers remain running"
}
