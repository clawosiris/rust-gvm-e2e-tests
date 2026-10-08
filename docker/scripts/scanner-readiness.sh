#!/usr/bin/env bash

wait_for_compose_service_health() {
  local service="${1:?service name is required}"
  local timeout_secs="${2:?timeout is required}"
  local poll_interval_secs="${3:-5}"
  local started_at elapsed container_id health_status

  [[ "${timeout_secs}" =~ ^[1-9][0-9]*$ ]] || {
    echo "ERROR: service health timeout must be a positive integer" >&2
    return 2
  }
  [[ "${poll_interval_secs}" =~ ^[1-9][0-9]*$ ]] || {
    echo "ERROR: service health poll interval must be a positive integer" >&2
    return 2
  }

  started_at=$(date +%s)
  while true; do
    elapsed=$(( $(date +%s) - started_at ))
    if (( elapsed >= timeout_secs )); then
      echo "ERROR: ${service} did not become healthy within ${timeout_secs}s" >&2
      return 1
    fi

    container_id="$(deployment_compose ps -q "${service}" 2>/dev/null || true)"
    health_status=""
    if [[ -n "${container_id}" ]]; then
      health_status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "${container_id}" 2>/dev/null || true)"
    fi
    if [[ "${health_status}" == "healthy" ]]; then
      echo "${service} container health is ready after ${elapsed}s"
      return 0
    fi

    sleep "${poll_interval_secs}"
  done
}
