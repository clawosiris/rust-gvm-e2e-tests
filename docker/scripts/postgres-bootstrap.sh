#!/usr/bin/env bash

wait_for_postgres_bootstrap() {
  local timeout_secs="${E2E_POSTGRES_BOOTSTRAP_TIMEOUT_SECS:-600}"
  local poll_interval_secs="${E2E_POSTGRES_BOOTSTRAP_POLL_INTERVAL_SECS:-2}"
  local max_attempts attempt

  [[ "${timeout_secs}" =~ ^[1-9][0-9]*$ ]] || {
    echo "E2E_POSTGRES_BOOTSTRAP_TIMEOUT_SECS must be a positive integer" >&2
    return 2
  }
  [[ "${poll_interval_secs}" =~ ^[1-9][0-9]*$ ]] || {
    echo "E2E_POSTGRES_BOOTSTRAP_POLL_INTERVAL_SECS must be a positive integer" >&2
    return 2
  }

  max_attempts=$(((timeout_secs + poll_interval_secs - 1) / poll_interval_secs))
  echo "Waiting up to ${timeout_secs}s for PostgreSQL recovery and bootstrap tuning"

  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    if deployment_compose exec -T --user postgres pg-gvm \
        psql --host=/var/run/postgresql --dbname=postgres --no-psqlrc -v ON_ERROR_STOP=1 \
        -c "ALTER SYSTEM SET max_wal_size = '16GB';" \
        -c "ALTER SYSTEM SET checkpoint_timeout = '30min';" \
        -c "SELECT pg_reload_conf();" >/dev/null 2>&1; then
      echo "PostgreSQL recovery completed and bootstrap tuning applied"
      return 0
    fi

    if [[ "${attempt}" -lt "${max_attempts}" ]]; then
      sleep "${poll_interval_secs}"
    fi
  done

  echo "PostgreSQL did not become available for bootstrap tuning within ${timeout_secs}s" >&2
  return 1
}
