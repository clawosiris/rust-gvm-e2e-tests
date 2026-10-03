#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/deployment-lane-artifacts.sh"
source "${script_dir}/postgres-bootstrap.sh"

expected=$'acme-ci-devel-fast-runtime-images.json\nacme-ci-devel-fast-capability-snapshot.json\nacme-ci-devel-fast-deployment-contract.json\nacme-ci-devel-fast-test-plan.json\nacme-ci-devel-fast-test-results.json\nacme-ci-devel-fast-provider.log'
[[ "$(deployment_lane_artifact_paths acme-ci devel-fast)" == "${expected}" ]]

if deployment_lane_artifact_paths '../escape' devel-fast >/dev/null 2>&1; then
  echo "path traversal deployment id unexpectedly accepted" >&2
  exit 1
fi
if deployment_lane_artifact_paths acme-ci '../lane' >/dev/null 2>&1; then
  echo "path traversal lane unexpectedly accepted" >&2
  exit 1
fi

docker() { printf '%s\n' "$@" >> "${DEPLOYMENT_DOCKER_LOG}"; }
export DEPLOYMENT_DOCKER_LOG="$(mktemp)"
bootstrap_error_log="$(mktemp)"
trap 'rm -f -- "${DEPLOYMENT_DOCKER_LOG}" "${bootstrap_error_log}"' EXIT
mkdir -p artifacts
prepare_deployment_lane_artifacts runner:test acme-ci devel-fast
grep -Fqx -- 'runner:test' "${DEPLOYMENT_DOCKER_LOG}"
grep -Fqx -- '/workspace/artifacts/acme-ci-devel-fast-test-plan.json' "${DEPLOYMENT_DOCKER_LOG}"
if grep -Eq '\.\./|community-e2e-' "${DEPLOYMENT_DOCKER_LOG}"; then
  echo "deployment artifact cleanup escaped its exact namespace" >&2
  exit 1
fi

bootstrap_attempts=0
bootstrap_sleeps=()
deployment_compose() {
  bootstrap_attempts=$((bootstrap_attempts + 1))
  [[ "${bootstrap_attempts}" -ge 3 ]]
}
sleep() { bootstrap_sleeps+=("$1"); }
export E2E_POSTGRES_BOOTSTRAP_TIMEOUT_SECS=5
export E2E_POSTGRES_BOOTSTRAP_POLL_INTERVAL_SECS=2
wait_for_postgres_bootstrap
[[ "${bootstrap_attempts}" -eq 3 ]]
[[ "${bootstrap_sleeps[*]}" == "2 2" ]]

bootstrap_attempts=0
deployment_compose() {
  bootstrap_attempts=$((bootstrap_attempts + 1))
  return 1
}
if wait_for_postgres_bootstrap 2>"${bootstrap_error_log}"; then
  echo "PostgreSQL bootstrap unexpectedly succeeded" >&2
  exit 1
fi
[[ "${bootstrap_attempts}" -eq 3 ]]
grep -Fq 'did not become available for bootstrap tuning within 5s' "${bootstrap_error_log}"
