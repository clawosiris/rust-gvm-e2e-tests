#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/deployment-lane-artifacts.sh"
source "${script_dir}/postgres-bootstrap.sh"

lane="${1:?usage: run-deployment-lane.sh <lane>}"
validate_deployment_lane "${lane}"
provider="${E2E_PROVIDER_MODE:-compose}"
deployment_id="${E2E_DEPLOYMENT_ID:-community-stable}"
contract="${E2E_DEPLOYMENT_CONTRACT:-contracts/community-stable.json}"
fixtures="${E2E_FIXTURE_DESCRIPTOR:-fixtures/community-provider.json}"
runner_image="${RUNNER_IMAGE_NAME:-rust-gvm-e2e-runner}:${RUNNER_IMAGE_TAG:-ci}"
validate_deployment_id "${deployment_id}"

image_rust_gvm_sha="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "${runner_image}")"
[[ "${image_rust_gvm_sha}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "runner image has no exact rust-gvm revision label" >&2
  exit 1
}
if [[ -n "${E2E_RUST_GVM_SHA:-}" && "${E2E_RUST_GVM_SHA}" != "${image_rust_gvm_sha}" ]]; then
  echo "runner image rust-gvm revision does not match E2E_RUST_GVM_SHA" >&2
  exit 1
fi
export E2E_RUST_GVM_SHA="${image_rust_gvm_sha}"

provider_args=(--contract "${contract}" --fixtures "${fixtures}" --provider "${provider}")
if [[ "${provider}" == "external" ]]; then
  provider_descriptor="${E2E_PROVIDER_DESCRIPTOR:?external provider requires E2E_PROVIDER_DESCRIPTOR}"
  provider_args+=(--provider-descriptor "${provider_descriptor}")
elif [[ "${provider}" != "compose" ]]; then
  echo "unsupported E2E_PROVIDER_MODE: ${provider}" >&2
  exit 2
fi
python3 tools/deployment_provider.py "${provider_args[@]}"

export E2E_RUN_ID="${E2E_RUN_ID:-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-${deployment_id}-${lane}}"
export E2E_DEPLOYMENT_ID="${deployment_id}"
export E2E_DEPLOYMENT_CONTRACT_PATH="/workspace/${contract}"
export E2E_FIXTURE_DESCRIPTOR_PATH="/workspace/${fixtures}"
export E2E_RESULTS_PATH="/workspace/artifacts/${deployment_id}-${lane}-test-results.json"
export E2E_CAPABILITY_SNAPSHOT_PATH="/workspace/artifacts/${deployment_id}-${lane}-capability-snapshot.json"
export E2E_TEST_PLAN_PATH="/workspace/artifacts/${deployment_id}-${lane}-test-plan.json"
export E2E_CONTRACT_ARTIFACT_PATH="/workspace/artifacts/${deployment_id}-${lane}-deployment-contract.json"
export E2E_RUNTIME_IMAGES_PATH="/workspace/artifacts/${deployment_id}-${lane}-runtime-images.json"
export E2E_SCAN_TARGET_HOST="${E2E_SCAN_TARGET_HOST:-scan-fixture}"
export E2E_TASK_PROGRESS_TIMEOUT_SECS="${E2E_TASK_PROGRESS_TIMEOUT_SECS:-900}"
export E2E_READINESS_TIMEOUT_SECS="${E2E_READINESS_TIMEOUT_SECS:-21000}"
[[ -n "${E2E_SCAN_TARGET_HOST}" ]] || { echo "E2E_SCAN_TARGET_HOST must not be empty" >&2; exit 2; }
for timeout in E2E_TASK_PROGRESS_TIMEOUT_SECS E2E_READINESS_TIMEOUT_SECS; do
  [[ "${!timeout}" =~ ^[1-9][0-9]*$ ]] || { echo "${timeout} must be a positive integer" >&2; exit 2; }
done

mkdir -p artifacts
prepare_deployment_lane_artifacts "${runner_image}" "${deployment_id}" "${lane}"

if [[ "${provider}" == "external" ]]; then
  socket_path="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["transport"]["socket_path"])' "${provider_descriptor}")"
  runtime_images_path="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["runtime_images_path"])' "${provider_descriptor}")"
  [[ -S "${socket_path}" ]] || { echo "external gvmd socket is not a socket: ${socket_path}" >&2; exit 1; }
  [[ -f "${runtime_images_path}" ]] || { echo "external runtime image descriptor is missing: ${runtime_images_path}" >&2; exit 1; }
  cp "${runtime_images_path}" "artifacts/${deployment_id}-${lane}-runtime-images.json"
  external_run=(docker run --rm \
    --mount "type=bind,src=$(pwd),dst=/workspace" \
    --mount "type=bind,src=${socket_path},dst=/run/external-gvmd/gvmd.sock,readonly" \
    -e GVM_ADMIN_USER -e GVM_ADMIN_PASS -e E2E_RUN_ID -e E2E_DEPLOYMENT_ID \
    -e E2E_DEPLOYMENT_CONTRACT_PATH -e E2E_FIXTURE_DESCRIPTOR_PATH -e E2E_RESULTS_PATH \
    -e E2E_CAPABILITY_SNAPSHOT_PATH -e E2E_TEST_PLAN_PATH -e E2E_CONTRACT_ARTIFACT_PATH \
    -e E2E_RUNTIME_IMAGES_PATH -e E2E_RUST_GVM_SHA -e E2E_TASK_PROGRESS_TIMEOUT_SECS \
    -e E2E_READINESS_TIMEOUT_SECS -e E2E_READINESS_POLL_INTERVAL_SECS \
    -e E2E_READINESS_MAX_RECONNECTS -e E2E_SCAN_TARGET_HOST -e E2E_OCI_IMAGE_REFERENCE \
    -e GVM_SOCKET_PATH=/run/external-gvmd/gvmd.sock \
    --entrypoint gvm-community-e2e "${runner_image}")
  "${external_run[@]}" --mode wait-ready
  "${external_run[@]}" --lane "${lane}"
  exit 0
fi

compose_file="${COMPOSE_FILE:-docker/docker-compose.yml}"
IFS=':' read -r -a compose_files <<< "${compose_file}"
compose_args=()
for file in "${compose_files[@]}"; do compose_args+=(-f "${file}"); done
deployment_compose() { docker compose --project-directory "$(pwd)" "${compose_args[@]}" "$@"; }
if [[ "${lane}" == "devel-isolated" ]]; then
  export COMPOSE_PROJECT_NAME="${E2E_ISOLATED_PROJECT:-rust-gvm-e2e-isolated}"
  export E2E_ISOLATED=1
else
  export COMPOSE_PROJECT_NAME="${E2E_COMPOSE_PROJECT:-rust-gvm-e2e}"
fi

quiesce_and_checkpoint() {
  if ! deployment_compose stop --timeout 120 gsad openvasd ospd-openvas gvmd; then
    echo "Graceful writer shutdown failed; forcing only non-database services" >&2
    deployment_compose kill gsad openvasd ospd-openvas gvmd || true
  fi
  if [[ -n "$(deployment_compose ps --status running --quiet pg-gvm)" ]]; then
    deployment_compose exec -T --user postgres pg-gvm \
      psql --host=/var/run/postgresql --dbname=postgres --no-psqlrc -v ON_ERROR_STOP=1 -c 'CHECKPOINT;' || true
  fi
}

cleanup() {
  status=$?
  if [[ "${status}" -ne 0 ]]; then
    deployment_compose logs --no-color > "artifacts/${deployment_id}-${lane}-provider.log" 2>&1 || true
  fi
  quiesce_and_checkpoint
  deployment_compose stop --timeout 300 pg-gvm || true
  deployment_compose down --timeout 60 || true
  return "${status}"
}
trap cleanup EXIT

if [[ "${E2E_CLEAN_VOLUMES:-0}" == "1" ]]; then deployment_compose down -v; fi
deployment_compose pull
deployment_compose up -d pg-gvm
wait_for_postgres_bootstrap
deployment_compose up -d
bash docker/scripts/wait-ready.sh
runtime_image_args=()
for file in "${compose_files[@]}"; do runtime_image_args+=(--compose-file "${file}"); done
python3 tools/runtime_images.py "${runtime_image_args[@]}" --project-directory "$(pwd)" \
  --output "artifacts/${deployment_id}-${lane}-runtime-images.json"
deployment_compose --profile runner run --rm -T --no-deps --entrypoint "" rust-gvm-e2e \
  gvm-community-e2e --lane "${lane}"
if [[ "${lane}" == "devel-fast" ]]; then
  deployment_compose --profile runner run --rm -T --no-deps --entrypoint "" rust-gvm-e2e \
    bash /workspace/tests/cli/smoke.sh
fi
if [[ "${lane}" == "differential" ]]; then
  deployment_compose --profile runner run --rm -T --no-deps --entrypoint "" rust-gvm-e2e \
    python3 /workspace/docker/scripts/validate-against-gvm-tools.py --check all
fi
