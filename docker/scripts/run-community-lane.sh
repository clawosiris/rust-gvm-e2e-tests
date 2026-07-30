#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/community-lane-artifacts.sh"

lane="${1:?usage: run-community-lane.sh <devel-fast|devel-scan|devel-isolated|devel-transport|differential>}"
validate_community_lane "${lane}"

compose_file="${COMPOSE_FILE:-docker/docker-compose.yml}"
if [[ "${lane}" == "devel-isolated" ]]; then
  export COMPOSE_PROJECT_NAME="${E2E_ISOLATED_PROJECT:-rust-gvm-e2e-isolated}"
  export E2E_ISOLATED=1
else
  export COMPOSE_PROJECT_NAME="${E2E_COMMUNITY_PROJECT:-rust-gvm-e2e}"
fi

export E2E_RUN_ID="${E2E_RUN_ID:-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-${lane}}"
export E2E_RESULTS_PATH="/workspace/artifacts/community-e2e-${lane}.json"
export E2E_RUNTIME_IMAGES_PATH="/workspace/artifacts/runtime-images-${lane}.json"
export E2E_SCAN_TARGET_HOST="${E2E_SCAN_TARGET_HOST:-scan-fixture}"
export E2E_TASK_PROGRESS_TIMEOUT_SECS="${E2E_TASK_PROGRESS_TIMEOUT_SECS:-900}"

mkdir -p artifacts
# This runs in the already-loaded runner image as root so stale root-owned
# selected-lane artifacts cannot block the host-side writers below.
prepare_community_lane_artifacts "${compose_file}" "${lane}"

cleanup() {
  status=$?
  if [[ "${status}" -ne 0 ]]; then
    docker compose -f "${compose_file}" logs --no-color \
      > "artifacts/community-e2e-${lane}-compose.log" 2>&1 || true
  fi
  docker compose -f "${compose_file}" down
  return "${status}"
}
trap cleanup EXIT

if [[ "${E2E_CLEAN_VOLUMES:-0}" == "1" ]]; then
  docker compose -f "${compose_file}" down -v
fi

docker compose -f "${compose_file}" pull
docker compose -f "${compose_file}" up -d
bash docker/scripts/wait-ready.sh
python3 tools/runtime_images.py \
  --compose-file "${compose_file}" \
  --output "artifacts/runtime-images-${lane}.json"

docker compose -f "${compose_file}" --profile runner run --rm -T \
  --entrypoint "" rust-gvm-e2e \
  gvm-community-e2e --lane "${lane}"

if [[ "${lane}" == "devel-fast" ]]; then
  docker compose -f "${compose_file}" --profile runner run --rm -T \
    --entrypoint "" rust-gvm-e2e \
    bash /workspace/tests/cli/smoke.sh
fi

if [[ "${lane}" == "differential" ]]; then
  docker compose -f "${compose_file}" --profile runner run --rm -T \
    --entrypoint "" rust-gvm-e2e \
    python3 /workspace/docker/scripts/validate-against-gvm-tools.py --check all
fi
