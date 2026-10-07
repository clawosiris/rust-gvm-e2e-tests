#!/usr/bin/env bash
set -euo pipefail

validate_deployment_id() {
  [[ "${1:?deployment id is required}" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || {
    echo "invalid deployment id: $1" >&2
    return 2
  }
}

validate_deployment_lane() {
  case "${1:?lane is required}" in
    devel-fast|devel-scan|devel-isolated|devel-transport|differential) ;;
    *) echo "unsupported deployment lane: ${1}" >&2; return 2 ;;
  esac
}

deployment_lane_artifact_paths() {
  local deployment_id="${1:?deployment id is required}"
  local lane="${2:?lane is required}"
  validate_deployment_id "${deployment_id}" || return $?
  validate_deployment_lane "${lane}" || return $?
  printf '%s\n' \
    "${deployment_id}-${lane}-runtime-images.json" \
    "${deployment_id}-${lane}-capability-snapshot.json" \
    "${deployment_id}-${lane}-deployment-contract.json" \
    "${deployment_id}-${lane}-test-plan.json" \
    "${deployment_id}-${lane}-test-results.json" \
    "${deployment_id}-${lane}-provider.log"
}

prepare_deployment_lane_artifacts() {
  local runner_image="${1:?runner image is required}"
  local deployment_id="${2:?deployment id is required}"
  local lane="${3:?lane is required}"
  local artifact
  local -a artifact_paths=()
  while IFS= read -r artifact; do
    artifact_paths+=("/workspace/artifacts/${artifact}")
  done < <(deployment_lane_artifact_paths "${deployment_id}" "${lane}")
  docker run --rm --user 0:0 \
    --mount "type=bind,src=$(pwd)/artifacts,dst=/workspace/artifacts" \
    --entrypoint /bin/sh "${runner_image}" -c \
    'chown "$1:$2" "$3" && shift 3 && rm -f -- "$@"' \
    sh "$(id -u)" "$(id -g)" /workspace/artifacts "${artifact_paths[@]}"
}
