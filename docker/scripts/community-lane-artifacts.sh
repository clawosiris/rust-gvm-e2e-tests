#!/usr/bin/env bash
set -euo pipefail

validate_community_lane() {
  case "${1:?lane is required}" in
    devel-fast|devel-scan|devel-isolated|devel-transport|differential) ;;
    *) echo "unsupported Community lane: ${1}" >&2; return 2 ;;
  esac
}

community_lane_artifact_paths() {
  local lane="${1:?lane is required}"
  validate_community_lane "${lane}" || return $?

  printf '%s\n' \
    "runtime-images-${lane}.json" \
    "community-e2e-${lane}.json" \
    "community-e2e-${lane}-compose.log"
}

prepare_community_lane_artifacts() {
  local compose_file="${1:?compose file is required}"
  local lane="${2:?lane is required}"
  local artifact
  local host_gid
  local host_uid
  local -a artifact_paths=()

  validate_community_lane "${lane}" || return $?
  while IFS= read -r artifact; do
    artifact_paths+=("/workspace/artifacts/${artifact}")
  done < <(community_lane_artifact_paths "${lane}")

  host_uid="$(id -u)"
  host_gid="$(id -g)"
  docker compose -f "${compose_file}" --profile runner run --rm -T --no-deps \
    --user 0:0 --entrypoint /bin/sh rust-gvm-e2e -c \
    'chown "$1:$2" "$3" && rm -f -- "$4" "$5" "$6"' \
    sh "${host_uid}" "${host_gid}" /workspace/artifacts "${artifact_paths[@]}"
}
