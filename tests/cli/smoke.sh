#!/usr/bin/env bash
set -euo pipefail

SOCKET_PATH="${GVM_SOCKET_PATH:-/run/gvmd/gvmd.sock}"
GVM_ADMIN_USER="${GVM_ADMIN_USER:-admin}"
GVM_ADMIN_PASS="${GVM_ADMIN_PASS:-admin}"
GVM_CLI_BIN="${GVM_CLI_BIN:-gvm-cli}"
SMOKE_TARGET_NAME="${SMOKE_TARGET_NAME:-e2e-cli-target}"

tmpdir="$(mktemp -d)"
TARGET_ID_FILE="${tmpdir}/target_id"

log() {
  printf '%s\n' "$1"
}

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

require_contains() {
  local haystack="$1"
  local needle="$2"
  local label="$3"
  [[ "${haystack}" == *"${needle}"* ]] || fail "${label}: expected output to contain ${needle}"
}

run_cli() {
  # --xml and --pretty are top-level flags; extract them before the subcommand.
  local top_args=()
  local sub_args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --xml)    top_args+=(--xml "$2"); shift 2 ;;
      --pretty) top_args+=(--pretty); shift ;;
      *)        sub_args+=("$1"); shift ;;
    esac
  done
  "${GVM_CLI_BIN}" \
    --gmp-username "${GVM_ADMIN_USER}" \
    --gmp-password "${GVM_ADMIN_PASS}" \
    "${top_args[@]}" \
    socket --path "${SOCKET_PATH}" \
    "${sub_args[@]}"
}

cleanup() {
  if [[ -s "${TARGET_ID_FILE}" ]]; then
    local target_id
    target_id="$(<"${TARGET_ID_FILE}")"
    run_cli --xml "<delete_target target_id=\"${target_id}\" ultimate=\"1\"/>" >/dev/null 2>&1 || true
  fi
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

version_output="$("${GVM_CLI_BIN}" --xml '<get_version/>' socket --path "${SOCKET_PATH}")"
require_contains "${version_output}" "<get_version_response" "get_version"
log "[pass] cli 01 get_version"

scanners_output="$(run_cli --xml '<get_scanners/>')"
require_contains "${scanners_output}" "<get_scanners_response" "get_scanners"
require_contains "${scanners_output}" "<scanner" "get_scanners"
log "[pass] cli 02 authenticated get_scanners"

pretty_output="$(run_cli --pretty --xml '<get_configs/>')"
require_contains "${pretty_output}" "<get_configs_response" "pretty get_configs"
require_contains "${pretty_output}" $'\n' "pretty get_configs"
log "[pass] cli 03 pretty get_configs"

create_output="$(run_cli --xml "<create_target><name>${SMOKE_TARGET_NAME}</name><hosts>127.0.0.1</hosts></create_target>")"
require_contains "${create_output}" "<create_target_response" "create_target"
target_id="$(printf '%s' "${create_output}" | sed -n 's/.*id="\([^"]*\)".*/\1/p' | head -n1)"
[[ -n "${target_id}" ]] || fail "create_target: failed to parse target id"
printf '%s' "${target_id}" > "${TARGET_ID_FILE}"
log "[pass] cli 04 create target (${target_id})"

delete_output="$(run_cli --xml "<delete_target target_id=\"${target_id}\" ultimate=\"1\"/>")"
require_contains "${delete_output}" "<delete_target_response" "delete_target"
require_contains "${delete_output}" 'status="200"' "delete_target"
: > "${TARGET_ID_FILE}"
log "[pass] cli 05 delete target"
