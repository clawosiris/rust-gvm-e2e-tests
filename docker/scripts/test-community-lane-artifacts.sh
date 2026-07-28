#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/community-lane-artifacts.sh"

test_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_dir}"' EXIT

mock_bin="${test_dir}/bin"
mock_log="${test_dir}/docker-arguments"
mkdir -p "${mock_bin}"
cat > "${mock_bin}/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >> "${MOCK_DOCKER_LOG:?}"
EOF
chmod +x "${mock_bin}/docker"

lane="devel-isolated"
generated_files=(
  "runtime-images-${lane}.json"
  "community-e2e-${lane}.json"
  "community-e2e-${lane}-compose.log"
)

mapfile -t enumerated_files < <(community_lane_artifact_paths "${lane}")
[[ "${#enumerated_files[@]}" -eq 3 ]]
[[ "${enumerated_files[*]}" == "${generated_files[*]}" ]]

PATH="${mock_bin}:${PATH}" MOCK_DOCKER_LOG="${mock_log}" \
  prepare_community_lane_artifacts docker/docker-compose.yml "${lane}"

mapfile -t docker_arguments < "${mock_log}"
expected_targets=(
  /workspace/artifacts
  "/workspace/artifacts/${generated_files[0]}"
  "/workspace/artifacts/${generated_files[1]}"
  "/workspace/artifacts/${generated_files[2]}"
)
for target in "${expected_targets[@]}"; do
  [[ " $(printf '%s ' "${docker_arguments[@]}")" == *" ${target} "* ]]
done

[[ "$(printf '%s\n' "${docker_arguments[@]}" | grep -Fxc -- /workspace/artifacts)" -eq 1 ]]
[[ "$(printf '%s\n' "${docker_arguments[@]}" | grep -Fc -- /workspace/artifacts/)" -eq 3 ]]
[[ "$(printf '%s\n' "${docker_arguments[@]}" | grep -Fxc -- --no-deps)" -eq 1 ]]
[[ "$(printf '%s\n' "${docker_arguments[@]}" | grep -Fxc -- --user)" -eq 1 ]]
[[ "$(printf '%s\n' "${docker_arguments[@]}" | grep -Fxc -- 0:0)" -eq 1 ]]
[[ "$(printf '%s\n' "${docker_arguments[@]}" | grep -Fxc -- rust-gvm-e2e)" -eq 1 ]]
[[ "$(printf '%s\n' "${docker_arguments[@]}" | grep -Fxc \
  'chown "$1:$2" "$3" && rm -f -- "$4" "$5" "$6"')" -eq 1 ]]
if printf '%s\n' "${docker_arguments[@]}" | grep -Eq 'devel-fast|keep-me|\.\./'; then
  echo 'root cleanup command included an unrelated path' >&2
  exit 1
fi

if community_lane_artifact_paths '../devel-isolated' >/dev/null 2>&1; then
  echo 'path traversal lane unexpectedly accepted' >&2
  exit 1
fi
if community_lane_artifact_paths 'unsupported' >/dev/null 2>&1; then
  echo 'unsupported lane unexpectedly accepted' >&2
  exit 1
fi
if PATH="${mock_bin}:${PATH}" MOCK_DOCKER_LOG="${mock_log}" \
  prepare_community_lane_artifacts docker/docker-compose.yml '../devel-isolated' \
  >/dev/null 2>&1; then
  echo 'path traversal lane reached root cleanup' >&2
  exit 1
fi
[[ "$(wc -l < "${mock_log}")" -eq "${#docker_arguments[@]}" ]]
