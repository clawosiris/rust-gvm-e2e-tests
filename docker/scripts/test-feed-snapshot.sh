#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/feed-snapshot.sh"

expected_materializers=$'vulnerability-tests\nnotus-data\nscap-data\ncert-bund-data\ndfn-cert-data\ndata-objects\nreport-formats\ngpg-data'
expected_consumers=$'redis-server\npg-gvm\ngvmd\nopenvasd\nospd-openvas\ngsad\nscan-fixture'
[[ "$(printf '%s\n' "${FEED_MATERIALIZER_SERVICES[@]}")" == "${expected_materializers}" ]]
[[ "$(printf '%s\n' "${FEED_SNAPSHOT_CONSUMER_SERVICES[@]}")" == "${expected_consumers}" ]]

test_log="$(mktemp)"
trap 'rm -f -- "${test_log}"' EXIT
snapshot_stopped=false

date() {
  [[ "$1" == "+%s" ]]
  printf '%s\n' 100
}

materializer_state='running|0|healthy'
read_feed_materializer_state() {
  printf '%s\n' "${materializer_state}"
}

wait_for_feed_materializer_completion vulnerability-tests 10 1
materializer_state='exited|0|missing'
wait_for_feed_materializer_completion gpg-data 10 1
materializer_state='exited|17|missing'
if wait_for_feed_materializer_completion broken-feed 10 1; then
  echo "failed materializer was accepted" >&2
  exit 1
fi

wait_for_feed_materializer_completion() {
  printf 'wait %s %s %s\n' "$1" "$2" "$3" >> "${test_log}"
}

deployment_compose() {
  if [[ "$1" == "ps" && "$2" == "--status" && "$3" == "running" && "$4" == "--quiet" ]]; then
    local service="$5"
    if [[ " ${FEED_MATERIALIZER_SERVICES[*]} " == *" ${service} "* && "${snapshot_stopped}" == "true" ]]; then
      return 0
    fi
    printf '%s-container\n' "${service}"
    return 0
  fi
  if [[ "$1" == "stop" ]]; then
    printf 'stop' >> "${test_log}"
    printf ' %s' "${@:2}" >> "${test_log}"
    printf '\n' >> "${test_log}"
    snapshot_stopped=true
    return 0
  fi
  echo "unexpected Compose call: $*" >&2
  return 1
}

freeze_feed_snapshot 200 7

expected_log=$'wait vulnerability-tests 100 7\nwait notus-data 100 7\nwait scap-data 100 7\nwait cert-bund-data 100 7\nwait dfn-cert-data 100 7\nwait data-objects 100 7\nwait report-formats 100 7\nwait gpg-data 100 7\nstop --timeout 10 vulnerability-tests notus-data scap-data cert-bund-data dfn-cert-data data-objects report-formats gpg-data'
[[ "$(<"${test_log}")" == "${expected_log}" ]]

for protected in redis-server pg-gvm gvmd openvasd ospd-openvas gsad scan-fixture; do
  if grep -Eq "^stop .* ${protected}( |$)" "${test_log}"; then
    echo "protected runtime service was stopped: ${protected}" >&2
    exit 1
  fi
done
