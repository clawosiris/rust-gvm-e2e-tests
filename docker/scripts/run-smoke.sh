#!/usr/bin/env bash
set -euo pipefail

library_tests() {
  echo "=== Layer 1: Library Tests (rust-gvm) ==="
  gvm-community-e2e --mode smoke
}

cli_tests() {
  echo "=== Layer 2: CLI Tests (gvm-rools) ==="
  bash /workspace/tests/cli/smoke.sh
}

case "${1:-all}" in
  library)
    library_tests
    ;;
  cli)
    cli_tests
    ;;
  all)
    library_tests
    cli_tests
    ;;
  *)
    echo "usage: $0 [all|library|cli]" >&2
    exit 1
    ;;
esac
