#!/usr/bin/env bash
set -euo pipefail

# Compatibility entry point for existing Community operators.
export E2E_PROVIDER_MODE=compose
export E2E_DEPLOYMENT_ID=community-stable
export E2E_DEPLOYMENT_CONTRACT=contracts/community-stable.json
export E2E_FIXTURE_DESCRIPTOR=fixtures/community-provider.json
exec bash "$(dirname "${BASH_SOURCE[0]}")/run-deployment-lane.sh" "$@"
