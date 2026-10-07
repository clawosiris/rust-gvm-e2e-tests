# Deployment providers and capability contracts

The harness separates deployment policy from observed gvmd behavior. A provider
supplies a deployment ID, a small contract, non-secret fixture evidence, and
runtime-image provenance. The harness discovers GMP version, raw `get_features`
attributes, authenticated help, and safe probes before it performs preflight
cleanup or any scenario mutation.

Authenticated help is also a reverse-parity boundary. Its complete brief-XML
command set is classified against the generated rust-gvm/E2E command inventory
and the reviewed exact-name allowlist. An advertised name in neither set fails
discovery before preflight cleanup; the capability snapshot, failed test-plan
artifact, and lane result retain the sorted unknown command list. Allowlist
entries are exact command names with individual rationale and evidence—wildcard
or family exclusions are invalid policy.

## Contract semantics

Contracts use schema version 1. `required` must resolve to ready; missing,
disabled, contradictory, unhealthy, or unknown evidence blocks the lane.
`optional` selects coverage only when ready and otherwise emits explicit
`not-selected` entries. An optional feature that is enabled but unhealthy is a
readiness failure, not a skip. `forbidden` blocks advertised or enabled
presence, and unknown evidence cannot prove that a forbidden capability is
absent. `allow_legacy_fallback` may name optional features for which missing
feature attributes can be resolved only when authenticated help and every
operational probe are ready.

The checked-in Community contract is
[`contracts/community-stable.json`](../contracts/community-stable.json). A
private caller should keep its expectations in its private repository and must
not put registry credentials, tokens, passwords, or proprietary topology in a
contract or descriptor.

Evidence precedence is direct feature flags, authenticated help, safe probe,
then rust-gvm registry metadata. The registry is diagnostic and never turns
inconclusive live evidence into support. Current two-attribute and legacy
enabled-only `get_features` responses preserve missing `compiled_in` as JSON
`null`.

## Providers

`compose` owns the repository Community lifecycle. `COMPOSE_FILE` accepts a
colon-separated base/overlay list. `E2E_COMPOSE_PROJECT` replaces the historical
Community-specific project variable. In the reusable workflow, the public
harness is checked out at the workspace root and the caller repository is
checked out at `provider/`; private Compose paths therefore use that prefix,
for example `docker/docker-compose.yml:provider/deploy/e2e-overlay.yml`.

`external` never starts, stops, cleans, or logs the external deployment. Its
descriptor supplies an absolute Unix socket and a JSON runtime-image descriptor.
For `devel-scan`, the descriptor's `gvmd` row must include the exact numeric
`version` and immutable `digest`. Only the canonical
`registry.community.greenbone.net/community/gvmd` repository can receive the
reviewed 26.40.2 baseline disposition; every other repository is
source-specific and must also include an exact `source_revision`. These values
drive and document the EPSS regression disposition.
The caller supplies credentials through `GVM_ADMIN_USER` and `GVM_ADMIN_PASS`;
the values are propagated by environment name and are not written to artifacts.
The runner performs the same authenticated socket/feed readiness check before
the lane, but lifecycle ownership remains with the caller.

```bash
python3 tools/deployment_provider.py \
  --contract path/to/contract.json \
  --fixtures path/to/fixtures.json \
  --provider external \
  --provider-descriptor path/to/provider.json

E2E_PROVIDER_MODE=external \
E2E_DEPLOYMENT_ID=my-deployment \
E2E_DEPLOYMENT_CONTRACT=path/to/contract.json \
E2E_FIXTURE_DESCRIPTOR=path/to/fixtures.json \
E2E_PROVIDER_DESCRIPTOR=path/to/provider.json \
bash docker/scripts/run-deployment-lane.sh devel-fast
```

If OCI target coverage is selected, set `E2E_OCI_IMAGE_REFERENCE` to a
provider-owned deterministic image reference. It is provenance, not a registry
credential.

## Planning and reconciliation

The generated manifest gives every registered command and public helper its
own lane, feature requirements, and implementation state. The feature catalog
also declares executable scenarios. Planning is sorted by entry kind and name
and fails before mutation for hidden enabled commands, unhealthy enabled
features, unknown required state, unknown enabled features, enabled known
features with no scenario, and enabled entries without a cleanup-safe public
path.

After a lane, every selected entry must have exactly one successful terminal
result. Missing, duplicate, unexpected, failed, or conditional selected results
fail reconciliation. Per-lane artifacts are:

- `<deployment>-<lane>-capability-snapshot.json`;
- `<deployment>-<lane>-deployment-contract.json`;
- `<deployment>-<lane>-test-plan.json`;
- `<deployment>-<lane>-test-results.json`;
- `<deployment>-<lane>-runtime-images.json`;
- `<deployment>-<lane>-provider.log` on provider failure.

This is an explicit artifact migration: the earlier
`community-e2e-<lane>.json`, `runtime-images-<lane>.json`, and
`community-e2e-<lane>-compose.log` names are no longer written by deployment
lanes. Consumers must use the deployment-qualified names; the harness does not
dual-write ambiguous old and new artifacts.

## Reusable workflow

[`deployment-e2e.yml`](../.github/workflows/deployment-e2e.yml) is the public
`workflow_call` entry point. Callers provide exact harness and rust-gvm commit
SHAs, deployment ID, provider mode, contract/fixture paths, Compose overlays or
external descriptor, runtime version, deterministic scan/OCI fixture references,
readiness/task budgets, fixed lane, and clean-volume policy. Jobs and artifacts
include the deployment ID. Private callers retain all proprietary images,
registries, secrets, and topology.

This repository can validate the generic interface and Community provider
offline and on its public runner. Enterprise qualification, deliberate removal
of a required private component, and an unhealthy private backing service are
external rollout evidence; no such result is claimed here.
