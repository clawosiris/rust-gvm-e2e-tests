# Community E2E test cases

The authoritative inventory is generated from rust-gvm’s command registry and
typed public client surface. See [community-coverage.md](community-coverage.md)
for every command/helper and its disposition. The generated file must never be
edited by hand.

## `devel-fast`

The blocking warm-volume lane validates:

- typed version, authentication, features, text/brief-XML/full-XML help, feeds, settings,
  system reports, aggregates, auth description, resource names, preferences;
- typed list/singular/filter/pagination parsing for targets, generic and scan
  configs/policies, scanners, port lists, tasks, NVTs/preferences/families,
  CVE/CPE/CERT/DFN SecInfo, vulnerabilities, alerts, credentials, filters,
  notes, overrides, schedules, tags, and report formats;
- atomic run-namespaced config and scanner create/get/modify/verify,
  trash/restore/ultimate-delete lifecycles and invalid-reference failures;
- target/task and the ordinary Community resource CRUD smoke, including a real
  syslog alert rather than an unconditional omission;
- authentication and deleted-resource error semantics;
- gvm-rools CLI framing, raw XML, authentication failure, and socket failure.

The lane performs namespaced stale-run cleanup before assertions and a second,
dependency-ordered cleanup on success or unwind.

## `devel-scan`

The nightly/manual warm-volume lane scans the Compose `scan-fixture` HTTP
service as a network host. It creates a `T:80` port list, target and task; checks
typed task identity, delivers `start_task` exactly once, and verifies that a
second local attempt is blocked before another wire mutation; observes start
and synchronous stop or terminal completion; resolves task/report linkage;
imports a sanitized report fixture; and removes reports before tasks, targets,
and supporting resources. A concrete report returned by `start_task` becomes
cleanup-owned immediately.

Issue #118's scan-linked typed report/result and export gap remains open. The
pinned stable gvmd baseline aborts those expansion paths because
`SEVERITY_ERROR` is undefined (greenbone/gvmd#3069), so the converged harness
records `conditional-unavailable` rather than claiming a pass. The ticket
lifecycle also remains open: its prerequisite no-match result query is
deliberately empty, so no eligible result exists. Neither gap is counted as
completed live coverage.

The fixture being a container does not make this container-image scanning.
No OCI target is created or required.

## `devel-isolated`

This lane requires `E2E_ISOLATED=1` and a distinct Compose project/volume
namespace. It covers:

- user/group/role/permission create, typed reads, modify, duplicate and
  permission-denied failures, trash/restore/ultimate delete;
- host asset and operating-system asset parsing plus modify and local request-validation
  failure behavior;
- cloned report-format and TLS-certificate lifecycles;
- global setting snapshot/write/restore;
- dedicated `empty_trashcan` execution.

Global mutations never run against the ordinary warm-volume project.
The access-control lifecycle uses the canonical nested permission subject and
complete request values throughout; response-loss reconciliation reads the
permission back and never replays an ambiguous mutation.

Issue #118's report-config gap also remains open. The pinned projection does
not expose the export envelope/parameter metadata needed to build a safe,
deterministic report-config fixture, so report-format import and report-config
lifecycle coverage is explicitly `conditional-unavailable`. The obsolete
`sync_scan_config` facade is recorded as removed because this rust-gvm revision
provides no supported canonical request for the registry-only `sync_config`
name.

## `devel-transport`

TLS, mTLS, and SSH-to-socket are selected only by explicit endpoint
environment. A selected transport must complete typed version and
authentication. An unprovisioned endpoint is emitted as
`conditional-unavailable`, not as a pass. Partially supplied configuration is a
hard configuration error.

## `differential`

The opt-in differential lane compares normalized semantic fields and UUID/name
identity sets with python-gvm for version, configs, scanners, port lists, feeds,
report formats, and cross-client target creation/visibility/deletion. Any
unexpected mismatch is blocking. Both clients issue an explicit unbounded
`usage_type=scan` config query because
[rust-gvm #404](https://github.com/greenbone-hive/rust-gvm/issues/404) tracks the
ergonomic `get_scan_configs` wrapper's missing scope. Feed equality
intentionally excludes the momentary `currently_syncing` flag, which can change
between sequential client reads; stable feed type, name, and status remain
blocking.

## Conditional and excluded outcomes

The fast discovery probe combines `get_version`, `get_features`, and normalized
`help` command evidence with rust-gvm’s semantic version registry. The
checked-in baseline pins the complete help inventory, feature states, and
conditional result. A changed advertisement or availability fails until
reviewed. Conditional and excluded states remain distinct from pass in the JSON
artifact. Confirmed upstream defects are also distinct as `known-upstream-bug`
and must name their tracked issue and exact reproduced response.

Authenticated live help/features are authoritative for Community capability
selection. The rust-gvm minimum-version gate is recorded separately as
diagnostic evidence. Advertised report drill-downs remain planned capabilities,
but the issue #118 scan/report blocker above prevents the converged harness from
claiming that they executed successfully.

Only issue #118’s 15 agent/OCI wire commands, four helper-only task variants,
and six OCI typed target methods are hard Community exclusions. A network
service hosted in a container remains covered.

## Issue #127 architecture status

The convergence preserves the current Community feature/help snapshot,
capability selection, structured results, fixed safety lanes, runtime image
provenance, isolation boundary, and exact result states. Issue #127's proposed
deployment-neutral contract/planner architecture is not implemented here:
there is no reusable external provider, feature-requirement catalog,
pre-execution `test-plan.json`, Enterprise contract, or selected-result
reconciliation yet. Those remain proposed follow-up work and must not be
inferred from the Community manifest.

The checked-in baseline is marked pending live revalidation for issue #148.
Targeted scan and isolated runs followed by one authoritative `lane=all` run
must supply publication evidence; this repository change does not fabricate
those results.
