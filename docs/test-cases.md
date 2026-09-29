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
retrieves exactly that report through the canonical typed request; proves the
report and task identities link in both directions; lists results with the
canonical `report_id` filter; and, when the report contains a result, retrieves
the lowest result UUID deterministically and verifies its identity and report
relationship. A zero-result deterministic scan remains a valid list outcome,
but is recorded as `conditional-unavailable` for the singular result read
rather than being reported as successful drill-down execution. The lane also
asserts typed 404 behavior for a missing report.

The lane selects the lowest-ID active typed report format that exposes both a
content type and extension, then proves the same format identity through the
singular typed read. On the enforced GMP 22.7 baseline, canonical structured
report drill-downs and synchronous `GetReportExportRequest` are advertised by
live help but rejected locally by rust-gvm's exact documented GMP 22.8
capability floor. Each surface must produce that exact typed
`UnsupportedCommand` result and is recorded with explicit no-wire evidence; on
GMP 22.8 or newer the same code executes the request and requires a successful
typed response, including nonempty decoded bytes for synchronous export.

The advertised asynchronous `ExportScanReportRequest` is intentionally not
mutated: the pinned typed API can create or reuse an export ID but exposes no
typed cancel/delete/reconciliation lifecycle, so cleanup ownership cannot be
guaranteed after success or an ambiguous response. Ticket coverage is outside
this PR's gating contract and is not emitted as a scan observation.

The lane additionally imports a sanitized report fixture and removes reports
before tasks, targets, and supporting resources. A concrete report returned by
`start_task` becomes cleanup-owned immediately. Final report cleanup treats a
typed 404 as idempotent success when task/report lifecycle processing already
removed it.

The fixture being a container does not make this container-image scanning.
No OCI target is created or required.

## `devel-isolated`

This lane requires `E2E_ISOLATED=1` and a distinct Compose project/volume
namespace. It covers:

- user/group/role/permission create, typed reads, modify, duplicate and
  permission-denied failures, trash/restore/ultimate delete;
- host asset and operating-system asset parsing plus modify and local request-validation
  failure behavior;
- cloned report-format, report-config, and TLS-certificate lifecycles;
- global setting snapshot/write/restore;
- dedicated `empty_trashcan` execution.

Global mutations never run against the ordinary warm-volume project.
The access-control lifecycle uses the canonical nested permission subject and
complete request values throughout; response-loss reconciliation reads the
permission back and never replays an ambiguous mutation.

Report-config coverage uses only the pinned typed API. Because the typed
report-format projection omits parameter metadata, the lane sorts every active
format by ID and tries one unique run-owned `CreateReportConfigRequest` per
candidate with zero overrides. Only status 400 plus a normalized exact match
for gvmd's authoritative text `Given report format does not have any
configurable parameters.` advances to the next candidate; every attempted
ID/name/status/text is retained. A generic 400 is blocking. If all candidates
return the definitive result, the lane emits `conditional-unavailable` and
does not claim a lifecycle pass. The checked-in stable help baseline continues
to advertise the report-config commands; help advertisement alone cannot
identify which active report format, if any, accepts configuration.

The first successful create is cleanup-owned immediately and exercises typed
list and singular identity/linkage reads, name/comment modification with
read-after-write verification, clone with immediate cleanup ownership,
singular clone verification, ultimate clone deletion, and exact typed 404
proof. Create and clone response loss is reconciled by a fresh authenticated
typed name query; the mutation is never replayed, and zero or multiple exact
matches fail while retaining the unique name for cleanup/preflight. Ambiguous
modify and delete responses likewise use typed read reconciliation without
mutation replay. The original remains tracked for dependency-ordered cleanup.

Report-format import remains separately `conditional-unavailable`: the pinned
typed projection does not expose the export envelope needed to construct a
canonical import request. The obsolete `sync_scan_config` facade is recorded
as removed because this rust-gvm revision provides no supported canonical
request for the registry-only `sync_config` name.

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
and the scan lane now checks their exact typed capability outcome. A GMP 22.7
result records the local 22.8 rejection and does not claim positive wire
execution.

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
