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
- issue #715 typed validation/error coverage: typed `get_info` NVT OID
  filtering; supplementary local empty-password typed-builder rejection plus a
  raw empty-password request to live gvmd that must return `GvmError::Server`
  status 400 with `Authentication failed`; typed invalid `get_settings`
  sort-field status-200 fallback followed by same-session health; and malformed
  note severity/active GMP 400 responses with `Error in severity specification`
  and `Error in active specification`, followed by same-session health. The
  note payloads use raw `XmlCommand` only for values the typed builders
  intentionally cannot represent;
- gvm-rools CLI framing, raw XML, authentication failure, and socket failure.

The lane performs namespaced stale-run cleanup before assertions and a second,
dependency-ordered cleanup on success or unwind.

Issue #715 also has deterministic Unix-socket server-error coverage. A raw
`XmlCommand` sends an empty-password `authenticate` request and must receive
`GvmError::Server` status 400 with `Authentication failed`; the same connection
then completes `get_version` and valid authentication. The `stop_task` error
path likewise requires `GvmError::Server` status 400 with `Internal error
stopping task` and same-session `get_version`, without creating a live failure
fixture. It deliberately does not cover the later stop-task return-code enum
change.

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
singular typed read. On the qualified Community GMP 22.7 deployment, canonical structured
report drill-downs and synchronous `GetReportExportRequest` are advertised by
live help but rejected locally by rust-gvm's exact documented GMP 22.8
capability floor. Each surface must produce that exact typed
`UnsupportedCommand` result and is recorded with explicit no-wire evidence; on
GMP 22.8 or newer the same code executes the request and requires a successful
typed response, including nonempty decoded bytes for synchronous export.

When authenticated help advertises the complete cleanup-safe command set, the
lane creates an asynchronous scan-report export and owns its returned ID
before checking any later assertion. Bounded `get_report_exports` polling
records every exact status/progress transition and requires terminal
`done`/`completed`. The lane downloads the file, checks its nonempty decoded
bytes, exact byte count, report/format relationships, type, content type, and
extension, then requires an exact typed 404 from `get_report_exports` to prove
gvmd consumed and removed the export after the response.

A second export uses a distinct option set for cancellation qualification. The
lane sends `cancel_report_export` only after it observes that export in
`pending` or `running`, then polls through any `cancel_requested` transition to
`canceled`. If the worker reaches a terminal state before the first read, the
lane consumes a completed file when applicable and emits the exact observed
state as `conditional-unavailable`; it never claims cancellation passed
without sending it. `E2E_REPORT_EXPORT_TIMEOUT_SECS` (default 300) and
`E2E_REPORT_EXPORT_POLL_INTERVAL_SECS` (default 1) bound both paths.

The tracker reconciles report exports before reports and never blindly replays
an ambiguous cancel or download. Cleanup discovers exports linked to every
tracked report, cancels or waits for active work, consumes an unattempted
completed artifact, and finally proves no linked export remains active before
report/task deletion. Preflight applies the same ordering to stale namespaced
tasks.

Audit and delta variants remain inventory-visible and help-gated. Community
Compose explicitly declares `audit_report`, `audit_report_pair`, and
`delta_scan_report_pair` fixtures unavailable, so `export_audit_report`,
`export_delta_audit_report`, and `export_delta_scan_report` emit exact
fixture-backed dispositions without mutation. A provider that declares one of
those fixtures ready fails closed until that lifecycle is implemented. Ticket
coverage remains outside this layer's gating contract.

The lane additionally imports a sanitized report fixture and removes reports
before tasks, targets, and supporting resources. A concrete report returned by
`start_task` becomes cleanup-owned immediately. Final report cleanup treats a
typed 404 as idempotent success when task/report lifecycle processing already
removed it.

The scan-linked report also drives the focused
[greenbone/gvmd#3163](https://github.com/greenbone/gvmd/pull/3163) EPSS
server-abort regression. The lane sends one filter and one sort request for
each of `epss_score`, `epss_percentile`, `max_epss_score`, and
`max_epss_percentile`; every read is followed by `get_version` on the same
authenticated connection. Exact gvmd release, source revision when published
by the image, and immutable image digest are included in the capability and
result artifacts. A proved abort on the known pre-fix Community 26.40.2
baseline is recorded per request as `known-upstream-bug`, never as a pass, and
the lane reconnects only to run the next independent read. Source
`471b7745697af0ee0804212c74f5040f30c6c3d7` (the exact PR head) and all
unclassified deployments must return normal GMP responses and keep the
connection usable. The deterministic policy and request matrix live in
`fixtures/epss-result-regression.json`; no report-config mutation is involved.

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

The lane retains the safe typed `get_report_configs` list read. When it finds
an existing config, it selects the lowest stable ID and proves the typed
`get_report_config` helper against that identity. An empty list emits explicit
`conditional-unavailable` evidence for the singular read: creation remains
quarantined, so it cannot be called a pass. The lane does not send
`create_report_config`, clone, modify, or delete requests while
[greenbone/gvmd#3165](https://github.com/greenbone/gvmd/issues/3165) remains
unresolved. In stable gvmd 26.40.2 / GMP 22.7, runs `36611076644` and
`36665378965` reproducibly closed the create connection; exact-name
reconciliation found no persisted object. The retained Compose log for the
latter run records `Report Config could not be created`, a backtrace, and
`Received Segmentation fault signal`. The result artifact emits one explicit
`known-upstream-bug` observation for every affected command/helper, including
this evidence and the fact that no mutation wire request was executed. It is
neither a pass nor a generic conditional skip.

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

## Capability-selected outcomes

Every deployment lane discovers `get_version`, raw current-or-legacy
`get_features`, authenticated `help`, safe feature probes, and provider fixture
evidence. It validates the selected deployment contract and writes a sorted
plan before preflight cleanup. Required/forbidden contradictions, hidden
commands for enabled features, unhealthy enabled features, unknown required
state, unknown enabled features, and enabled entries without a cleanup-safe
implementation are blocking. Optional unavailable entries are explicit
`not-selected` results and never count as passes.

Before probes, cleanup, or mutation, the complete authenticated brief-XML help
set is classified command by command against the generated modeled inventory
and the reviewed exact-name allowlist. Modeled and allowlisted commands retain
their separate machine-readable evidence. Any unknown advertised name blocks
discovery and is written to the capability snapshot, failed plan, and result
artifacts. A synthetic unknown fixture proves this fail-closed path; separate
fixture cases prove modeled names pass after the report-export allowlist is
empty. Wildcards and command-family exclusions are not accepted.

Authenticated help and probes are authoritative for deployment availability.
Typed semantic version floors are an additional pre-execution gate: help
advertisement cannot select a command/helper that the negotiated GMP version
cannot invoke. Such entries are deterministically `not-selected` with the
required and negotiated versions plus explicit no-wire evidence. This includes
`get_report_export` and the migrated `get_report_export_with_opts` surface on
GMP 22.7. Confirmed upstream defects remain distinct
`known-upstream-bug` outcomes with tracked reproduction evidence.

The former issue #118 agent and OCI exclusions now have feature requirements.
When selected, `devel-fast` performs non-mutating reads plus reversible,
namespace-owned agent-group and OCI-target create/read/modify/delete lifecycles.
The OCI lifecycle requires the provider's deterministic
`E2E_OCI_IMAGE_REFERENCE`. Commands that need additional private fixtures are
marked unimplemented and cause a coverage-gap failure if their feature becomes
enabled; they are not silently skipped or reported as executed.

After execution, every selected command, helper, and scenario must reconcile to
exactly one successful terminal result. Missing, duplicate, unexpected, failed,
or conditional selected results fail the lane. Terminal results are emitted by
the command/helper/scenario runtime branch itself; completing a suite or lane
does not synthesize results for untouched plan entries. See
[deployment providers](deployment-providers.md) for artifact names, provider
contracts, and the external rollout boundary.
