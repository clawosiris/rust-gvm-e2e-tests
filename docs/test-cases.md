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
typed task identity and illegal double-start behavior; observes start,
stop/resume or terminal completion; validates task/report linkage; parses typed
reports and results; exports through an advertised report format; runs every
available report drill-down; and removes tickets/tasks/targets/supporting
resources in dependency order.

The fixture being a container does not make this container-image scanning.
No OCI target is created or required.

## `devel-isolated`

This lane requires `E2E_ISOLATED=1` and a distinct Compose project/volume
namespace. It covers:

- user/group/role/permission create, typed reads, modify, duplicate and
  permission-denied failures, trash/restore/ultimate delete;
- host asset and operating-system asset parsing plus modify/failure behavior;
- cloned report formats, report configs, and TLS certificate lifecycles;
- global setting snapshot/write/restore;
- dedicated `empty_trashcan` execution.

Global mutations never run against the ordinary warm-volume project.

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
unexpected mismatch is blocking.

## Conditional and excluded outcomes

The fast discovery probe combines `get_version`, `get_features`, and normalized
`help` command evidence with rust-gvm’s semantic version registry. The
checked-in baseline pins the complete help inventory, feature states, and
conditional result. A changed advertisement or availability fails until
reviewed. Conditional and excluded states remain distinct from pass in the JSON
artifact.

Only issue #118’s 15 agent/OCI wire commands, four helper-only task variants,
and six OCI typed target methods are hard Community exclusions. A network
service hosted in a container remains covered.
