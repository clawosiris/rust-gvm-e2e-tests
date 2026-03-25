# E2E Test Cases

A comprehensive overview of all test cases covered by the rust-gvm E2E test suite.

> **Quick Stats:** 60+ test points across 5 suites, validating library, CLI, and cross-implementation consistency.

---

## Suite 1: Smoke Tests

**Purpose:** Validate core GMP protocol operations via the rust-gvm library.  
**Runtime:** ~2 minutes

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 01 | Version negotiation | GMP protocol version ≥22.4 supported |
| 02 | Authentication | Admin credentials accepted, session established |
| 03 | List scan configs | Feed data loaded, configs queryable (typically 10) |
| 04 | List scanners | OpenVAS scanner registered and available |
| 05 | List report formats | Export formats available (PDF, XML, CSV, etc.) |
| 06 | List port lists | Default port lists present |
| 07 | Create target | Target creation with hosts + port list reference |
| 08 | Get target | Retrieve target by UUID, verify attributes |
| 09 | Delete target | Remove target, handle dependencies |
| 10 | Verify deletion | Confirm 404 response for deleted target |

### Extended Scan (opt-in)

**Trigger:** `run-scan: true`  
**Runtime:** ~10 minutes additional

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 11 | Create scan task | Task creation with target + scan config + scanner |
| 12 | Start scan | Scan initiation, status transitions |
| 13 | Poll scan status | Status polling until completion/stop |
| 14 | Stop scan | Graceful scan termination |
| 15 | Get report | Report retrieval with results |
| 16 | Cleanup | Task and target deletion |

---

## Suite 2: CRUD Tests

**Purpose:** Full lifecycle validation for all major GMP entity types.  
**Pattern:** Create → Get → Delete → Verify Absent  
**Runtime:** ~3 minutes

### Port Lists

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 01 | Create port list | Custom port range (T:1-100) |
| 02 | Get port list | Retrieve by UUID |
| 03 | Delete port list | Removal with ultimate flag |
| 04 | Verify absent | 404 after deletion |

### Credentials

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 05 | Create credential | Username/password type |
| 06 | Get credential | Retrieve (password redacted) |
| 07 | Delete credential | Removal |
| 08 | Verify absent | 404 after deletion |

### Schedules

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 09 | Create schedule | iCalendar format, weekly recurrence |
| 10 | Get schedule | Retrieve with timezone |
| 11 | Delete schedule | Removal |
| 12 | Verify absent | 404 after deletion |

### Filters

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 13 | Create filter | Filter type + search term |
| 14 | Get filter | Retrieve filter definition |
| 15 | Delete filter | Removal |
| 16 | Verify absent | 404 after deletion |

### Tasks

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 17 | Create target (for task) | Prerequisite entity |
| 18 | Create task | Task with target + scan config + scanner |
| 19 | Get task | Retrieve task configuration |
| 20 | Delete task | Remove task (keeps target) |
| 21 | Verify task absent | 404 after deletion |
| 22 | Delete target | Cleanup prerequisite |

### Notes

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 23 | Create note | Note attached to NVT OID |
| 24 | Get note | Retrieve note text |
| 25 | Delete note | Removal |
| 26 | Verify absent | 404 after deletion |

### Overrides

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 27 | Create override | Severity override for NVT |
| 28 | Get override | Retrieve override config |
| 29 | Delete override | Removal |
| 30 | Verify absent | 404 after deletion |

### Tags

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 31 | Create tag | Tag with resource attachment |
| 32 | Get tag | Retrieve tag metadata |
| 33 | Delete tag | Removal |
| 34 | Verify absent | 404 after deletion |

### Alerts

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 35 | Create alert | HTTP GET alert with condition/event/method |
| 36 | Get alert | Retrieve alert configuration |
| 37 | Delete alert | Removal |
| 38 | Verify absent | 404 after deletion |

---

## Suite 3: SecInfo Tests

**Purpose:** Validate read-only access to security intelligence feed data.  
**Runtime:** ~1 minute

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 01 | Get feeds | All 4 feed types present (NVT, SCAP, CERT, GVMD_DATA) |
| 02 | Get CVEs | CVE entries queryable from SCAP feed |
| 03 | Get CPEs | CPE dictionary entries available |
| 04 | Get CERT-Bund | German CERT advisories loaded |
| 05 | Get DFN-CERT | DFN-CERT advisories loaded |
| 06 | Get NVTs | Vulnerability tests queryable (~170k+) |

---

## Suite 4: CLI Tests (gvm-rools)

**Purpose:** Validate the `gvm-cli` command-line tool end-to-end.  
**Runtime:** ~1 minute

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 01 | `get_version` | Unauthenticated version query works |
| 02 | `get_scanners` | Authenticated command with credentials |
| 03 | `get_scan_configs` | Pretty-print output formatting |
| 04 | Create target (XML) | Raw XML command passthrough |
| 05 | Delete target | Cleanup via CLI |
| 06 | `--duration` flag | Timing output displayed |
| 07 | Wrong password | Non-zero exit code on auth failure |
| 08 | `--raw` flag | Raw XML response passthrough |
| 09 | Bad socket | Graceful error on connection failure |

---

## Suite 5: Differential Tests

**Purpose:** Send identical GMP commands via rust-gvm and python-gvm (`gvm-tools`) and compare normalized results.  
**Trigger:** Opt-in via `--suite differential` or workflow input `run-differential: true`.  
**Behavior:** Mismatches are logged as warnings (non-blocking) for fault isolation.

| # | Test Case | What It Validates |
|---|-----------|-------------------|
| 01 | `get_version` | Version string parity across both clients |
| 02 | `get_scan_configs` | Config count, UUID set, and names match |
| 03 | `get_scanners` | Scanner count and UUID/name parity |
| 04 | `get_port_lists` | Port list count and UUID/name parity |
| 05 | `get_feeds` | Feed type/status/syncing parity |
| 06 | `get_report_formats` | Format count and UUID/name/type parity |
| 07 | Target lifecycle cross-check | Create target via both clients, verify visibility in both, cleanup |

---

## Cross-Validation: gvm-tools

**Purpose:** Ensure rust-gvm results match the reference python-gvm implementation.  
**Trigger:** Runs by default on success; always runs on failure for fault isolation.

| Check | What It Validates |
|-------|-------------------|
| `get_version` | Protocol version matches |
| `get_scan_configs` | Same configs returned |
| `get_scanners` | Same scanners returned |
| `get_port_lists` | Same port lists returned |
| `get_feeds` | Same feed status |
| `get_report_formats` | Same formats available |

---

## Test Infrastructure

### Fixtures & Dependencies

| Entity | Source | Notes |
|--------|--------|-------|
| Scan configs | GVM feed | ~10 default configs (Full, Fast, Discovery, etc.) |
| Scanners | gvmd | OpenVAS Default scanner auto-registered |
| Port lists | GVM feed | All IANA ports, common ports, etc. |
| Report formats | GVM feed | PDF, XML, CSV, TXT, etc. |
| NVT for notes/overrides | GVM feed | Uses well-known OID |

### Cleanup Strategy

- **Per-test cleanup:** Each CRUD test deletes what it creates
- **CleanupTracker:** Safety net catches entities if test fails mid-run
- **Pre-flight cleanup:** Extended scan cleans stale targets before starting
- **Nuclear option:** `clean: true` wipes all volumes for fresh start

---

## Coverage Matrix

| Component | Smoke | CRUD | SecInfo | CLI | gvm-tools |
|-----------|:-----:|:----:|:-------:|:---:|:---------:|
| Version/Auth | ✅ | — | — | ✅ | ✅ |
| Scan Configs | ✅ | — | — | ✅ | ✅ |
| Scanners | ✅ | — | — | ✅ | ✅ |
| Port Lists | ✅ | ✅ | — | — | ✅ |
| Report Formats | ✅ | — | — | — | ✅ |
| Targets | ✅ | ✅ | — | ✅ | — |
| Tasks | ⚡ | ✅ | — | — | — |
| Credentials | — | ✅ | — | — | — |
| Schedules | — | ✅ | — | — | — |
| Filters | — | ✅ | — | — | — |
| Notes | — | ✅ | — | — | — |
| Overrides | — | ✅ | — | — | — |
| Tags | — | ✅ | — | — | — |
| Alerts | — | ✅ | — | — | — |
| Feeds | — | — | ✅ | — | ✅ |
| CVEs/CPEs | — | — | ✅ | — | — |
| CERT Advisories | — | — | ✅ | — | — |
| NVTs | — | — | ✅ | — | — |

Legend: ✅ = covered | ⚡ = opt-in (`run-scan: true`) | — = not covered

---

## Adding New Tests

1. **Library tests:** Add to `tests/library/src/main.rs`
2. **CLI tests:** Add to `tests/cli/smoke.sh`
3. **New suite:** Create function in main.rs, add step to `.github/workflows/e2e.yml`

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup.
