# Test Spec: Removing E2E Infrastructure from rust-gvm

**Related issue:** [#2 — History split: move E2E assets from rust-gvm via git-filter-repo](https://github.com/clawosiris/rust-gvm-e2e-tests/issues/2)

## Objective

Safely remove the E2E test infrastructure from `clawosiris/rust-gvm` after validating that `clawosiris/rust-gvm-e2e-tests` provides equivalent coverage.

## Prerequisites

All items must be verified before removal:

### 1. Smoke Tests Passing ✅
- [x] Layer 1 (rust-gvm library): 10 tests passing
- [x] Layer 2 (gvm-rools CLI): 5 tests passing
- [x] gvm-tools cross-check available on failure

### 2. Extended Scan Test Validated
- [ ] Run `E2E_RUN_SCAN=1` in rust-gvm-e2e-tests and verify:
  - Task creation with real scan config
  - Scan start, status polling, stop
  - Report retrieval and structure validation
  - Full cleanup (no orphan tasks/targets)

### 3. Cross-Repo Trigger Wired
- [ ] Add `repository_dispatch` step to rust-gvm CI (`ci.yml` or `e2e-trigger.yml`):
  ```yaml
  - name: Trigger E2E tests
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    env:
      GH_TOKEN: ${{ secrets.RELEASE_TOKEN }}
    run: |
      gh api repos/clawosiris/rust-gvm-e2e-tests/dispatches \
        -f event_type=component-updated \
        -f client_payload='{"component":"rust-gvm","ref":"${{ github.sha }}"}'
  ```
- [ ] Add equivalent trigger to gvm-rools CI
- [ ] Verify trigger fires and E2E run starts

### 4. Parallel Validation Period
- [ ] Both rust-gvm E2E (in-repo) and rust-gvm-e2e-tests (standalone) run for ≥3 successful cycles
- [ ] Results match (same tests pass/fail)
- [ ] No false negatives in standalone repo

### 5. Parameterized Ref Testing
- [ ] Trigger standalone E2E with a specific rust-gvm branch (not main)
- [ ] Verify the correct ref is built and tested

## Removal Plan

### Step 1: Wire cross-repo triggers
Add `repository_dispatch` to rust-gvm and gvm-rools CI workflows.

### Step 2: Parallel run period
Keep both E2E paths active for ≥3 days. Monitor via heartbeat cron.

### Step 3: Remove from rust-gvm (PR)
Create a PR that removes:
```
tests/e2e/gvm-community/          # Docker Compose stack + scripts
examples/e2e_gvm_community.rs     # E2E test binary
.github/workflows/e2e.yml         # E2E workflow
.github/workflows/e2e-trigger.yml # E2E trigger workflow
```

Keep:
- `gvm-mock-server` (used for unit/integration tests, not E2E)
- Any references in README (update to point to rust-gvm-e2e-tests)

### Step 4: Update rust-gvm README
Add pointer to rust-gvm-e2e-tests for E2E testing.

### Step 5: Close issue #2
After removal PR is merged and standalone tests remain green.

## Rollback

If standalone E2E tests prove unreliable after removal:
1. Revert the removal PR in rust-gvm
2. Disable `repository_dispatch` trigger
3. Re-evaluate standalone approach

## Verification Checklist (pre-merge of removal PR)

- [ ] Standalone E2E smoke tests green for ≥3 consecutive runs
- [ ] Extended scan test validated at least once
- [ ] Cross-repo trigger confirmed working
- [ ] No regression in rust-gvm CI coverage
- [ ] README updated
