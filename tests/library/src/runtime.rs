// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Structured lane results and deployment capability artifacts.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::capability::{
    reconcile, DeploymentCapabilities, DeploymentContract, ExecutionResult, PlanEntryKind,
    TerminalOutcome, TestPlan,
};
use crate::{Disposition, COMMAND_COVERAGE, HELPER_COVERAGE, RUST_GVM_SHA};

static REPORT: OnceLock<Mutex<RunReport>> = OnceLock::new();

/// Reproducibility evidence for the report-config mutation crash disposition.
pub const REPORT_CONFIG_CRASH_EVIDENCE: &str = "known upstream crash greenbone/gvmd#3165: gvmd 26.40.2 / GMP 22.7 closed create_report_config connections in reproducible runs 36611076644 and 36665378965; exact-name reconciliation found no persisted object; the retained run 36665378965 Compose log recorded 'Report Config could not be created', a backtrace, and 'Received Segmentation fault signal'; no report-config mutation wire request is executed";

/// Stable result state. Conditional, excluded, and known-bug states never count as passes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Pass,
    Fail,
    KnownUpstreamBug,
    ConditionalAvailable,
    ConditionalUnavailable,
    Excluded,
    NotSelected,
}

/// One executable assertion or capability-discovery result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Observation {
    pub name: String,
    pub outcome: Outcome,
    pub evidence: String,
}

/// Runtime image identity recorded by the workflow.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeImage {
    pub service: String,
    pub repository: String,
    pub tag: String,
    pub digest: String,
}

/// Complete machine-readable result for one lane invocation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RunReport {
    pub schema_version: u32,
    pub run_id: String,
    pub deployment_id: String,
    pub lane: String,
    pub started_unix_seconds: u64,
    pub finished_unix_seconds: Option<u64>,
    pub rust_gvm_sha: String,
    pub gvm_image_tag: String,
    pub gmp_version: Option<String>,
    pub runtime_images: Vec<RuntimeImage>,
    pub command_dispositions: BTreeMap<String, usize>,
    pub helper_dispositions: BTreeMap<String, usize>,
    pub outcome_counts: BTreeMap<String, usize>,
    pub features: BTreeMap<String, FeatureState>,
    pub help_commands: Vec<String>,
    pub conditional_commands: BTreeMap<String, bool>,
    pub registry_version_gates: BTreeMap<String, bool>,
    pub observations: Vec<Observation>,
    pub plan_results: Vec<ExecutionResult>,
}

/// Recorded `get_features` state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeatureState {
    pub compiled_in: bool,
    pub enabled: bool,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn disposition_counts(entries: &[crate::CoverageEntry]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for entry in entries {
        *counts
            .entry(entry.disposition.as_str().to_string())
            .or_default() += 1;
    }
    counts
}

impl RunReport {
    /// Create a report and make all edition exclusions visible immediately.
    #[must_use]
    pub fn new(run_id: &str, lane: &str) -> Self {
        let mut observations = Vec::new();
        for entry in COMMAND_COVERAGE
            .iter()
            .filter(|entry| entry.disposition == Disposition::KnownUpstreamBug)
        {
            observations.push(Observation {
                name: format!("command:{}", entry.name),
                outcome: Outcome::KnownUpstreamBug,
                evidence: REPORT_CONFIG_CRASH_EVIDENCE.to_string(),
            });
        }
        for entry in HELPER_COVERAGE
            .iter()
            .filter(|entry| entry.disposition == Disposition::KnownUpstreamBug)
        {
            observations.push(Observation {
                name: format!("helper:{}", entry.name),
                outcome: Outcome::KnownUpstreamBug,
                evidence: REPORT_CONFIG_CRASH_EVIDENCE.to_string(),
            });
        }
        Self {
            schema_version: 2,
            run_id: run_id.to_string(),
            deployment_id: env::var("E2E_DEPLOYMENT_ID")
                .unwrap_or_else(|_| "community-stable".to_string()),
            lane: lane.to_string(),
            started_unix_seconds: now(),
            finished_unix_seconds: None,
            rust_gvm_sha: env::var("E2E_RUST_GVM_SHA")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| RUST_GVM_SHA.to_string()),
            gvm_image_tag: env::var("GVM_VERSION").unwrap_or_else(|_| "stable".to_string()),
            gmp_version: None,
            runtime_images: read_runtime_images(),
            command_dispositions: disposition_counts(COMMAND_COVERAGE),
            helper_dispositions: disposition_counts(HELPER_COVERAGE),
            outcome_counts: BTreeMap::new(),
            features: BTreeMap::new(),
            help_commands: Vec::new(),
            conditional_commands: BTreeMap::new(),
            registry_version_gates: BTreeMap::new(),
            observations,
            plan_results: Vec::new(),
        }
    }

    fn finish(&mut self) {
        self.finished_unix_seconds = Some(now());
        self.outcome_counts.clear();
        for observation in &self.observations {
            let key = serde_json::to_value(observation.outcome)
                .ok()
                .and_then(|value| value.as_str().map(ToString::to_string))
                .unwrap_or_else(|| "unknown".to_string());
            *self.outcome_counts.entry(key).or_default() += 1;
        }
    }
}

fn read_runtime_images() -> Vec<RuntimeImage> {
    let Ok(path) = env::var("E2E_RUNTIME_IMAGES_PATH") else {
        return Vec::new();
    };
    if path.trim().is_empty() {
        return Vec::new();
    }
    fs::read_to_string(path)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or_default()
}

/// Fail closed when a provider claims runtime provenance but supplies invalid evidence.
pub fn validate_runtime_images() -> Result<(), String> {
    let path = env::var("E2E_RUNTIME_IMAGES_PATH").map_err(|_| {
        "E2E_RUNTIME_IMAGES_PATH is required for deployment-lane provenance".to_string()
    })?;
    if path.trim().is_empty() {
        return Err(
            "E2E_RUNTIME_IMAGES_PATH is required for deployment-lane provenance".to_string(),
        );
    }
    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("failed to read runtime image evidence at {path}: {error}"))?;
    let images: Vec<RuntimeImage> = serde_json::from_str(&contents)
        .map_err(|error| format!("invalid runtime image evidence at {path}: {error}"))?;
    validate_runtime_image_rows(&images, &path)
}

fn validate_runtime_image_rows(images: &[RuntimeImage], source: &str) -> Result<(), String> {
    if images.is_empty() {
        return Err(format!("runtime image evidence at {source} is empty"));
    }
    let mut services = std::collections::BTreeSet::new();
    for image in images {
        if image.service.trim().is_empty() || image.digest.trim().is_empty() {
            return Err(format!(
                "runtime image evidence at {source} has an empty service or digest"
            ));
        }
        if !services.insert(image.service.clone()) {
            return Err(format!(
                "runtime image evidence at {source} repeats service {}",
                image.service
            ));
        }
    }
    Ok(())
}

/// Start the process-global lane report.
pub fn initialize(run_id: &str, lane: &str) -> Result<(), String> {
    REPORT
        .set(Mutex::new(RunReport::new(run_id, lane)))
        .map_err(|_| "structured result recorder was initialized twice".to_string())
}

fn with_report(operation: impl FnOnce(&mut RunReport)) {
    if let Some(report) = REPORT.get() {
        if let Ok(mut report) = report.lock() {
            operation(&mut report);
        }
    }
}

/// Record a successful executable assertion.
pub fn pass(name: &str, evidence: &str) {
    observe(name, Outcome::Pass, evidence);
}

/// Record a failed executable assertion.
pub fn fail(name: &str, evidence: &str) {
    observe(name, Outcome::Fail, evidence);
}

/// Record an explicit conditional/excluded/selection result.
pub fn observe(name: &str, outcome: Outcome, evidence: &str) {
    with_report(|report| {
        report.observations.push(Observation {
            name: name.to_string(),
            outcome,
            evidence: evidence.to_string(),
        });
    });
}

/// Record one terminal result at the exact runtime path that produced it.
pub fn record_terminal(kind: PlanEntryKind, name: &str, outcome: TerminalOutcome, evidence: &str) {
    with_report(|report| {
        if report
            .plan_results
            .iter()
            .any(|result| result.kind == kind && result.name == name && result.outcome == outcome)
        {
            return;
        }
        report.plan_results.push(ExecutionResult {
            kind,
            name: name.to_string(),
            outcome,
            evidence: evidence.to_string(),
        });
    });
}

/// Record successful completion by an exact command/helper/scenario path.
pub fn record_execution(kind: PlanEntryKind, name: &str, evidence: &str) {
    record_terminal(kind, name, TerminalOutcome::Pass, evidence);
}

/// Store typed discovery evidence in the report.
pub fn discovery(
    gmp_version: &str,
    features: BTreeMap<String, FeatureState>,
    mut help_commands: Vec<String>,
) {
    help_commands.sort();
    help_commands.dedup();
    with_report(|report| {
        report.gmp_version = Some(gmp_version.to_string());
        report.features = features;
        report.help_commands = help_commands;
    });
}

/// Store live conditional availability and non-authoritative registry gates.
pub fn conditional_discovery(
    conditional_commands: BTreeMap<String, bool>,
    registry_version_gates: BTreeMap<String, bool>,
) {
    with_report(|report| {
        report.conditional_commands = conditional_commands;
        report.registry_version_gates = registry_version_gates;
    });
}

/// Snapshot the current report.
pub fn snapshot() -> Option<RunReport> {
    REPORT
        .get()
        .and_then(|report| report.lock().ok().map(|report| report.clone()))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let payload = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    fs::write(path, format!("{payload}\n")).map_err(|error| error.to_string())
}

/// Publish discovery, reviewed contract, and deterministic plan before mutation.
pub fn publish_plan(
    capabilities: &DeploymentCapabilities,
    contract: &DeploymentContract,
    plan: &TestPlan,
) -> Result<(), String> {
    let snapshot_path = env::var("E2E_CAPABILITY_SNAPSHOT_PATH").unwrap_or_else(|_| {
        format!(
            "/workspace/artifacts/{}-{}-capability-snapshot.json",
            capabilities.deployment_id, plan.lane
        )
    });
    let contract_path = env::var("E2E_CONTRACT_ARTIFACT_PATH").unwrap_or_else(|_| {
        format!(
            "/workspace/artifacts/{}-{}-deployment-contract.json",
            capabilities.deployment_id, plan.lane
        )
    });
    let plan_path = env::var("E2E_TEST_PLAN_PATH").unwrap_or_else(|_| {
        format!(
            "/workspace/artifacts/{}-{}-test-plan.json",
            capabilities.deployment_id, plan.lane
        )
    });
    write_json(Path::new(&snapshot_path), capabilities)?;
    write_json(Path::new(&contract_path), contract)?;
    write_json(Path::new(&plan_path), plan)?;
    for entry in &plan.entries {
        if entry.decision == crate::capability::PlanDecision::NotSelected {
            observe(
                &format!("{:?}:{}", entry.kind, entry.name),
                Outcome::NotSelected,
                &entry.evidence,
            );
        }
    }
    Ok(())
}

/// Preserve discovery and the blocking planner error when no executable plan exists.
pub fn publish_planning_failure(
    capabilities: &DeploymentCapabilities,
    contract: &DeploymentContract,
    lane: &str,
    error: &str,
) -> Result<(), String> {
    let snapshot_path = env::var("E2E_CAPABILITY_SNAPSHOT_PATH").unwrap_or_else(|_| {
        format!(
            "/workspace/artifacts/{}-{lane}-capability-snapshot.json",
            capabilities.deployment_id
        )
    });
    let contract_path = env::var("E2E_CONTRACT_ARTIFACT_PATH").unwrap_or_else(|_| {
        format!(
            "/workspace/artifacts/{}-{lane}-deployment-contract.json",
            capabilities.deployment_id
        )
    });
    let plan_path = env::var("E2E_TEST_PLAN_PATH").unwrap_or_else(|_| {
        format!(
            "/workspace/artifacts/{}-{lane}-test-plan.json",
            capabilities.deployment_id
        )
    });
    write_json(Path::new(&snapshot_path), capabilities)?;
    write_json(Path::new(&contract_path), contract)?;
    write_json(
        Path::new(&plan_path),
        &serde_json::json!({
            "schema_version": 1,
            "deployment_id": capabilities.deployment_id,
            "lane": lane,
            "planning_error": error,
            "entries": [],
        }),
    )
}

/// Reconcile exact terminal results and retain them in the result artifact.
pub fn reconcile_plan(plan: &TestPlan) -> Result<(), String> {
    let mut results = snapshot()
        .ok_or_else(|| "structured result recorder is not initialized".to_string())?
        .plan_results;
    results.sort_by(|left, right| (left.kind, &left.name).cmp(&(right.kind, &right.name)));
    reconcile(plan, &results)?;
    with_report(|report| report.plan_results = results);
    Ok(())
}

/// Finalize and write the report to the configured artifact path.
pub fn write() -> Result<PathBuf, String> {
    let report = REPORT
        .get()
        .ok_or_else(|| "structured result recorder is not initialized".to_string())?;
    let mut report = report
        .lock()
        .map_err(|_| "structured result recorder lock is poisoned".to_string())?;
    report.finish();
    let default = format!(
        "/workspace/artifacts/{}-{}-test-results.json",
        report.deployment_id, report.lane
    );
    let path = PathBuf::from(
        env::var("E2E_RESULTS_PATH")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(default),
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    write_json(&path, &*report)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_states_do_not_merge_non_pass_with_pass() {
        let mut report = RunReport::new("unit", "devel-fast");
        let initial_known_bugs = report
            .observations
            .iter()
            .filter(|observation| observation.outcome == Outcome::KnownUpstreamBug)
            .count();
        report.observations.push(Observation {
            name: "conditional".to_string(),
            outcome: Outcome::ConditionalUnavailable,
            evidence: "help omitted command".to_string(),
        });
        report.observations.push(Observation {
            name: "known upstream bug".to_string(),
            outcome: Outcome::KnownUpstreamBug,
            evidence: "rust-gvm#405".to_string(),
        });
        report.finish();
        assert_eq!(
            report.outcome_counts.get("conditional-unavailable"),
            Some(&1)
        );
        assert_eq!(
            report.outcome_counts.get("known-upstream-bug"),
            Some(&(initial_known_bugs + 1))
        );
        assert_eq!(report.outcome_counts.get("pass"), None);
    }

    #[test]
    fn report_config_crash_disposition_is_known_bug_not_pass_or_generic_skip() {
        let mut report = RunReport::new("unit", "devel-isolated");
        let names = report
            .observations
            .iter()
            .filter(|observation| observation.evidence == REPORT_CONFIG_CRASH_EVIDENCE)
            .map(|observation| observation.name.as_str())
            .collect::<Vec<_>>();
        for name in [
            "command:create_report_config",
            "command:delete_report_config",
            "command:modify_report_config",
            "helper:create_report_config",
            "helper:clone_report_config",
            "helper:delete_report_config",
            "helper:modify_report_config",
        ] {
            assert!(
                names.contains(&name),
                "missing explicit disposition for {name}"
            );
        }
        assert!(report.observations.iter().all(|observation| {
            observation.evidence != REPORT_CONFIG_CRASH_EVIDENCE
                || observation.outcome == Outcome::KnownUpstreamBug
        }));
        report.finish();
        assert_eq!(report.outcome_counts.get("known-upstream-bug"), Some(&7));
        assert_eq!(report.outcome_counts.get("pass"), None);
        assert_eq!(report.outcome_counts.get("conditional-unavailable"), None);
    }

    #[test]
    fn runtime_image_provenance_is_nonempty_complete_and_unique() {
        let valid = [RuntimeImage {
            service: "gvmd".to_string(),
            repository: "registry.example/gvmd".to_string(),
            tag: "stable".to_string(),
            digest: "sha256:abc".to_string(),
        }];
        validate_runtime_image_rows(&valid, "unit").expect("valid provenance");
        assert!(validate_runtime_image_rows(&[], "unit").is_err());
        let duplicate = [valid[0].clone(), valid[0].clone()];
        assert!(validate_runtime_image_rows(&duplicate, "unit")
            .unwrap_err()
            .contains("repeats service"));
        let incomplete = [RuntimeImage {
            digest: String::new(),
            ..valid[0].clone()
        }];
        assert!(validate_runtime_image_rows(&incomplete, "unit")
            .unwrap_err()
            .contains("empty service or digest"));
    }
}
