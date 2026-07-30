// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Structured lane results and recorded Community runtime evidence.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{Disposition, COMMAND_COVERAGE, HELPER_COVERAGE, RUST_GVM_SHA};

static REPORT: OnceLock<Mutex<RunReport>> = OnceLock::new();

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
}

/// Recorded `get_features` state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeatureState {
    pub compiled_in: bool,
    pub enabled: bool,
}

/// Pinned Community baseline checked into the repository.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommunityBaseline {
    pub schema_version: u32,
    pub gvm_image_tag: String,
    pub gmp_version: String,
    pub rust_gvm_sha: String,
    pub features: BTreeMap<String, FeatureState>,
    pub help_commands: Vec<String>,
    pub conditional_commands: BTreeMap<String, bool>,
    pub registry_version_gates: BTreeMap<String, bool>,
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
            .filter(|entry| entry.disposition == Disposition::ExcludedCommunity)
        {
            observations.push(Observation {
                name: format!("command:{}", entry.name),
                outcome: Outcome::Excluded,
                evidence: "issue #118 explicit Community edition boundary".to_string(),
            });
        }
        for entry in HELPER_COVERAGE
            .iter()
            .filter(|entry| entry.disposition == Disposition::ExcludedCommunity)
        {
            observations.push(Observation {
                name: format!("helper:{}", entry.name),
                outcome: Outcome::Excluded,
                evidence: "issue #118 explicit Community edition boundary".to_string(),
            });
        }
        Self {
            schema_version: 1,
            run_id: run_id.to_string(),
            lane: lane.to_string(),
            started_unix_seconds: now(),
            finished_unix_seconds: None,
            rust_gvm_sha: env::var("E2E_RUST_GVM_SHA").unwrap_or_else(|_| RUST_GVM_SHA.to_string()),
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

/// Finalize and write the report to the configured artifact path.
pub fn write() -> Result<PathBuf, String> {
    let report = REPORT
        .get()
        .ok_or_else(|| "structured result recorder is not initialized".to_string())?;
    let mut report = report
        .lock()
        .map_err(|_| "structured result recorder lock is poisoned".to_string())?;
    report.finish();
    let default = format!("/workspace/artifacts/community-e2e-{}.json", report.lane);
    let path = PathBuf::from(
        env::var("E2E_RESULTS_PATH")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(default),
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let payload = serde_json::to_string_pretty(&*report).map_err(|error| error.to_string())?;
    fs::write(&path, format!("{payload}\n")).map_err(|error| error.to_string())?;
    Ok(path)
}

/// Load the checked-in baseline.
pub fn baseline() -> Result<CommunityBaseline, String> {
    serde_json::from_str(include_str!("../../../baselines/community-stable.json"))
        .map_err(|error| error.to_string())
}

fn normalized_help_commands(commands: &[String]) -> Vec<String> {
    let mut commands = commands.to_vec();
    commands.sort();
    commands.dedup();
    commands
}

/// Compare typed discovery with the pinned baseline.
pub fn validate_baseline(
    gmp_version: &str,
    features: &BTreeMap<String, FeatureState>,
    help_commands: &[String],
    conditional_commands: &BTreeMap<String, bool>,
    registry_version_gates: &BTreeMap<String, bool>,
) -> Result<(), String> {
    let expected = baseline()?;
    let image_tag = env::var("GVM_VERSION").unwrap_or_else(|_| "stable".to_string());
    if expected.gvm_image_tag != image_tag {
        return Err(format!(
            "baseline image tag mismatch: expected {}, observed {image_tag}",
            expected.gvm_image_tag
        ));
    }
    if expected.rust_gvm_sha != RUST_GVM_SHA {
        return Err(format!(
            "baseline rust-gvm mismatch: expected {}, compiled {RUST_GVM_SHA}",
            expected.rust_gvm_sha
        ));
    }
    if expected.gmp_version != gmp_version {
        return Err(format!(
            "baseline GMP version changed: expected {}, observed {gmp_version}",
            expected.gmp_version
        ));
    }
    if !expected.features.is_empty() && expected.features != *features {
        return Err(format!(
            "advertised feature baseline changed: expected {:?}, observed {features:?}",
            expected.features
        ));
    }
    if normalized_help_commands(&expected.help_commands) != normalized_help_commands(help_commands)
    {
        return Err(format!(
            "advertised help baseline changed: expected {:?}, observed {help_commands:?}",
            expected.help_commands
        ));
    }
    if expected.conditional_commands != *conditional_commands {
        return Err(format!(
            "conditional command availability changed: expected {:?}, observed {conditional_commands:?}",
            expected.conditional_commands
        ));
    }
    if expected.registry_version_gates != *registry_version_gates {
        return Err(format!(
            "registry version-gate diagnostics changed: expected {:?}, observed {registry_version_gates:?}",
            expected.registry_version_gates
        ));
    }
    Ok(())
}

/// Write an observed candidate baseline during an explicit recording run.
pub fn write_baseline_candidate(
    gmp_version: &str,
    features: &BTreeMap<String, FeatureState>,
    help_commands: &[String],
    conditional_commands: &BTreeMap<String, bool>,
    registry_version_gates: &BTreeMap<String, bool>,
) -> Result<PathBuf, String> {
    let baseline = CommunityBaseline {
        schema_version: 1,
        gvm_image_tag: env::var("GVM_VERSION").unwrap_or_else(|_| "stable".to_string()),
        gmp_version: gmp_version.to_string(),
        rust_gvm_sha: RUST_GVM_SHA.to_string(),
        features: features.clone(),
        help_commands: help_commands.to_vec(),
        conditional_commands: conditional_commands.clone(),
        registry_version_gates: registry_version_gates.clone(),
    };
    let path = Path::new("/workspace/artifacts/community-baseline-candidate.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let payload = serde_json::to_string_pretty(&baseline).map_err(|error| error.to_string())?;
    fs::write(path, format!("{payload}\n")).map_err(|error| error.to_string())?;
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_states_do_not_merge_non_pass_with_pass() {
        let mut report = RunReport::new("unit", "devel-fast");
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
        assert_eq!(report.outcome_counts.get("known-upstream-bug"), Some(&1));
        assert_eq!(report.outcome_counts.get("pass"), None);
    }

    #[test]
    fn checked_in_baseline_parses() {
        let parsed = baseline().expect("baseline parses");
        assert_eq!(parsed.schema_version, 1);
        assert_eq!(parsed.gvm_image_tag, "stable");
        assert_eq!(parsed.help_commands.len(), 127);
        assert!(parsed
            .help_commands
            .iter()
            .any(|name| name == "get_audit_report"));
        assert!(parsed.help_commands.iter().any(|name| name == "get_tasks"));
        assert_eq!(
            parsed.conditional_commands.get("get_report_hosts"),
            Some(&true)
        );
        assert_eq!(
            parsed.registry_version_gates.get("get_report_hosts"),
            Some(&false)
        );
    }

    #[test]
    fn help_baseline_comparison_is_order_independent() {
        let observed = vec!["get_nvt_families".to_string(), "get_nvts".to_string()];
        let recorded = vec!["get_nvts".to_string(), "get_nvt_families".to_string()];
        assert_eq!(
            normalized_help_commands(&observed),
            normalized_help_commands(&recorded)
        );
    }
}
