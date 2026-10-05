// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Fail-closed deployment capability discovery, planning, and reconciliation.

use std::collections::{BTreeMap, BTreeSet};

use quick_xml::events::Event;
use quick_xml::Reader;
use serde::{Deserialize, Serialize};

use crate::LiveHelpAllowlistEntry;

/// Schema version for deployment capability snapshots.
///
/// Optional provenance fields are additive, so they remain compatible with the
/// original snapshot schema consumed by [`build_plan`].
pub const DEPLOYMENT_CAPABILITIES_SCHEMA_VERSION: u32 = 1;

/// The deployment's policy for an observed capability or fixture.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Requirement {
    Required,
    Optional,
    Forbidden,
}

/// A minimal expected-capability contract supplied by a deployment provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentContract {
    pub schema_version: u32,
    pub deployment_id: String,
    #[serde(default)]
    pub allow_legacy_fallback: BTreeSet<String>,
    #[serde(default)]
    pub features: BTreeMap<String, Requirement>,
    #[serde(default)]
    pub fixtures: BTreeMap<String, Requirement>,
}

/// Origin and summary of one observed fact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Evidence {
    pub source: String,
    pub value: String,
    pub detail: String,
}

/// Feature flags preserve absence of legacy response attributes as unknown.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedFeature {
    pub compiled_in: Option<bool>,
    pub enabled: Option<bool>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

/// Health state for a non-mutating feature probe.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeState {
    Ready,
    Unavailable,
    Unhealthy,
    Unknown,
}

/// Result of a safe readiness probe or provider-owned fixture check.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProbeResult {
    pub state: ProbeState,
    pub evidence: Evidence,
}

/// Non-secret provider evidence loaded before connecting to gvmd.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEvidence {
    pub state: ProbeState,
    pub detail: String,
}

/// Provider-owned fixture and out-of-band probe descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureDescriptor {
    pub schema_version: u32,
    pub deployment_id: String,
    #[serde(default)]
    pub fixtures: BTreeMap<String, ProviderEvidence>,
    #[serde(default)]
    pub probes: BTreeMap<String, ProviderEvidence>,
}

/// Authenticated command visibility.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandSupport {
    pub advertised: bool,
    pub evidence: Evidence,
}

/// Owned reviewed evidence for one exact allowlisted live-help command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AllowlistedLiveHelpCommand {
    pub name: String,
    pub rationale: String,
    pub evidence_source: String,
    pub evidence_detail: String,
}

/// Exhaustive classification of the authenticated live-help command set.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveHelpParity {
    pub advertised_commands: Vec<String>,
    pub modeled_commands: Vec<String>,
    pub allowlisted_commands: Vec<AllowlistedLiveHelpCommand>,
    pub unknown_commands: Vec<String>,
}

/// Classify every advertised command against the generated modeled inventory
/// and the reviewed exact-name allowlist.
pub fn classify_live_help_commands(
    advertised: &BTreeSet<String>,
    modeled: &BTreeSet<String>,
    allowlist: &[LiveHelpAllowlistEntry],
) -> Result<LiveHelpParity, String> {
    let mut reviewed = BTreeMap::new();
    for entry in allowlist {
        if modeled.contains(entry.name) {
            return Err(format!(
                "live-help allowlist command is already modeled: {}",
                entry.name
            ));
        }
        if reviewed.insert(entry.name, entry).is_some() {
            return Err(format!(
                "live-help allowlist repeats exact command {}",
                entry.name
            ));
        }
    }

    let mut parity = LiveHelpParity {
        advertised_commands: advertised.iter().cloned().collect(),
        ..LiveHelpParity::default()
    };
    for name in advertised {
        if modeled.contains(name) {
            parity.modeled_commands.push(name.clone());
        } else if let Some(entry) = reviewed.get(name.as_str()) {
            parity
                .allowlisted_commands
                .push(AllowlistedLiveHelpCommand {
                    name: name.clone(),
                    rationale: entry.rationale.to_string(),
                    evidence_source: entry.evidence_source.to_string(),
                    evidence_detail: entry.evidence_detail.to_string(),
                });
        } else {
            parity.unknown_commands.push(name.clone());
        }
    }
    Ok(parity)
}

/// Reject any authenticated live-help command without an exact reviewed
/// disposition. The caller publishes the parity object before returning this
/// error, so the unknown names remain machine-readable.
pub fn enforce_live_help_parity(parity: &LiveHelpParity) -> Result<(), String> {
    if parity.unknown_commands.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "authenticated live-help reverse parity failed; unknown advertised commands: {}",
            parity.unknown_commands.join(", ")
        ))
    }
}

/// Complete deployment-neutral discovery artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeploymentCapabilities {
    pub schema_version: u32,
    pub deployment_id: String,
    pub gmp_version: Option<String>,
    pub gvmd_version: Option<String>,
    pub gvmd_source_revision: Option<String>,
    pub gvmd_image_digest: Option<String>,
    #[serde(default)]
    pub live_help_parity: LiveHelpParity,
    #[serde(default)]
    pub features: BTreeMap<String, ObservedFeature>,
    #[serde(default)]
    pub commands: BTreeMap<String, CommandSupport>,
    #[serde(default)]
    pub probes: BTreeMap<String, ProbeResult>,
    #[serde(default)]
    pub fixtures: BTreeMap<String, ProbeResult>,
}

/// Resolved state after applying evidence precedence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectiveState {
    Ready,
    Unsupported,
    Disabled,
    EnabledUnhealthy,
    Unknown,
    Contradictory,
}

/// Catalog entry mapping one gvmd flag to protocol and operational evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureCatalogEntry {
    #[serde(default)]
    pub commands: BTreeSet<String>,
    pub probe: Option<String>,
    pub fixture: Option<String>,
    #[serde(default)]
    pub scenarios: BTreeMap<String, ScenarioRequirement>,
}

/// Lane and public implementation state for one feature scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioRequirement {
    pub lane: String,
    pub implemented: bool,
}

/// Checked-in feature-to-coverage catalog.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureCatalog {
    pub schema_version: u32,
    pub features: BTreeMap<String, FeatureCatalogEntry>,
}

/// A command, helper, or scenario independently considered by the planner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanInput {
    pub kind: PlanEntryKind,
    pub name: String,
    pub lane: String,
    pub feature: Option<String>,
    pub wire_command: Option<String>,
    pub command_optional: bool,
    pub implemented: bool,
    /// Whether the negotiated GMP version permits the exact typed semantic.
    pub semantic_eligible: bool,
    /// Concrete pre-execution evidence for the semantic-version decision.
    pub semantic_evidence: String,
}

/// Independently reconciled coverage surface.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanEntryKind {
    Command,
    Helper,
    Scenario,
}

/// Pre-mutation planner decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanDecision {
    Selected,
    NotSelected,
    Blocked,
    CoverageGap,
}

/// One deterministic plan row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlanEntry {
    pub kind: PlanEntryKind,
    pub name: String,
    pub lane: String,
    pub feature: Option<String>,
    pub decision: PlanDecision,
    pub evidence: String,
}

/// Pre-mutation plan artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TestPlan {
    pub schema_version: u32,
    pub deployment_id: String,
    pub lane: String,
    pub entries: Vec<PlanEntry>,
}

/// A selected plan entry's terminal execution state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TerminalOutcome {
    Pass,
    Fail,
    Conditional,
}

/// Execution record consumed by exact reconciliation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionResult {
    pub kind: PlanEntryKind,
    pub name: String,
    pub outcome: TerminalOutcome,
    pub evidence: String,
}

fn parse_bool(value: &str, field: &str) -> Result<bool, String> {
    match value {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(format!("invalid {field} boolean `{value}`")),
    }
}

/// Parse both current two-attribute and legacy enabled-only feature XML.
pub fn parse_feature_evidence(xml: &[u8]) -> Result<BTreeMap<String, ObservedFeature>, String> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut result = BTreeMap::new();
    let mut current: Option<(Option<bool>, Option<bool>)> = None;
    let mut in_name = false;
    let mut name = String::new();
    loop {
        match reader.read_event().map_err(|error| error.to_string())? {
            Event::Start(event) if event.name().as_ref() == "feature" => {
                let mut compiled_in = None;
                let mut enabled = None;
                for attribute in event.attributes() {
                    let attribute = attribute.map_err(|error| error.to_string())?;
                    match attribute.key.as_ref() {
                        "compiled_in" => {
                            compiled_in = Some(parse_bool(&attribute.value, "compiled_in")?)
                        }
                        "enabled" => enabled = Some(parse_bool(&attribute.value, "enabled")?),
                        _ => {}
                    }
                }
                current = Some((compiled_in, enabled));
                name.clear();
            }
            Event::Start(event) if current.is_some() && event.name().as_ref() == "name" => {
                in_name = true;
            }
            Event::Text(text) if in_name => {
                name.push_str(text.as_ref());
            }
            Event::End(event) if event.name().as_ref() == "name" => in_name = false,
            Event::End(event) if event.name().as_ref() == "feature" => {
                let (compiled_in, enabled) = current
                    .take()
                    .ok_or_else(|| "feature end without start".to_string())?;
                if name.trim().is_empty() {
                    return Err("feature response contains an empty name".to_string());
                }
                if enabled.is_none() {
                    return Err(format!("feature {name} omitted required enabled evidence"));
                }
                let shape = if compiled_in.is_some() {
                    "current-two-attribute"
                } else {
                    "legacy-enabled-only"
                };
                let feature = ObservedFeature {
                    compiled_in,
                    enabled,
                    evidence: vec![Evidence {
                        source: "get_features".to_string(),
                        value: shape.to_string(),
                        detail: format!("compiled_in={compiled_in:?}; enabled={enabled:?}"),
                    }],
                };
                if result.insert(name.clone(), feature).is_some() {
                    return Err(format!("feature response repeats {name}"));
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(result)
}

fn operational_state(
    snapshot: &DeploymentCapabilities,
    catalog: &FeatureCatalogEntry,
) -> ProbeState {
    for key in catalog.probe.iter().chain(catalog.fixture.iter()) {
        let result = if catalog.probe.as_ref() == Some(key) {
            snapshot.probes.get(key)
        } else {
            snapshot.fixtures.get(key)
        };
        match result
            .map(|result| result.state)
            .unwrap_or(ProbeState::Unknown)
        {
            ProbeState::Ready => {}
            state => return state,
        }
    }
    ProbeState::Ready
}

/// Resolve direct flags first, then authenticated help and operational evidence.
pub fn effective_state(
    feature: Option<&ObservedFeature>,
    catalog: &FeatureCatalogEntry,
    snapshot: &DeploymentCapabilities,
    allow_legacy_fallback: bool,
) -> EffectiveState {
    let Some(feature) = feature else {
        return EffectiveState::Unknown;
    };
    if feature.compiled_in == Some(false) && feature.enabled == Some(true) {
        return EffectiveState::Contradictory;
    }
    if feature.compiled_in == Some(false) {
        return EffectiveState::Unsupported;
    }
    if feature.enabled == Some(false) {
        return EffectiveState::Disabled;
    }
    if feature.compiled_in.is_none() && feature.enabled == Some(true) && !allow_legacy_fallback {
        return EffectiveState::Unknown;
    }
    let all_advertised = catalog.commands.iter().all(|command| {
        snapshot
            .commands
            .get(command)
            .is_some_and(|support| support.advertised)
    });
    if feature.enabled == Some(true) && !all_advertised {
        return EffectiveState::Contradictory;
    }
    let operational = operational_state(snapshot, catalog);
    if feature.enabled == Some(true) {
        return match operational {
            ProbeState::Ready => EffectiveState::Ready,
            ProbeState::Unavailable | ProbeState::Unhealthy | ProbeState::Unknown => {
                EffectiveState::EnabledUnhealthy
            }
        };
    }
    if allow_legacy_fallback && all_advertised && operational == ProbeState::Ready {
        EffectiveState::Ready
    } else {
        EffectiveState::Unknown
    }
}

fn decision_for(requirement: Requirement, state: EffectiveState) -> (PlanDecision, &'static str) {
    match (requirement, state) {
        (Requirement::Forbidden, EffectiveState::Ready | EffectiveState::EnabledUnhealthy) => {
            (PlanDecision::Blocked, "forbidden capability is present")
        }
        (Requirement::Forbidden, EffectiveState::Contradictory) => (
            PlanDecision::Blocked,
            "forbidden capability evidence is contradictory",
        ),
        (Requirement::Forbidden, EffectiveState::Unsupported | EffectiveState::Disabled) => (
            PlanDecision::NotSelected,
            "forbidden capability is conclusively absent",
        ),
        (Requirement::Forbidden, EffectiveState::Unknown) => (
            PlanDecision::Blocked,
            "forbidden capability absence is not proven",
        ),
        (_, EffectiveState::Contradictory) => (
            PlanDecision::Blocked,
            "enabled feature command evidence is contradictory",
        ),
        (_, EffectiveState::EnabledUnhealthy) => (
            PlanDecision::Blocked,
            "enabled feature readiness probe is unhealthy",
        ),
        (Requirement::Required, EffectiveState::Ready) => {
            (PlanDecision::Selected, "required capability is ready")
        }
        (Requirement::Required, _) => (
            PlanDecision::Blocked,
            "required capability is not conclusively ready",
        ),
        (Requirement::Optional, EffectiveState::Ready) => {
            (PlanDecision::Selected, "optional capability is ready")
        }
        (Requirement::Optional, _) => (
            PlanDecision::NotSelected,
            "optional capability is unavailable with explicit evidence",
        ),
    }
}

/// Build and validate a stable plan before any cleanup or test mutation.
pub fn build_plan(
    contract: &DeploymentContract,
    catalog: &FeatureCatalog,
    snapshot: &DeploymentCapabilities,
    lane: &str,
    inputs: impl IntoIterator<Item = PlanInput>,
) -> Result<TestPlan, String> {
    if contract.schema_version != 1
        || catalog.schema_version != 1
        || snapshot.schema_version != DEPLOYMENT_CAPABILITIES_SCHEMA_VERSION
    {
        return Err("unsupported capability schema version".to_string());
    }
    if contract.deployment_id != snapshot.deployment_id {
        return Err(format!(
            "deployment identity mismatch: contract={}, observed={}",
            contract.deployment_id, snapshot.deployment_id
        ));
    }
    for feature in &contract.allow_legacy_fallback {
        if contract.features.get(feature) != Some(&Requirement::Optional) {
            return Err(format!(
                "legacy fallback is allowed only for contracted optional features: {feature}"
            ));
        }
    }
    for feature in contract.features.keys() {
        if !catalog.features.contains_key(feature) {
            return Err(format!("contract references unmapped feature {feature}"));
        }
    }
    for (feature, observed) in &snapshot.features {
        if observed.enabled == Some(true) && !catalog.features.contains_key(feature) {
            return Err(format!(
                "enabled feature {feature} has no catalog/scenario mapping"
            ));
        }
    }

    let mut feature_decisions = BTreeMap::new();
    for (feature, requirement) in &contract.features {
        let mapping = &catalog.features[feature];
        if mapping.scenarios.is_empty() {
            return Err(format!(
                "known feature {feature} has no executable scenario mapping"
            ));
        }
        let state = effective_state(
            snapshot.features.get(feature),
            mapping,
            snapshot,
            contract.allow_legacy_fallback.contains(feature),
        );
        let advertised_presence = mapping.commands.iter().any(|command| {
            snapshot
                .commands
                .get(command)
                .is_some_and(|support| support.advertised)
        });
        let decision = if *requirement == Requirement::Forbidden && advertised_presence {
            (
                PlanDecision::Blocked,
                "forbidden capability command is advertised",
            )
        } else {
            decision_for(*requirement, state)
        };
        feature_decisions.insert(feature.clone(), (state, decision));
    }
    let feature_blocks = feature_decisions
        .iter()
        .filter(|(_, (_, (decision, _)))| *decision == PlanDecision::Blocked)
        .map(|(feature, (state, (_, reason)))| {
            format!("{feature}: {reason}; effective_state={state:?}")
        })
        .collect::<Vec<_>>();
    if !feature_blocks.is_empty() {
        return Err(format!(
            "deployment contract validation blocked before mutation: {}",
            feature_blocks.join(", ")
        ));
    }

    for (fixture, requirement) in &contract.fixtures {
        let state = snapshot
            .fixtures
            .get(fixture)
            .map(|result| result.state)
            .unwrap_or(ProbeState::Unknown);
        let invalid = match requirement {
            Requirement::Required => state != ProbeState::Ready,
            Requirement::Forbidden => state != ProbeState::Unavailable,
            Requirement::Optional => state == ProbeState::Unhealthy,
        };
        if invalid {
            return Err(format!(
                "fixture contract violation: {fixture} is {requirement:?}, observed {state:?}"
            ));
        }
    }

    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for input in inputs {
        if input.lane != lane && input.lane != "all" {
            continue;
        }
        if !seen.insert((input.kind, input.name.clone())) {
            return Err(format!(
                "duplicate plan entry {:?}:{}",
                input.kind, input.name
            ));
        }
        let (mut decision, mut evidence) = if !input.semantic_eligible {
            (PlanDecision::NotSelected, input.semantic_evidence.clone())
        } else {
            match &input.feature {
                None => match input.wire_command.as_deref() {
                    // gvmd implements these discovery commands but omits them from
                    // authenticated brief help. Both still execute and must pass
                    // their direct live assertions before any mutation begins.
                    Some("get_features" | "get_resource_names") => (
                        PlanDecision::Selected,
                        "discovery command is validated directly".to_string(),
                    ),
                    Some(command)
                        if snapshot
                            .commands
                            .get(command)
                            .is_some_and(|support| support.advertised) =>
                    {
                        (
                            PlanDecision::Selected,
                            "deployment-independent command is advertised".to_string(),
                        )
                    }
                    Some(_) if input.command_optional => (
                        PlanDecision::NotSelected,
                        "optional command is not advertised".to_string(),
                    ),
                    Some(command) => (
                        PlanDecision::Blocked,
                        format!("required lane command {command} is not advertised"),
                    ),
                    None => (
                        PlanDecision::Selected,
                        "deployment-independent lane scenario".to_string(),
                    ),
                },
                Some(feature) => {
                    let (state, (decision, reason)) =
                        feature_decisions.get(feature).ok_or_else(|| {
                            format!(
                                "plan entry {:?}:{} references uncontracted feature {feature}",
                                input.kind, input.name
                            )
                        })?;
                    (*decision, format!("{reason}; effective_state={state:?}"))
                }
            }
        };
        if decision == PlanDecision::Selected && !input.implemented {
            if input.feature.is_some() {
                decision = PlanDecision::CoverageGap;
                evidence =
                    "enabled feature entry has no cleanup-safe public execution path".to_string();
            } else {
                decision = PlanDecision::NotSelected;
                evidence =
                    "registered surface has no deterministic public execution path".to_string();
            }
        }
        entries.push(PlanEntry {
            kind: input.kind,
            name: input.name,
            lane: input.lane,
            feature: input.feature,
            decision,
            evidence,
        });
    }
    entries.sort_by(|left, right| (left.kind, &left.name).cmp(&(right.kind, &right.name)));
    let blocked = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.decision,
                PlanDecision::Blocked | PlanDecision::CoverageGap
            )
        })
        .map(|entry| format!("{:?}:{} ({})", entry.kind, entry.name, entry.evidence))
        .collect::<Vec<_>>();
    if !blocked.is_empty() {
        return Err(format!(
            "capability planning blocked before mutation: {}",
            blocked.join(", ")
        ));
    }
    Ok(TestPlan {
        schema_version: 1,
        deployment_id: contract.deployment_id.clone(),
        lane: lane.to_string(),
        entries,
    })
}

/// Require every selected entry to have exactly one successful terminal result.
pub fn reconcile(plan: &TestPlan, results: &[ExecutionResult]) -> Result<(), String> {
    let selected = plan
        .entries
        .iter()
        .filter(|entry| entry.decision == PlanDecision::Selected)
        .map(|entry| (entry.kind, entry.name.as_str()))
        .collect::<BTreeSet<_>>();
    let mut observed = BTreeMap::new();
    for result in results {
        let key = (result.kind, result.name.as_str());
        if !selected.contains(&key) {
            return Err(format!(
                "unexpected execution {:?}:{}",
                result.kind, result.name
            ));
        }
        if observed.insert(key, result.outcome).is_some() {
            return Err(format!(
                "duplicate terminal result {:?}:{}",
                result.kind, result.name
            ));
        }
        if result.outcome != TerminalOutcome::Pass {
            return Err(format!(
                "selected entry did not pass {:?}:{} ({:?})",
                result.kind, result.name, result.outcome
            ));
        }
    }
    let missing = selected
        .iter()
        .filter(|key| !observed.contains_key(*key))
        .map(|(kind, name)| format!("{kind:?}:{name}"))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "selected entries have no terminal result: {}",
            missing.join(", ")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(source: &str) -> Evidence {
        Evidence {
            source: source.into(),
            value: "test".into(),
            detail: "fixture".into(),
        }
    }

    fn catalog() -> FeatureCatalog {
        FeatureCatalog {
            schema_version: 1,
            features: BTreeMap::from([(
                "ENABLE_AGENTS".into(),
                FeatureCatalogEntry {
                    commands: BTreeSet::from(["get_agents".into()]),
                    probe: Some("agents".into()),
                    fixture: Some("agent_endpoint".into()),
                    scenarios: BTreeMap::from([(
                        "agent-read".into(),
                        ScenarioRequirement {
                            lane: "devel-fast".into(),
                            implemented: true,
                        },
                    )]),
                },
            )]),
        }
    }

    fn snapshot(
        feature: ObservedFeature,
        advertised: bool,
        probe: ProbeState,
    ) -> DeploymentCapabilities {
        DeploymentCapabilities {
            schema_version: DEPLOYMENT_CAPABILITIES_SCHEMA_VERSION,
            deployment_id: "test".into(),
            gmp_version: Some("22.7".into()),
            gvmd_version: None,
            gvmd_source_revision: None,
            gvmd_image_digest: None,
            live_help_parity: LiveHelpParity::default(),
            features: BTreeMap::from([("ENABLE_AGENTS".into(), feature)]),
            commands: BTreeMap::from([(
                "get_agents".into(),
                CommandSupport {
                    advertised,
                    evidence: evidence("help"),
                },
            )]),
            probes: BTreeMap::from([(
                "agents".into(),
                ProbeResult {
                    state: probe,
                    evidence: evidence("probe"),
                },
            )]),
            fixtures: BTreeMap::from([(
                "agent_endpoint".into(),
                ProbeResult {
                    state: ProbeState::Ready,
                    evidence: evidence("provider"),
                },
            )]),
        }
    }

    fn contract(requirement: Requirement, legacy: bool) -> DeploymentContract {
        DeploymentContract {
            schema_version: 1,
            deployment_id: "test".into(),
            allow_legacy_fallback: if legacy {
                BTreeSet::from(["ENABLE_AGENTS".into()])
            } else {
                BTreeSet::new()
            },
            features: BTreeMap::from([("ENABLE_AGENTS".into(), requirement)]),
            fixtures: BTreeMap::new(),
        }
    }

    #[test]
    fn discovery_commands_omitted_from_brief_help_are_validated_directly() {
        let observed = snapshot(
            ObservedFeature {
                compiled_in: Some(true),
                enabled: Some(false),
                evidence: vec![evidence("get_features")],
            },
            false,
            ProbeState::Unavailable,
        );
        let direct_input = |kind, name: &str, wire_command: &str| PlanInput {
            kind,
            name: name.into(),
            lane: "devel-fast".into(),
            feature: None,
            wire_command: Some(wire_command.into()),
            command_optional: false,
            implemented: true,
            semantic_eligible: true,
            semantic_evidence: "eligible".into(),
        };

        let plan = build_plan(
            &contract(Requirement::Optional, false),
            &catalog(),
            &observed,
            "devel-fast",
            [
                direct_input(PlanEntryKind::Command, "get_features", "get_features"),
                direct_input(
                    PlanEntryKind::Command,
                    "get_resource_names",
                    "get_resource_names",
                ),
                direct_input(
                    PlanEntryKind::Helper,
                    "get_resource_name",
                    "get_resource_names",
                ),
                direct_input(
                    PlanEntryKind::Helper,
                    "get_resource_names",
                    "get_resource_names",
                ),
            ],
        )
        .expect("directly validated discovery commands must not depend on brief help");

        assert!(plan.entries.iter().all(|entry| {
            entry.decision == PlanDecision::Selected
                && entry.evidence == "discovery command is validated directly"
        }));

        let error = build_plan(
            &contract(Requirement::Optional, false),
            &catalog(),
            &observed,
            "devel-fast",
            [direct_input(
                PlanEntryKind::Command,
                "get_version",
                "get_version",
            )],
        )
        .expect_err("ordinary required commands must still fail closed");
        assert!(error.contains("required lane command get_version is not advertised"));
    }

    #[test]
    fn capability_snapshot_v1_with_additive_provenance_builds_a_plan() {
        assert_eq!(DEPLOYMENT_CAPABILITIES_SCHEMA_VERSION, 1);
        let mut observed = snapshot(
            ObservedFeature {
                compiled_in: Some(true),
                enabled: Some(true),
                evidence: vec![evidence("get_features")],
            },
            true,
            ProbeState::Ready,
        );
        observed.gvmd_version = Some("26.40.2".into());
        observed.gvmd_source_revision = Some("471b7745697af0ee0804212c74f5040f30c6c3d7".into());
        observed.gvmd_image_digest =
            Some("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into());

        let plan = build_plan(
            &contract(Requirement::Optional, false),
            &catalog(),
            &observed,
            "devel-fast",
            [input()],
        )
        .expect("v1 discovery snapshot with additive provenance must be plannable");

        assert_eq!(observed.schema_version, 1);
        assert_eq!(plan.schema_version, 1);
    }

    fn input() -> PlanInput {
        PlanInput {
            kind: PlanEntryKind::Scenario,
            name: "agent-read".into(),
            lane: "devel-fast".into(),
            feature: Some("ENABLE_AGENTS".into()),
            wire_command: None,
            command_optional: false,
            implemented: true,
            semantic_eligible: true,
            semantic_evidence: "GMP 22.7 satisfies the typed semantic".into(),
        }
    }

    #[derive(Deserialize)]
    struct LiveHelpFixture {
        schema_version: u32,
        cases: Vec<LiveHelpFixtureCase>,
    }

    #[derive(Deserialize)]
    struct LiveHelpFixtureCase {
        name: String,
        advertised_commands: Vec<String>,
        expected_modeled: Vec<String>,
        expected_allowlisted: Vec<String>,
        expected_unknown: Vec<String>,
    }

    #[test]
    fn live_help_reverse_parity_fixture_covers_modeled_and_unknown_after_allowlist_removal() {
        let fixture: LiveHelpFixture =
            serde_json::from_str(include_str!("../../../fixtures/live-help-parity.json"))
                .expect("live-help parity fixture must parse");
        assert_eq!(fixture.schema_version, 1);
        let modeled = BTreeSet::from([
            "cancel_report_export".to_string(),
            "get_version".to_string(),
        ]);
        for case in fixture.cases {
            let advertised = case.advertised_commands.into_iter().collect();
            let parity =
                classify_live_help_commands(&advertised, &modeled, crate::LIVE_HELP_ALLOWLIST)
                    .unwrap_or_else(|error| panic!("fixture {} policy failed: {error}", case.name));
            assert_eq!(
                parity.modeled_commands, case.expected_modeled,
                "{}",
                case.name
            );
            assert_eq!(
                parity
                    .allowlisted_commands
                    .iter()
                    .map(|entry| entry.name.clone())
                    .collect::<Vec<_>>(),
                case.expected_allowlisted,
                "{}",
                case.name
            );
            assert_eq!(
                parity.unknown_commands, case.expected_unknown,
                "{}",
                case.name
            );
            let artifact = serde_json::to_value(&parity)
                .unwrap_or_else(|error| panic!("fixture {} must serialize: {error}", case.name));
            assert_eq!(
                artifact["unknown_commands"],
                serde_json::json!(parity.unknown_commands),
                "{}",
                case.name
            );
            if parity.unknown_commands.is_empty() {
                enforce_live_help_parity(&parity)
                    .unwrap_or_else(|error| panic!("fixture {} must pass: {error}", case.name));
            } else {
                let error = enforce_live_help_parity(&parity)
                    .expect_err("synthetic unknown command must fail closed");
                assert!(error.contains(&parity.unknown_commands.join(", ")));
            }
        }
    }

    #[test]
    fn parses_current_and_legacy_feature_evidence_without_inventing_compiled_state() {
        let parsed = parse_feature_evidence(br#"<get_features_response><feature compiled_in="1" enabled="1"><name>ENABLE_AGENTS</name></feature><feature enabled="0"><name>ENABLE_JWT_AUTH</name></feature></get_features_response>"#).unwrap();
        assert_eq!(parsed["ENABLE_AGENTS"].compiled_in, Some(true));
        assert_eq!(parsed["ENABLE_JWT_AUTH"].compiled_in, None);
        assert_eq!(parsed["ENABLE_JWT_AUTH"].enabled, Some(false));
        assert_eq!(
            parsed["ENABLE_JWT_AUTH"].evidence[0].value,
            "legacy-enabled-only"
        );
    }

    #[test]
    fn required_unknown_fails_but_explicit_optional_legacy_fallback_selects() {
        let legacy = ObservedFeature {
            compiled_in: None,
            enabled: Some(true),
            evidence: vec![evidence("legacy")],
        };
        assert!(build_plan(
            &contract(Requirement::Required, false),
            &catalog(),
            &snapshot(legacy.clone(), true, ProbeState::Ready),
            "devel-fast",
            [input()]
        )
        .is_err());
        assert!(build_plan(
            &contract(Requirement::Required, true),
            &catalog(),
            &snapshot(legacy.clone(), true, ProbeState::Ready),
            "devel-fast",
            [input()]
        )
        .unwrap_err()
        .contains("only for contracted optional"));
        let unavailable = build_plan(
            &contract(Requirement::Optional, false),
            &catalog(),
            &snapshot(legacy.clone(), true, ProbeState::Ready),
            "devel-fast",
            [input()],
        )
        .unwrap();
        assert_eq!(unavailable.entries[0].decision, PlanDecision::NotSelected);
        let plan = build_plan(
            &contract(Requirement::Optional, true),
            &catalog(),
            &snapshot(legacy, true, ProbeState::Ready),
            "devel-fast",
            [input()],
        )
        .unwrap();
        assert_eq!(plan.entries[0].decision, PlanDecision::Selected);
    }

    #[test]
    fn optional_disabled_is_explicitly_not_selected() {
        let feature = ObservedFeature {
            compiled_in: Some(true),
            enabled: Some(false),
            evidence: vec![evidence("flags")],
        };
        let plan = build_plan(
            &contract(Requirement::Optional, false),
            &catalog(),
            &snapshot(feature, false, ProbeState::Unavailable),
            "devel-fast",
            [input()],
        )
        .unwrap();
        assert_eq!(plan.entries[0].decision, PlanDecision::NotSelected);
        assert!(plan.entries[0].evidence.contains("explicit evidence"));
    }

    #[test]
    fn advertised_helper_below_its_typed_semantic_floor_is_not_selected() {
        let feature = ObservedFeature {
            compiled_in: Some(true),
            enabled: Some(false),
            evidence: vec![evidence("flags")],
        };
        let mut observed = snapshot(feature, false, ProbeState::Unavailable);
        observed.commands.insert(
            "get_reports".into(),
            CommandSupport {
                advertised: true,
                evidence: evidence("authenticated-help"),
            },
        );
        let plan = build_plan(
            &contract(Requirement::Optional, false),
            &catalog(),
            &observed,
            "devel-scan",
            [PlanInput {
                kind: PlanEntryKind::Helper,
                name: "get_report_export".into(),
                lane: "devel-scan".into(),
                feature: None,
                wire_command: Some("get_reports".into()),
                command_optional: true,
                implemented: true,
                semantic_eligible: false,
                semantic_evidence:
                    "typed semantic get_report_export requires GMP 22.8; negotiated GMP 22.7; no wire request is eligible"
                        .into(),
            }],
        )
        .unwrap();
        assert_eq!(plan.entries[0].decision, PlanDecision::NotSelected);
        assert!(plan.entries[0].evidence.contains("requires GMP 22.8"));
        assert!(plan.entries[0].evidence.contains("negotiated GMP 22.7"));
    }

    #[test]
    fn forbidden_presence_required_absence_hidden_command_and_unhealthy_probe_block() {
        let enabled = ObservedFeature {
            compiled_in: Some(true),
            enabled: Some(true),
            evidence: vec![evidence("flags")],
        };
        for (requirement, advertised, probe) in [
            (Requirement::Forbidden, true, ProbeState::Ready),
            (Requirement::Required, false, ProbeState::Ready),
            (Requirement::Optional, true, ProbeState::Unhealthy),
        ] {
            assert!(build_plan(
                &contract(requirement, false),
                &catalog(),
                &snapshot(enabled.clone(), advertised, probe),
                "devel-fast",
                [input()]
            )
            .is_err());
        }
        let disabled = ObservedFeature {
            compiled_in: Some(false),
            enabled: Some(false),
            evidence: vec![evidence("flags")],
        };
        assert!(build_plan(
            &contract(Requirement::Required, false),
            &catalog(),
            &snapshot(disabled, false, ProbeState::Unavailable),
            "devel-fast",
            [input()]
        )
        .is_err());

        let unknown = ObservedFeature {
            compiled_in: None,
            enabled: None,
            evidence: vec![evidence("missing-flags")],
        };
        assert!(build_plan(
            &contract(Requirement::Forbidden, false),
            &catalog(),
            &snapshot(unknown, false, ProbeState::Unknown),
            "devel-fast",
            [input()]
        )
        .unwrap_err()
        .contains("absence is not proven"));

        let mut forbidden_fixture = contract(Requirement::Optional, false);
        forbidden_fixture
            .fixtures
            .insert("external-service".into(), Requirement::Forbidden);
        assert!(build_plan(
            &forbidden_fixture,
            &catalog(),
            &snapshot(
                ObservedFeature {
                    compiled_in: Some(true),
                    enabled: Some(false),
                    evidence: vec![evidence("flags")],
                },
                false,
                ProbeState::Unavailable,
            ),
            "devel-fast",
            [input()]
        )
        .unwrap_err()
        .contains("fixture contract violation"));
    }

    #[test]
    fn enabled_unknown_and_known_but_unmapped_features_are_coverage_gaps() {
        let mut observed = snapshot(
            ObservedFeature {
                compiled_in: Some(true),
                enabled: Some(true),
                evidence: vec![evidence("flags")],
            },
            true,
            ProbeState::Ready,
        );
        observed.features.insert(
            "FUTURE_FEATURE".into(),
            ObservedFeature {
                compiled_in: Some(true),
                enabled: Some(true),
                evidence: vec![],
            },
        );
        assert!(build_plan(
            &contract(Requirement::Optional, false),
            &catalog(),
            &observed,
            "devel-fast",
            [input()]
        )
        .unwrap_err()
        .contains("no catalog/scenario mapping"));
        let mut no_scenario = catalog();
        no_scenario
            .features
            .get_mut("ENABLE_AGENTS")
            .unwrap()
            .scenarios
            .clear();
        assert!(build_plan(
            &contract(Requirement::Optional, false),
            &no_scenario,
            &snapshot(
                ObservedFeature {
                    compiled_in: Some(true),
                    enabled: Some(true),
                    evidence: vec![]
                },
                true,
                ProbeState::Ready
            ),
            "devel-fast",
            [input()]
        )
        .unwrap_err()
        .contains("no executable scenario"));

        let mut gap = input();
        gap.implemented = false;
        assert!(build_plan(
            &contract(Requirement::Optional, false),
            &catalog(),
            &snapshot(
                ObservedFeature {
                    compiled_in: Some(true),
                    enabled: Some(true),
                    evidence: vec![]
                },
                true,
                ProbeState::Ready,
            ),
            "devel-fast",
            [gap],
        )
        .unwrap_err()
        .contains("no cleanup-safe public execution path"));
    }

    #[test]
    fn planning_is_deterministic_and_reconciliation_is_exact() {
        let feature = ObservedFeature {
            compiled_in: Some(true),
            enabled: Some(true),
            evidence: vec![evidence("flags")],
        };
        let mut observed = snapshot(feature, true, ProbeState::Ready);
        for command in ["alpha", "zeta"] {
            observed.commands.insert(
                command.into(),
                CommandSupport {
                    advertised: true,
                    evidence: evidence("help"),
                },
            );
        }
        let inputs = vec![
            input(),
            PlanInput {
                kind: PlanEntryKind::Command,
                name: "zeta".into(),
                lane: "devel-fast".into(),
                feature: None,
                wire_command: Some("zeta".into()),
                command_optional: false,
                implemented: true,
                semantic_eligible: true,
                semantic_evidence: "eligible".into(),
            },
            PlanInput {
                kind: PlanEntryKind::Command,
                name: "alpha".into(),
                lane: "devel-fast".into(),
                feature: None,
                wire_command: Some("alpha".into()),
                command_optional: false,
                implemented: true,
                semantic_eligible: true,
                semantic_evidence: "eligible".into(),
            },
        ];
        let plan = build_plan(
            &contract(Requirement::Optional, false),
            &catalog(),
            &observed,
            "devel-fast",
            inputs,
        )
        .unwrap();
        assert_eq!(
            plan.entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "zeta", "agent-read"]
        );
        let discovery_only = build_plan(
            &contract(Requirement::Optional, false),
            &catalog(),
            &observed,
            "devel-fast",
            [PlanInput {
                kind: PlanEntryKind::Command,
                name: "alpha".into(),
                lane: "devel-fast".into(),
                feature: None,
                wire_command: Some("alpha".into()),
                command_optional: true,
                implemented: false,
                semantic_eligible: true,
                semantic_evidence: "eligible".into(),
            }],
        )
        .unwrap();
        assert_eq!(
            discovery_only.entries[0].decision,
            PlanDecision::NotSelected
        );
        let results = plan
            .entries
            .iter()
            .map(|entry| ExecutionResult {
                kind: entry.kind,
                name: entry.name.clone(),
                outcome: TerminalOutcome::Pass,
                evidence: "ok".into(),
            })
            .collect::<Vec<_>>();
        reconcile(&plan, &results).unwrap();
        assert!(reconcile(&plan, &results[..results.len() - 1])
            .unwrap_err()
            .contains("no terminal result"));
        let mut duplicate = results.clone();
        duplicate.push(results[0].clone());
        assert!(reconcile(&plan, &duplicate)
            .unwrap_err()
            .contains("duplicate"));
        let unexpected = [ExecutionResult {
            kind: PlanEntryKind::Command,
            name: "other".into(),
            outcome: TerminalOutcome::Pass,
            evidence: "bad".into(),
        }];
        assert!(reconcile(&plan, &unexpected)
            .unwrap_err()
            .contains("unexpected execution"));
        let mut conditional = results;
        conditional[0].outcome = TerminalOutcome::Conditional;
        assert!(reconcile(&plan, &conditional)
            .unwrap_err()
            .contains("did not pass"));
        conditional[0].outcome = TerminalOutcome::Fail;
        assert!(reconcile(&plan, &conditional)
            .unwrap_err()
            .contains("did not pass"));
    }

    #[test]
    fn exact_reconciliation_accepts_observed_success_and_rejects_unexecuted_selection() {
        let plan = TestPlan {
            schema_version: 1,
            deployment_id: "test".into(),
            lane: "devel-scan".into(),
            entries: vec![PlanEntry {
                kind: PlanEntryKind::Helper,
                name: "get_report".into(),
                lane: "devel-scan".into(),
                feature: None,
                decision: PlanDecision::Selected,
                evidence: "advertised and version eligible".into(),
            }],
        };
        assert!(reconcile(&plan, &[])
            .unwrap_err()
            .contains("no terminal result"));
        reconcile(
            &plan,
            &[ExecutionResult {
                kind: PlanEntryKind::Helper,
                name: "get_report".into(),
                outcome: TerminalOutcome::Pass,
                evidence: "typed runtime path executed".into(),
            }],
        )
        .unwrap();
    }
}
