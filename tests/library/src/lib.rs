// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Shared deployment coverage manifest and capability-planning support.

use std::collections::BTreeSet;

use gvm_gmp::capabilities::COMMAND_CAPABILITIES;

pub mod capability;
mod generated_manifest;
pub mod runtime;

pub use generated_manifest::{
    compile_enforce_public_helper_surface, COMMAND_COVERAGE, HELPER_COVERAGE, HELPER_MIGRATIONS,
    RUST_GVM_SHA,
};

/// Executable coverage disposition, independent from deployment capability policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    BlockingLive,
    NightlyLive,
    IsolatedLive,
    KnownUpstreamBug,
    ConditionalAvailability,
    CapabilitySelected,
}

impl Disposition {
    /// Stable machine-readable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BlockingLive => "blocking-live",
            Self::NightlyLive => "nightly-live",
            Self::IsolatedLive => "isolated-live",
            Self::KnownUpstreamBug => "known-upstream-bug",
            Self::ConditionalAvailability => "conditional-availability",
            Self::CapabilitySelected => "capability-selected",
        }
    }
}

/// One command or public-helper manifest row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageEntry {
    pub name: &'static str,
    pub wire_command: &'static str,
    pub disposition: Disposition,
    pub lane: &'static str,
    /// Empty for deployment-independent coverage, otherwise an all-of feature list.
    pub requires: &'static [&'static str],
    /// Whether the public harness has a cleanup-safe executable path for this entry.
    pub implemented: bool,
}

/// Availability of a helper exposed by the pre-convergence rich harness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceStatus {
    /// The facade was removed with no supported replacement claimed here.
    Removed,
    /// The facade was replaced by a canonical request passed to `GmpClient::execute`.
    Replaced,
}

/// Generated evidence for one disappeared public/helper-only surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceMigration {
    pub name: &'static str,
    pub wire_command: &'static str,
    pub status: SurfaceStatus,
    pub replacement: Option<&'static str>,
}

/// Validate the compiled manifest against the authoritative dependency registry.
pub fn validate_compiled_manifest() -> Result<(), String> {
    let upstream: BTreeSet<_> = COMMAND_CAPABILITIES
        .iter()
        .map(|capability| capability.name)
        .collect();
    let covered: BTreeSet<_> = COMMAND_COVERAGE.iter().map(|entry| entry.name).collect();
    if COMMAND_COVERAGE.len() != covered.len() {
        return Err("command manifest contains duplicate entries".to_string());
    }
    if upstream != covered {
        return Err(format!(
            "command manifest drift: upstream-only={:?}, manifest-only={:?}",
            upstream.difference(&covered).collect::<Vec<_>>(),
            covered.difference(&upstream).collect::<Vec<_>>()
        ));
    }
    let helpers: BTreeSet<_> = HELPER_COVERAGE.iter().map(|entry| entry.name).collect();
    if HELPER_COVERAGE.len() != helpers.len() {
        return Err("helper manifest contains duplicate entries".to_string());
    }
    let unknown_wire: Vec<_> = HELPER_COVERAGE
        .iter()
        .filter(|entry| !upstream.contains(entry.wire_command))
        .map(|entry| (entry.name, entry.wire_command))
        .collect();
    if !unknown_wire.is_empty() {
        return Err(format!(
            "helper manifest references unknown wire commands: {unknown_wire:?}"
        ));
    }
    let migrations: BTreeSet<_> = HELPER_MIGRATIONS.iter().map(|entry| entry.name).collect();
    if HELPER_MIGRATIONS.len() != migrations.len() {
        return Err("helper migration evidence contains duplicate entries".to_string());
    }
    if let Some(overlap) = helpers.intersection(&migrations).next() {
        return Err(format!(
            "helper surface is both current and migrated: {overlap}"
        ));
    }
    let invalid_migrations: Vec<_> = HELPER_MIGRATIONS
        .iter()
        .filter(|entry| match entry.status {
            SurfaceStatus::Removed => entry.replacement.is_some(),
            SurfaceStatus::Replaced => {
                entry.replacement.is_none() || !upstream.contains(entry.wire_command)
            }
        })
        .map(|entry| entry.name)
        .collect();
    if !invalid_migrations.is_empty() {
        return Err(format!(
            "invalid helper migration evidence: {invalid_migrations:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_CAPABILITY_SELECTED: &[&str] = &[
        "create_agent_group",
        "create_oci_image_target",
        "delete_agent",
        "delete_agent_group",
        "delete_oci_image_target",
        "get_agent_groups",
        "get_agent_installer_instruction",
        "get_agent_support_bundle",
        "get_agents",
        "get_oci_image_targets",
        "modify_agent",
        "modify_agent_control_scan_config",
        "modify_agent_group",
        "modify_oci_image_target",
        "sync_agents",
    ];

    #[test]
    fn registry_and_manifest_are_exactly_equal() {
        validate_compiled_manifest().expect("compiled manifest must match dependency registry");
        assert_eq!(COMMAND_COVERAGE.len(), 158);
    }

    #[test]
    fn former_edition_exclusions_are_capability_selected() {
        let actual: Vec<_> = COMMAND_COVERAGE
            .iter()
            .filter(|entry| {
                entry.disposition == Disposition::CapabilitySelected
                    && matches!(
                        entry.requires,
                        ["ENABLE_AGENTS" | "ENABLE_CONTAINER_SCANNING"]
                    )
            })
            .map(|entry| entry.name)
            .collect();
        assert_eq!(actual, EXPECTED_CAPABILITY_SELECTED);
    }

    #[test]
    fn report_config_mutations_are_explicit_known_upstream_bugs_but_reads_remain_isolated() {
        for name in [
            "create_report_config",
            "delete_report_config",
            "modify_report_config",
        ] {
            assert!(COMMAND_COVERAGE.iter().any(|entry| {
                entry.name == name
                    && entry.disposition == Disposition::KnownUpstreamBug
                    && entry.lane == "none"
            }));
        }
        assert!(COMMAND_COVERAGE.iter().any(|entry| {
            entry.name == "get_report_configs"
                && entry.disposition == Disposition::IsolatedLive
                && entry.lane == "devel-isolated"
        }));
        for name in ["get_report_config", "get_report_configs"] {
            assert!(HELPER_COVERAGE.iter().any(|entry| {
                entry.name == name
                    && entry.disposition == Disposition::IsolatedLive
                    && entry.lane == "devel-isolated"
            }));
        }
        for name in [
            "create_report_config",
            "clone_report_config",
            "delete_report_config",
            "modify_report_config",
        ] {
            assert!(HELPER_COVERAGE.iter().any(|entry| {
                entry.name == name && entry.disposition == Disposition::KnownUpstreamBug
            }));
        }
    }

    #[test]
    fn all_public_helpers_remain_compile_referenced() {
        compile_enforce_public_helper_surface();
        assert_eq!(HELPER_COVERAGE.len(), 261);
    }

    #[test]
    fn disappeared_surfaces_are_explicitly_removed_or_replaced() {
        assert_eq!(HELPER_MIGRATIONS.len(), 29);
        assert_eq!(
            HELPER_MIGRATIONS
                .iter()
                .filter(|entry| entry.status == SurfaceStatus::Removed)
                .count(),
            1
        );
        assert!(HELPER_MIGRATIONS.iter().any(|entry| {
            entry.name == "get_features_parsed"
                && entry.status == SurfaceStatus::Replaced
                && entry.replacement.is_some()
        }));
        assert!(HELPER_MIGRATIONS.iter().any(|entry| {
            entry.name == "sync_scan_config"
                && entry.status == SurfaceStatus::Removed
                && entry.replacement.is_none()
        }));
    }
}
