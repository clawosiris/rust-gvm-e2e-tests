// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Shared Community coverage manifest and validation support.

use std::collections::BTreeSet;

use gvm_gmp::capabilities::COMMAND_CAPABILITIES;

mod generated_manifest;
pub mod runtime;

pub use generated_manifest::{
    compile_enforce_public_helper_surface, COMMAND_COVERAGE, HELPER_COVERAGE, RUST_GVM_SHA,
};

/// Executable Community coverage disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    BlockingLive,
    NightlyLive,
    IsolatedLive,
    ConditionalCommunity,
    ExcludedCommunity,
}

impl Disposition {
    /// Stable machine-readable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BlockingLive => "blocking-live",
            Self::NightlyLive => "nightly-live",
            Self::IsolatedLive => "isolated-live",
            Self::ConditionalCommunity => "conditional-community",
            Self::ExcludedCommunity => "excluded-community",
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_EXCLUSIONS: &[&str] = &[
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
        assert_eq!(COMMAND_COVERAGE.len(), 155);
    }

    #[test]
    fn hard_exclusions_are_only_the_edition_boundary() {
        let actual: Vec<_> = COMMAND_COVERAGE
            .iter()
            .filter(|entry| entry.disposition == Disposition::ExcludedCommunity)
            .map(|entry| entry.name)
            .collect();
        assert_eq!(actual, EXPECTED_EXCLUSIONS);
    }

    #[test]
    fn all_public_helpers_remain_compile_referenced() {
        compile_enforce_public_helper_surface();
        assert_eq!(
            HELPER_COVERAGE.len(),
            147,
            "143 public typed helpers plus four explicit task variants"
        );
    }
}
