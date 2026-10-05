#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG
"""Generate and drift-check the deployment-neutral coverage manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DISPOSITIONS = {
    "blocking-live",
    "nightly-live",
    "isolated-live",
    "known-upstream-bug",
    "conditional-availability",
    "capability-selected",
}

SURFACE_STATUSES = {"current", "removed", "replaced"}

HISTORICAL_FEATURE_COMMANDS = {
    "create_agent_group",
    "delete_agent",
    "delete_agent_group",
    "get_agent_groups",
    "get_agent_installer_instruction",
    "get_agent_support_bundle",
    "get_agents",
    "modify_agent",
    "modify_agent_control_scan_config",
    "modify_agent_group",
    "sync_agents",
    "create_oci_image_target",
    "delete_oci_image_target",
    "get_oci_image_targets",
    "modify_oci_image_target",
}

# Feature-gated operations that the public harness can execute safely with the
# generic fixture contract. Any other enabled catalog command is a coverage gap.
IMPLEMENTED_FEATURE_COMMANDS = {
    "create_agent_group",
    "delete_agent_group",
    "get_agent_groups",
    "get_agents",
    "modify_agent_group",
    "create_oci_image_target",
    "delete_oci_image_target",
    "get_oci_image_targets",
    "modify_oci_image_target",
    "get_credential_stores",
    "get_integration_configs",
    "get_web_application_targets",
}

FEATURE_CATALOG_PATH = ROOT / "coverage/feature-catalog.json"
LIVE_HELP_ALLOWLIST_PATH = ROOT / "coverage/live-help-allowlist.json"
EPSS_REGRESSION_PATH = ROOT / "fixtures/epss-result-regression.json"


def load_feature_catalog() -> dict[str, object]:
    catalog = json.loads(FEATURE_CATALOG_PATH.read_text(encoding="utf-8"))
    if catalog.get("schema_version") != 1 or not isinstance(catalog.get("features"), dict):
        raise ValueError("feature catalog must use schema_version 1 and contain features")
    return catalog


def load_epss_regression() -> dict[str, object]:
    regression = json.loads(EPSS_REGRESSION_PATH.read_text(encoding="utf-8"))
    required = {
        "schema_version",
        "upstream_pull_request",
        "fixed_source_revision",
        "known_affected_release",
        "probes",
    }
    if set(regression) != required or regression["schema_version"] != 1:
        raise ValueError("EPSS regression fixture must use schema_version 1 and exact fields")
    probes = regression["probes"]
    expected_fields = [
        "epss_score",
        "epss_percentile",
        "max_epss_score",
        "max_epss_percentile",
    ]
    if not isinstance(probes, list) or [probe.get("field") for probe in probes] != expected_fields:
        raise ValueError("EPSS regression fixture must contain the four ordered gvmd fields")
    return regression


def load_live_help_allowlist() -> list[dict[str, str]]:
    policy = json.loads(LIVE_HELP_ALLOWLIST_PATH.read_text(encoding="utf-8"))
    if set(policy) != {"schema_version", "commands"} or policy["schema_version"] != 1:
        raise ValueError("live-help allowlist must use schema_version 1 and contain only commands")
    commands = policy["commands"]
    if not isinstance(commands, list):
        raise ValueError("live-help allowlist commands must be a list")
    required = {"name", "rationale", "evidence_source", "evidence_detail"}
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in commands:
        if not isinstance(entry, dict) or set(entry) != required:
            raise ValueError("every live-help allowlist entry must contain exact reviewed fields")
        if not all(isinstance(entry[field], str) and entry[field].strip() for field in required):
            raise ValueError("live-help allowlist fields must be nonempty strings")
        name = entry["name"]
        if re.fullmatch(r"[a-z0-9]+(?:_[a-z0-9]+)*", name) is None:
            raise ValueError(f"live-help allowlist entry is not an exact command name: {name}")
        if name in seen:
            raise ValueError(f"live-help allowlist repeats command {name}")
        evidence_path = ROOT / entry["evidence_source"]
        if not evidence_path.is_file():
            raise ValueError(f"live-help evidence source does not exist: {entry['evidence_source']}")
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        if name not in evidence.get("help_commands", []):
            raise ValueError(
                f"live-help evidence source does not advertise exact command {name}"
            )
        seen.add(name)
        result.append({field: entry[field] for field in sorted(required)})
    return sorted(result, key=lambda entry: entry["name"])


def feature_command_map(catalog: dict[str, object] | None = None) -> dict[str, str]:
    catalog = catalog or load_feature_catalog()
    result: dict[str, str] = {}
    for feature, entry in catalog["features"].items():  # type: ignore[union-attr]
        scenarios = entry.get("scenarios")
        if not isinstance(scenarios, dict) or not scenarios:
            raise ValueError(f"feature {feature} has no scenario mapping")
        for scenario, requirement in scenarios.items():
            if (
                not isinstance(requirement, dict)
                or set(requirement) != {"lane", "implemented"}
                or requirement.get("lane") not in {"devel-fast", "devel-scan"}
                or not isinstance(requirement.get("implemented"), bool)
            ):
                raise ValueError(
                    f"feature {feature} scenario {scenario} has invalid requirements"
                )
        for command in entry.get("commands", []):
            if command in result:
                raise ValueError(f"command {command} belongs to multiple features")
            result[command] = feature
    return result

CONDITIONAL_COMMANDS = {
    "cancel_report_export",
    "create_web_application_target",
    "delete_web_application_target",
    "download_report_export",
    "export_audit_report",
    "export_delta_audit_report",
    "export_delta_scan_report",
    "export_scan_report",
    "get_credential_stores",
    "get_integration_configs",
    "get_license",
    "get_report_applications",
    "get_report_closed_cves",
    "get_report_cves",
    "get_report_errors",
    "get_report_exports",
    "get_report_hosts",
    "get_report_operating_systems",
    "get_report_ports",
    "get_report_tls_certificates",
    "get_report_vulns",
    "get_scan_report",
    "get_timezones",
    "get_web_application_targets",
    "modify_credential_store",
    "modify_integration_config",
    "modify_license",
    "modify_web_application_target",
    "sync_config",
    "verify_credential_store",
}

# Registered commands that remain discovery-visible but do not have a safe,
# deterministic live execution path in the public harness. The planner emits
# them as explicit not-selected entries even when help advertises them.
UNIMPLEMENTED_DISCOVERY_COMMANDS = {
    "cancel_report_export",
    "export_audit_report",
    "export_delta_audit_report",
    "export_delta_scan_report",
    "get_license",
    "get_timezones",
    "modify_license",
    "sync_config",
}

SCAN_CONDITIONAL_COMMANDS = {
    "cancel_report_export",
    "download_report_export",
    "export_audit_report",
    "export_delta_audit_report",
    "export_delta_scan_report",
    "export_scan_report",
    "get_report_applications",
    "get_report_closed_cves",
    "get_report_cves",
    "get_report_errors",
    "get_report_exports",
    "get_report_hosts",
    "get_report_operating_systems",
    "get_report_ports",
    "get_report_tls_certificates",
    "get_report_vulns",
    "get_reports",
    "get_scan_report",
}

NIGHTLY_COMMANDS = {
    "create_report",
    "get_reports",
    "get_results",
    "move_task",
    "resume_task",
    "start_task",
    "stop_task",
}

# Do not send report-config mutations to the Community stable stack while
# greenbone/gvmd#3165 is unresolved. Runs 36611076644 and 36665378965 both
# reproduced a connection closure; the latter retained gvmd 26.40.2 / GMP 22.7
# evidence of `Report Config could not be created` followed by SIGSEGV. Exact
# name reconciliation found no persisted object, so retrying would only replay
# a known crash boundary.
KNOWN_UPSTREAM_BUG_COMMANDS = {
    "create_report_config",
    "delete_report_config",
    "modify_report_config",
}

ISOLATED_COMMANDS = {
    "create_asset",
    "create_group",
    "create_permission",
    "create_report_format",
    "create_role",
    "create_ticket",
    "create_tls_certificate",
    "create_user",
    "delete_asset",
    "delete_group",
    "delete_permission",
    "delete_report",
    "delete_report_format",
    "delete_role",
    "delete_ticket",
    "delete_tls_certificate",
    "delete_user",
    "empty_trashcan",
    "get_assets",
    "get_groups",
    "get_permissions",
    "get_report_configs",
    "get_roles",
    "get_tickets",
    "get_tls_certificates",
    "get_users",
    "modify_asset",
    "modify_auth",
    "modify_group",
    "modify_permission",
    "modify_report_format",
    "modify_role",
    "modify_setting",
    "modify_ticket",
    "modify_tls_certificate",
    "modify_user",
    "run_wizard",
    "test_alert",
    "verify_report_format",
}

HELPER_WIRE_OVERRIDES = {
    "clone_agent_group": "create_agent_group",
    "clone_alert": "create_alert",
    "clone_audit": "create_task",
    "clone_filter": "create_filter",
    "clone_group": "create_group",
    "clone_note": "create_note",
    "clone_oci_image_target": "create_oci_image_target",
    "clone_override": "create_override",
    "clone_permission": "create_permission",
    "clone_port_list": "create_port_list",
    "clone_role": "create_role",
    "clone_schedule": "create_schedule",
    "clone_tag": "create_tag",
    "clone_task": "create_task",
    "clone_tls_certificate": "create_tls_certificate",
    "clone_user": "create_user",
    "clone_web_application_target": "create_web_application_target",
    "create_agent_group_task": "create_task",
    "create_audit": "create_task",
    "create_container_image_task": "create_task",
    "create_container_task": "create_task",
    "create_oci_image_target_task": "create_task",
    "create_web_application_task": "create_task",
    "delete_audit": "delete_task",
    "delete_audit_report": "delete_report",
    "delete_host": "delete_asset",
    "delete_operating_system_asset": "delete_asset",
    "get_agent": "get_agents",
    "get_agent_group": "get_agent_groups",
    "get_alert": "get_alerts",
    "get_audit": "get_tasks",
    "get_audit_reports": "get_reports",
    "get_audits": "get_tasks",
    "get_filter": "get_filters",
    "get_group": "get_groups",
    "get_host": "get_assets",
    "get_info_list": "get_info",
    "get_integration_config": "get_integration_configs",
    "get_legacy_aggregates": "get_aggregates",
    "get_note": "get_notes",
    "get_nvt": "get_nvts",
    "get_nvt_preference": "get_nvts",
    "get_nvt_preferences": "get_nvts",
    "get_oci_image_target": "get_oci_image_targets",
    "get_override": "get_overrides",
    "get_permission": "get_permissions",
    "get_port_list": "get_port_lists",
    "get_report": "get_reports",
    "get_report_config": "get_report_configs",
    "get_report_format": "get_report_formats",
    "get_resource_name": "get_resource_names",
    "get_result": "get_results",
    "get_role": "get_roles",
    "get_schedule": "get_schedules",
    "get_tag": "get_tags",
    "get_target": "get_targets",
    "get_task": "get_tasks",
    "get_tls_certificate": "get_tls_certificates",
    "get_user": "get_users",
    "get_web_application_target": "get_web_application_targets",
    "modify_audit": "modify_task",
    "modify_host": "modify_asset",
    "resume_audit": "resume_task",
    "start_audit": "start_task",
    "stop_audit": "stop_task",
    "trigger_alert": "get_reports",
    "clone_config": "create_config",
    "clone_oci_image_target_parsed": "create_oci_image_target",
    "clone_report_config": "create_report_config",
    "clone_report_format": "create_report_format",
    "clone_scan_config": "create_config",
    "clone_scanner": "create_scanner",
    "clone_web_application_target_parsed": "create_web_application_target",
    "create_credential_store_credential": "create_credential",
    "create_host": "create_asset",
    "create_import_task": "create_task",
    "create_scan_config": "create_config",
    "delete_oci_image_target_parsed": "delete_oci_image_target",
    "delete_scan_config": "delete_config",
    "delete_web_application_target_parsed": "delete_web_application_target",
    "get_asset": "get_assets",
    "get_cert_bund_advisories": "get_info",
    "get_cert_bund_advisory": "get_info",
    "get_config": "get_configs",
    "get_cpe": "get_info",
    "get_cpes": "get_info",
    "get_credential_store": "get_credential_stores",
    "get_credential_stores_with_opts": "get_credential_stores",
    "get_cve": "get_info",
    "get_cves": "get_info",
    "get_dfn_cert_advisories": "get_info",
    "get_dfn_cert_advisory": "get_info",
    "get_feed": "get_feeds",
    "get_features_parsed": "get_features",
    "get_help": "help",
    "get_help_with_mode": "help",
    "get_hosts": "get_assets",
    "get_integration_config_parsed": "get_integration_configs",
    "get_integration_configs_parsed": "get_integration_configs",
    "get_operating_system_asset": "get_assets",
    "get_operating_system_assets": "get_assets",
    "get_oci_image_target_parsed": "get_oci_image_targets",
    "get_oci_image_targets_parsed": "get_oci_image_targets",
    "get_policies": "get_configs",
    "get_policy": "get_configs",
    "get_report_applications_parsed": "get_report_applications",
    "get_report_configs_parsed": "get_report_configs",
    "get_report_cves_parsed": "get_report_cves",
    "get_report_export": "get_reports",
    "get_report_export_with_opts": "get_reports",
    "get_report_hosts_parsed": "get_report_hosts",
    "get_report_operating_systems_parsed": "get_report_operating_systems",
    "get_report_ports_parsed": "get_report_ports",
    "get_report_vulnerabilities": "get_report_vulns",
    "get_scan_config": "get_configs",
    "get_scan_config_nvt": "get_nvts",
    "get_scan_config_nvts": "get_nvts",
    "get_scan_configs": "get_configs",
    "get_scanner": "get_scanners",
    "get_vulnerabilities": "get_vulns",
    "get_vulnerability": "get_vulns",
    "get_web_application_target_parsed": "get_web_application_targets",
    "import_policy": "create_config",
    "import_report": "create_report",
    "import_report_format": "create_report_format",
    "import_scan_config": "create_config",
    "modify_credential_store_credential": "modify_credential",
    "modify_integration_config_parsed": "modify_integration_config",
    "modify_oci_image_target_parsed": "modify_oci_image_target",
    "modify_policy_set_comment": "modify_config",
    "modify_policy_set_name": "modify_config",
    "modify_scan_config": "modify_config",
    "modify_scan_config_set_comment": "modify_config",
    "modify_scan_config_set_name": "modify_config",
    "modify_web_application_target_parsed": "modify_web_application_target",
    "restore_from_trashcan": "restore",
    "sync_scan_config": "sync_config",
}

EXTRA_HELPERS = {
    "create_agent_group_task": ("create_task", "capability-selected"),
    "create_container_image_task": ("create_task", "capability-selected"),
    "create_container_task": ("create_task", "capability-selected"),
    "create_oci_image_target_task": ("create_task", "capability-selected"),
}

# This disappeared helper cannot be called through a supported canonical
# request at the pinned revision, even though its historical wire name remains
# in the capability registry.
REMOVED_HELPERS = {"sync_scan_config"}

DIRECT_CLIENT_HELPERS: set[str] = set()

HELPER_DISPOSITION_OVERRIDES = {
    **{name: disposition for name, (_, disposition) in EXTRA_HELPERS.items()},
    "create_credential_store_credential": "capability-selected",
    "get_report_export": "conditional-availability",
    "get_report_export_with_opts": "conditional-availability",
    "modify_credential_store_credential": "capability-selected",
}

HELPER_FEATURE_OVERRIDES = {
    "create_agent_group_task": "ENABLE_AGENTS",
    "create_container_image_task": "ENABLE_CONTAINER_SCANNING",
    "create_container_task": "ENABLE_CONTAINER_SCANNING",
    "create_oci_image_target_task": "ENABLE_CONTAINER_SCANNING",
    "create_credential_store_credential": "ENABLE_CREDENTIAL_STORES",
    "modify_credential_store_credential": "ENABLE_CREDENTIAL_STORES",
}


@dataclass(frozen=True)
class Entry:
    name: str
    wire_command: str
    disposition: str
    lane: str
    rationale: str
    requires: tuple[str, ...] = ()
    implemented: bool = True

    def as_json(self) -> dict[str, object]:
        return {
            "name": self.name,
            "wire_command": self.wire_command,
            "disposition": self.disposition,
            "lane": self.lane,
            "rationale": self.rationale,
            "requires": list(self.requires),
            "implemented": self.implemented,
        }


@dataclass(frozen=True)
class SurfaceMigration:
    name: str
    wire_command: str
    status: str
    replacement: str | None
    rationale: str

    def as_json(self) -> dict[str, str | None]:
        return {
            "name": self.name,
            "wire_command": self.wire_command,
            "status": self.status,
            "replacement": self.replacement,
            "rationale": self.rationale,
        }


def git_sha(source: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def command_names(source: Path) -> list[str]:
    text = (source / "crates/gvm-gmp/src/capabilities.rs").read_text()
    block = text.split("command_capabilities! {", 1)[1].split("\n}", 1)[0]
    names = re.findall(r'^\s+\("([^"]+)"', block, flags=re.MULTILINE)
    if names != sorted(set(names)):
        raise ValueError("upstream command registry is not sorted and unique")
    return names


def typed_helpers(source: Path) -> list[str]:
    typed_root = source / "crates/gvm-client/src/typed"
    files = [source / "crates/gvm-client/src/typed.rs", *sorted(typed_root.glob("*.rs"))]
    names = []
    for path in files:
        names.extend(
            re.findall(
                r"^\s+pub async fn ([a-z0-9_]+)\s*\(",
                path.read_text(),
                flags=re.MULTILINE,
            )
        )
    names.extend(DIRECT_CLIENT_HELPERS)
    if len(names) != len(set(names)):
        raise ValueError("upstream typed helper surface contains duplicate names")
    return sorted(names)


def command_disposition(name: str) -> str:
    feature_commands = feature_command_map()
    if name in feature_commands:
        return "capability-selected"
    classes = [
        name in KNOWN_UPSTREAM_BUG_COMMANDS,
        name in CONDITIONAL_COMMANDS,
        name in NIGHTLY_COMMANDS,
        name in ISOLATED_COMMANDS,
    ]
    if sum(classes) > 1:
        raise ValueError(f"{name} appears in more than one disposition policy")
    if classes[0]:
        return "known-upstream-bug"
    if classes[1]:
        return "conditional-availability"
    if classes[2]:
        return "nightly-live"
    if classes[3]:
        return "isolated-live"
    return "blocking-live"


def lane_for(disposition: str, wire_command: str = "") -> str:
    if disposition == "conditional-availability" and wire_command in SCAN_CONDITIONAL_COMMANDS:
        return "devel-scan"
    return {
        "blocking-live": "devel-fast",
        "nightly-live": "devel-scan",
        "isolated-live": "devel-isolated",
        "known-upstream-bug": "none",
        "conditional-availability": "devel-fast",
        "capability-selected": "devel-fast",
    }[disposition]


def rationale_for(name: str, disposition: str) -> str:
    if name == "get_results":
        return (
            "Nightly scan-linked result coverage includes read-only filter and sort probes for "
            "epss_score, epss_percentile, max_epss_score, and max_epss_percentile, with a "
            "same-connection health assertion and exact gvmd source/release disposition."
        )
    if name in {"export_scan_report", "get_report_exports", "download_report_export"}:
        return (
            "Help-gated asynchronous scan-report export lifecycle coverage; creation, "
            "bounded state polling, download consumption, and final reconciliation execute "
            "together only when the cleanup-safe command set is advertised."
        )
    if name == "cancel_report_export":
        return (
            "Cancellation executes only for a separately created export observed in pending "
            "or running state; an immediate terminal state receives an exact live disposition "
            "and cleanup instead of a synthetic pass."
        )
    if name == "export_audit_report":
        return (
            "Typed and help-gated, but Community Compose has no deterministic audit-report "
            "fixture; the scan lane emits the provider-fixture disposition without mutation."
        )
    if name == "export_delta_audit_report":
        return (
            "Typed and help-gated, but Community Compose has no deterministic compatible "
            "audit-report pair; the scan lane emits the provider-fixture disposition."
        )
    if name == "export_delta_scan_report":
        return (
            "Typed and help-gated, but Community Compose provisions one deterministic scan "
            "report rather than a compatible delta pair; the scan lane emits that disposition."
        )
    if name in UNIMPLEMENTED_DISCOVERY_COMMANDS:
        return (
            "Advertised surface is retained as explicit discovery evidence but is not selected "
            "without a deterministic public execution path."
        )
    return {
        "blocking-live": "Expected Community capability exercised by the warm-volume blocking lane.",
        "nightly-live": "Expected Community scan/report capability exercised by the bounded nightly/manual lane.",
        "isolated-live": "Supported operation isolated because it is administrative, global, or destructive.",
        "known-upstream-bug": (
            "Known upstream crash greenbone/gvmd#3165: gvmd 26.40.2 / GMP 22.7 "
            "closed create_report_config connections in runs 36611076644 and 36665378965; "
            "exact-name reconciliation found no persisted object, so this mutation family is not executed."
        ),
        "conditional-availability": "Availability is decided by recorded version, feature, help, and probe evidence.",
        "capability-selected": "Selection is decided by the deployment contract and feature catalog before mutation.",
    }[disposition]


def helper_wire(name: str, commands: set[str]) -> str:
    if name in HELPER_WIRE_OVERRIDES:
        return HELPER_WIRE_OVERRIDES[name]
    parsed = name.removesuffix("_parsed")
    if parsed in commands:
        return parsed
    if name in commands:
        return name
    raise ValueError(f"no explicit wire-command mapping for typed helper {name}")


def previous_helper_entries(path: Path) -> list[dict[str, str]]:
    """Load the last generated helper surface as migration input.

    Schema v1 stored every surface in ``helpers``. Schema v2 keeps only live
    helpers there and carries disappeared surfaces in ``helper_migrations``.
    Reading both makes regeneration stable while ensuring a newly removed
    upstream helper cannot silently vanish from the evidence.
    """
    if not path.exists():
        return []
    manifest = json.loads(path.read_text())
    entries = list(manifest.get("helpers", []))
    entries.extend(manifest.get("helper_migrations", []))
    result: dict[str, dict[str, str]] = {}
    for entry in entries:
        name = entry.get("name")
        wire = entry.get("wire_command")
        if not isinstance(name, str) or not isinstance(wire, str):
            raise ValueError("previous helper evidence has an invalid name or wire command")
        result[name] = {"name": name, "wire_command": wire}
    return [result[name] for name in sorted(result)]


def classify_helper_migrations(
    previous: list[dict[str, str]],
    current_names: set[str],
    commands: set[str],
) -> list[SurfaceMigration]:
    migrations = []
    for item in previous:
        name = item["name"]
        wire = item["wire_command"]
        if name in current_names:
            continue
        if name in REMOVED_HELPERS or wire not in commands:
            status = "removed"
            replacement = None
            rationale = (
                "The legacy helper surface no longer exists at the pinned rust-gvm revision; "
                "the harness does not compile-reference or claim it."
            )
        else:
            status = "replaced"
            replacement = f"GmpClient::execute with a complete `{wire}` request value"
            rationale = (
                "The legacy facade was replaced by the canonical request value executed through "
                "GmpClient::execute."
            )
        migrations.append(SurfaceMigration(name, wire, status, replacement, rationale))
    if any(item.status not in SURFACE_STATUSES for item in migrations):
        raise ValueError("unknown helper surface status")
    return migrations


def build_manifest(
    source: Path, previous_helpers: list[dict[str, str]] | None = None
) -> dict[str, object]:
    commands = command_names(source)
    command_set = set(commands)
    live_help_allowlist = load_live_help_allowlist()
    overlap = command_set & {entry["name"] for entry in live_help_allowlist}
    if overlap:
        raise ValueError(
            "live-help allowlist contains commands modeled by rust-gvm: "
            + ", ".join(sorted(overlap))
        )
    feature_map = feature_command_map()
    command_entries = []
    for name in commands:
        disposition = command_disposition(name)
        command_entries.append(
            Entry(
                name=name,
                wire_command=name,
                disposition=disposition,
                lane=lane_for(disposition, name),
                rationale=rationale_for(name, disposition),
                requires=(feature_map[name],) if name in feature_map else (),
                implemented=name not in UNIMPLEMENTED_DISCOVERY_COMMANDS
                and (name not in feature_map or name in IMPLEMENTED_FEATURE_COMMANDS),
            )
        )

    helper_entries = []
    for name in typed_helpers(source):
        wire = helper_wire(name, command_set)
        disposition = HELPER_DISPOSITION_OVERRIDES.get(name, command_disposition(wire))
        helper_entries.append(
            Entry(
                name=name,
                wire_command=wire,
                disposition=disposition,
                lane=lane_for(disposition, wire),
                rationale=rationale_for(name, disposition),
                requires=(HELPER_FEATURE_OVERRIDES[name],)
                if name in HELPER_FEATURE_OVERRIDES
                else (feature_map[wire],)
                if wire in feature_map
                else (),
                implemented=wire not in UNIMPLEMENTED_DISCOVERY_COMMANDS
                and (wire not in feature_map or wire in IMPLEMENTED_FEATURE_COMMANDS),
            )
        )
    helper_entries.sort(key=lambda entry: entry.name)
    helper_names = {entry.name for entry in helper_entries}
    migrations = classify_helper_migrations(
        previous_helpers or [], helper_names, command_set
    )

    if not HISTORICAL_FEATURE_COMMANDS <= set(feature_map):
        raise ValueError("historical feature commands are missing from the catalog")
    if any(entry.disposition not in DISPOSITIONS for entry in command_entries + helper_entries):
        raise ValueError("unknown disposition")

    return {
        "schema_version": 4,
        "rust_gvm_sha": git_sha(source),
        "registry_count": len(command_entries),
        "typed_helper_count": len(helper_entries),
        "helper_variant_count": sum(name in EXTRA_HELPERS for name in helper_names),
        "replaced_helper_count": sum(item.status == "replaced" for item in migrations),
        "removed_helper_count": sum(item.status == "removed" for item in migrations),
        "live_help_allowlist_count": len(live_help_allowlist),
        "live_help_allowlist": live_help_allowlist,
        "regressions": {"gvmd-epss-result-filter-sort": load_epss_regression()},
        "feature_catalog": load_feature_catalog()["features"],
        "scenarios": [
            {
                "name": scenario,
                "feature": feature,
                "lane": requirement["lane"],
                "requires": [feature],
                "implemented": requirement["implemented"],
            }
            for feature, entry in load_feature_catalog()["features"].items()  # type: ignore[union-attr]
            for scenario, requirement in entry["scenarios"].items()
        ],
        "commands": [entry.as_json() for entry in command_entries],
        "helpers": [entry.as_json() for entry in helper_entries],
        "helper_migrations": [entry.as_json() for entry in migrations],
    }


def render_json(manifest: dict[str, object]) -> str:
    return json.dumps(manifest, indent=2, sort_keys=False) + "\n"


def render_markdown(manifest: dict[str, object]) -> str:
    commands = manifest["commands"]
    helpers = manifest["helpers"]
    migrations = manifest["helper_migrations"]
    live_help_allowlist = manifest["live_help_allowlist"]
    epss = manifest["regressions"]["gvmd-epss-result-filter-sort"]
    counts = {
        disposition: sum(
            item["disposition"] == disposition for item in commands  # type: ignore[index]
        )
        for disposition in sorted(DISPOSITIONS)
    }
    lines = [
        "# Generated Deployment Coverage Manifest",
        "",
        "<!-- Generated by tools/coverage_manifest.py; do not edit manually. -->",
        "",
        f"- rust-gvm commit: `{manifest['rust_gvm_sha']}`",
        f"- registered wire commands: **{manifest['registry_count']}**",
        f"- public typed helpers: **{manifest['typed_helper_count']}**",
        f"- explicit helper-only variants: **{manifest['helper_variant_count']}**",
        f"- replaced legacy helper surfaces: **{manifest['replaced_helper_count']}**",
        f"- removed legacy helper surfaces: **{manifest['removed_helper_count']}**",
        f"- exact live-help allowlist entries: **{manifest['live_help_allowlist_count']}**",
        "- ordinary live runs use warm persistent volumes",
        "- a `*-live` disposition assigns an intended lane; only a published run artifact proves execution",
        "",
        "## Command summary",
        "",
        "| Disposition | Count |",
        "|---|---:|",
    ]
    lines.extend(f"| `{name}` | {count} |" for name, count in counts.items())
    lines.extend(
        [
            "",
            "## Exact live-help allowlist",
            "",
            "These exact command names are advertised by reviewed live deployment evidence but are not modeled by the pinned rust-gvm registry. Any other unmodeled advertised command blocks discovery before mutation.",
            "",
            "| Command | Rationale | Evidence |",
            "|---|---|---|",
        ]
    )
    lines.extend(
        f"| `{item['name']}` | {item['rationale']} | `{item['evidence_source']}`: {item['evidence_detail']} |"
        for item in live_help_allowlist  # type: ignore[union-attr]
    )
    lines.extend(
        [
            "",
            "## Focused gvmd regressions",
            "",
            "### EPSS result filter/sort server-abort regression",
            "",
            f"- upstream fix: [{epss['upstream_pull_request']}]({epss['upstream_pull_request']}) at exact source `{epss['fixed_source_revision']}`",
            f"- known affected Community release: `{epss['known_affected_release']}`",
            "- lane: `devel-scan`; fixture: the deterministic scan-linked report; requests are read-only",
            "- each request is followed on the same authenticated connection by `get_version`",
            "- the exact affected release may emit `known-upstream-bug` on a proved connection abort; it never emits pass for that failure",
            "- the fixed source and every unclassified deployment must return a normal GMP response and keep the connection usable",
            "",
            "| Field | Filter expression | Sort expression |",
            "|---|---|---|",
        ]
    )
    lines.extend(
        f"| `{probe['field']}` | `{probe['filter_expression']}` | `{probe['sort_expression']}` |"
        for probe in epss["probes"]
    )
    lines.extend(
        [
            "",
            "## Wire commands",
            "",
            "| Command | Disposition | Lane | Requirements |",
            "|---|---|---|---|",
        ]
    )
    lines.extend(
        f"| `{item['name']}` | `{item['disposition']}` | `{item['lane']}` | "
        f"{', '.join(f'`{value}`' for value in item['requires']) or '—'} |"
        for item in commands  # type: ignore[union-attr]
    )
    known_bug_commands = [
        item for item in commands if item["disposition"] == "known-upstream-bug"  # type: ignore[index]
    ]
    if known_bug_commands:
        lines.extend(
            [
                "",
                "## Known upstream Community defects",
                "",
                "These entries are explicit non-execution dispositions, not passes or generic skips.",
                "",
                "| Command | Evidence |",
                "|---|---|",
            ]
        )
        lines.extend(
            f"| `{item['name']}` | {item['rationale']} |"
            for item in known_bug_commands
        )
    lines.extend(
        [
            "",
            "## Public helpers and helper variants",
            "",
            "| Helper | Wire command | Disposition | Lane | Requirements |",
            "|---|---|---|---|---|",
        ]
    )
    lines.extend(
        f"| `{item['name']}` | `{item['wire_command']}` | `{item['disposition']}` | `{item['lane']}` | "
        f"{', '.join(f'`{value}`' for value in item['requires']) or '—'} |"
        for item in helpers  # type: ignore[union-attr]
    )
    lines.extend(
        [
            "",
            "## Legacy helper migrations",
            "",
            "These rows preserve the prior rich-harness API surface as explicit migration evidence. "
            "`replaced` means the wire operation remains supported through a complete canonical request "
            "value and `GmpClient::execute`; `removed` means no supported facade is claimed.",
            "",
            "| Legacy helper | Wire command | Status | Replacement |",
            "|---|---|---|---|",
        ]
    )
    lines.extend(
        f"| `{item['name']}` | `{item['wire_command']}` | `{item['status']}` | "
        f"{item['replacement'] or '—'} |"
        for item in migrations  # type: ignore[union-attr]
    )
    return "\n".join(lines) + "\n"


def rust_string(value: str) -> str:
    return json.dumps(value)


def render_rust(manifest: dict[str, object]) -> str:
    command_lines = []
    for item in manifest["commands"]:  # type: ignore[union-attr]
        command_lines.append(
            "    CoverageEntry { name: %s, wire_command: %s, disposition: Disposition::%s, lane: %s, requires: &[%s], implemented: %s },"
            % (
                rust_string(item["name"]),
                rust_string(item["wire_command"]),
                "".join(part.title() for part in item["disposition"].split("-")),
                rust_string(item["lane"]),
                ", ".join(rust_string(value) for value in item["requires"]),
                str(item["implemented"]).lower(),
            )
        )
    helper_lines = []
    helper_refs = []
    for item in manifest["helpers"]:  # type: ignore[union-attr]
        helper_lines.append(
            "    CoverageEntry { name: %s, wire_command: %s, disposition: Disposition::%s, lane: %s, requires: &[%s], implemented: %s },"
            % (
                rust_string(item["name"]),
                rust_string(item["wire_command"]),
                "".join(part.title() for part in item["disposition"].split("-")),
                rust_string(item["lane"]),
                ", ".join(rust_string(value) for value in item["requires"]),
                str(item["implemented"]).lower(),
            )
        )
        helper_refs.append(
            f"    let _ = GmpClient::<UnixSocketConnection>::{item['name']};"
        )
    migration_lines = []
    for item in manifest["helper_migrations"]:  # type: ignore[union-attr]
        replacement = (
            f"Some({rust_string(item['replacement'])})"
            if item["replacement"] is not None
            else "None"
        )
        migration_lines.append(
            "    SurfaceMigration { name: %s, wire_command: %s, status: SurfaceStatus::%s, replacement: %s },"
            % (
                rust_string(item["name"]),
                rust_string(item["wire_command"]),
                item["status"].title(),
                replacement,
            )
        )
    live_help_allowlist_lines = []
    for item in manifest["live_help_allowlist"]:  # type: ignore[union-attr]
        live_help_allowlist_lines.append(
            "    LiveHelpAllowlistEntry { name: %s, rationale: %s, evidence_source: %s, evidence_detail: %s },"
            % (
                rust_string(item["name"]),
                rust_string(item["rationale"]),
                rust_string(item["evidence_source"]),
                rust_string(item["evidence_detail"]),
            )
        )
    source = "\n".join(
        [
            "// SPDX-License-Identifier: AGPL-3.0-or-later",
            "// SPDX-FileCopyrightText: 2026 Greenbone AG",
            "",
            "// Generated by tools/coverage_manifest.py; do not edit manually.",
            "use gvm_client::GmpClient;",
            "use gvm_connection::UnixSocketConnection;",
            "",
            "use crate::{CoverageEntry, Disposition, LiveHelpAllowlistEntry, SurfaceMigration, SurfaceStatus};",
            "",
            f'pub const RUST_GVM_SHA: &str = {rust_string(str(manifest["rust_gvm_sha"]))};',
            "",
            "pub static COMMAND_COVERAGE: &[CoverageEntry] = &[",
            *command_lines,
            "];",
            "",
            "pub static HELPER_COVERAGE: &[CoverageEntry] = &[",
            *helper_lines,
            "];",
            "",
            "pub static HELPER_MIGRATIONS: &[SurfaceMigration] = &[",
            *migration_lines,
            "];",
            "",
            "pub static LIVE_HELP_ALLOWLIST: &[LiveHelpAllowlistEntry] = &[",
            *live_help_allowlist_lines,
            "];",
            "",
            "#[allow(clippy::let_underscore_untyped)]",
            "pub fn compile_enforce_public_helper_surface() {",
            *helper_refs,
            "}",
            "",
        ]
    )
    return subprocess.run(
        ["rustfmt", "--emit", "stdout", "--edition", "2021"],
        check=True,
        input=source,
        capture_output=True,
        text=True,
    ).stdout


def outputs(manifest: dict[str, object]) -> dict[Path, str]:
    return {
        ROOT / "coverage/manifest.json": render_json(manifest),
        ROOT / "docs/community-coverage.md": render_markdown(manifest),
        ROOT / "tests/library/src/generated_manifest.rs": render_rust(manifest),
    }


def apply_policy_sha(manifest: dict[str, object], policy_sha: str | None) -> None:
    """Anchor generated policy metadata while checking another exact source SHA."""
    if policy_sha is None:
        return
    if re.fullmatch(r"[0-9a-f]{40}", policy_sha) is None:
        raise ValueError(
            "coverage policy rust-gvm SHA must be 40 lowercase hexadecimal characters"
        )
    manifest["rust_gvm_sha"] = policy_sha


def check_or_write(rendered: dict[Path, str], check: bool) -> int:
    failures = []
    for path, content in rendered.items():
        if check:
            actual = path.read_text() if path.exists() else ""
            if actual != content:
                failures.append(path.relative_to(ROOT))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    if failures:
        print("coverage manifest drift:", file=sys.stderr)
        for path in failures:
            print(f"  {path}", file=sys.stderr)
        print("run tools/coverage_manifest.py --rust-gvm-source <path>", file=sys.stderr)
        return 1
    digest = hashlib.sha256(
        rendered[ROOT / "coverage/manifest.json"].encode()
    ).hexdigest()
    action = "verified" if check else "generated"
    print(f"{action} coverage manifest sha256={digest}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--rust-gvm-source",
        required=True,
        type=Path,
        help="checkout of the exact rust-gvm revision under test",
    )
    parser.add_argument(
        "--policy-rust-gvm-sha",
        help=(
            "render the checked-in policy SHA while auditing command/helper coverage "
            "from the supplied exact source checkout"
        ),
    )
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    previous = previous_helper_entries(ROOT / "coverage/manifest.json")
    manifest = build_manifest(args.rust_gvm_source.resolve(), previous)
    apply_policy_sha(manifest, args.policy_rust_gvm_sha)
    return check_or_write(outputs(manifest), args.check)


if __name__ == "__main__":
    raise SystemExit(main())
