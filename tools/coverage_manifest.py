#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG
"""Generate and drift-check the Community command/helper coverage manifest."""

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
    "conditional-community",
    "excluded-community",
}

EXCLUDED_COMMANDS = {
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

CONDITIONAL_COMMANDS = {
    "create_web_application_target",
    "delete_web_application_target",
    "get_credential_stores",
    "get_integration_configs",
    "get_license",
    "get_report_applications",
    "get_report_closed_cves",
    "get_report_cves",
    "get_report_errors",
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
    "verify_credential_store",
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

ISOLATED_COMMANDS = {
    "create_asset",
    "create_group",
    "create_permission",
    "create_report_config",
    "create_report_format",
    "create_role",
    "create_ticket",
    "create_tls_certificate",
    "create_user",
    "delete_asset",
    "delete_group",
    "delete_permission",
    "delete_report",
    "delete_report_config",
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
    "modify_report_config",
    "modify_report_format",
    "modify_role",
    "modify_setting",
    "modify_ticket",
    "modify_tls_certificate",
    "modify_user",
    "run_wizard",
    "sync_config",
    "test_alert",
    "verify_report_format",
}

HELPER_WIRE_OVERRIDES = {
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
    "create_agent_group_task": ("create_task", "excluded-community"),
    "create_container_image_task": ("create_task", "excluded-community"),
    "create_container_task": ("create_task", "excluded-community"),
    "create_oci_image_target_task": ("create_task", "excluded-community"),
}

HELPER_DISPOSITION_OVERRIDES = {
    "create_credential_store_credential": "conditional-community",
    "modify_credential_store_credential": "conditional-community",
}


@dataclass(frozen=True)
class Entry:
    name: str
    wire_command: str
    disposition: str
    lane: str
    rationale: str

    def as_json(self) -> dict[str, str]:
        return {
            "name": self.name,
            "wire_command": self.wire_command,
            "disposition": self.disposition,
            "lane": self.lane,
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
    text = (source / "crates/gvm-client/src/typed.rs").read_text()
    names = re.findall(r"^\s+pub async fn ([a-z0-9_]+)\s*\(", text, flags=re.MULTILINE)
    if len(names) != len(set(names)):
        raise ValueError("upstream typed helper surface contains duplicate names")
    return names


def command_disposition(name: str) -> str:
    classes = [
        name in EXCLUDED_COMMANDS,
        name in CONDITIONAL_COMMANDS,
        name in NIGHTLY_COMMANDS,
        name in ISOLATED_COMMANDS,
    ]
    if sum(classes) > 1:
        raise ValueError(f"{name} appears in more than one disposition policy")
    if classes[0]:
        return "excluded-community"
    if classes[1]:
        return "conditional-community"
    if classes[2]:
        return "nightly-live"
    if classes[3]:
        return "isolated-live"
    return "blocking-live"


def lane_for(disposition: str) -> str:
    return {
        "blocking-live": "devel-fast",
        "nightly-live": "devel-scan",
        "isolated-live": "devel-isolated",
        "conditional-community": "discovery-selected",
        "excluded-community": "none",
    }[disposition]


def rationale_for(disposition: str) -> str:
    return {
        "blocking-live": "Expected Community capability exercised by the warm-volume blocking lane.",
        "nightly-live": "Expected Community scan/report capability exercised by the bounded nightly/manual lane.",
        "isolated-live": "Supported operation isolated because it is administrative, global, or destructive.",
        "conditional-community": "Availability is decided only by recorded get_version/get_features/help evidence.",
        "excluded-community": "Explicit issue #118 Community boundary: agent or OCI/container-image capability.",
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


def build_manifest(source: Path) -> dict[str, object]:
    commands = command_names(source)
    command_set = set(commands)
    command_entries = []
    for name in commands:
        disposition = command_disposition(name)
        command_entries.append(
            Entry(
                name=name,
                wire_command=name,
                disposition=disposition,
                lane=lane_for(disposition),
                rationale=rationale_for(disposition),
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
                lane=lane_for(disposition),
                rationale=rationale_for(disposition),
            )
        )
    for name, (wire, disposition) in EXTRA_HELPERS.items():
        helper_entries.append(
            Entry(
                name=name,
                wire_command=wire,
                disposition=disposition,
                lane=lane_for(disposition),
                rationale=rationale_for(disposition),
            )
        )
    helper_entries.sort(key=lambda entry: entry.name)

    if set(EXCLUDED_COMMANDS) != {
        entry.name for entry in command_entries if entry.disposition == "excluded-community"
    }:
        raise ValueError("hard command exclusions drifted from the issue #118 boundary")
    if any(entry.disposition not in DISPOSITIONS for entry in command_entries + helper_entries):
        raise ValueError("unknown disposition")

    return {
        "schema_version": 1,
        "rust_gvm_sha": git_sha(source),
        "registry_count": len(command_entries),
        "typed_helper_count": len(helper_entries) - len(EXTRA_HELPERS),
        "helper_variant_count": len(EXTRA_HELPERS),
        "commands": [entry.as_json() for entry in command_entries],
        "helpers": [entry.as_json() for entry in helper_entries],
    }


def render_json(manifest: dict[str, object]) -> str:
    return json.dumps(manifest, indent=2, sort_keys=False) + "\n"


def render_markdown(manifest: dict[str, object]) -> str:
    commands = manifest["commands"]
    helpers = manifest["helpers"]
    counts = {
        disposition: sum(
            item["disposition"] == disposition for item in commands  # type: ignore[index]
        )
        for disposition in sorted(DISPOSITIONS)
    }
    lines = [
        "# Generated Community Coverage Manifest",
        "",
        "<!-- Generated by tools/coverage_manifest.py; do not edit manually. -->",
        "",
        f"- rust-gvm commit: `{manifest['rust_gvm_sha']}`",
        f"- registered wire commands: **{manifest['registry_count']}**",
        f"- public typed helpers: **{manifest['typed_helper_count']}**",
        f"- explicit helper-only variants: **{manifest['helper_variant_count']}**",
        "- ordinary live runs use warm persistent volumes",
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
            "## Wire commands",
            "",
            "| Command | Disposition | Lane |",
            "|---|---|---|",
        ]
    )
    lines.extend(
        f"| `{item['name']}` | `{item['disposition']}` | `{item['lane']}` |"
        for item in commands  # type: ignore[union-attr]
    )
    lines.extend(
        [
            "",
            "## Public helpers and helper variants",
            "",
            "| Helper | Wire command | Disposition | Lane |",
            "|---|---|---|---|",
        ]
    )
    lines.extend(
        f"| `{item['name']}` | `{item['wire_command']}` | `{item['disposition']}` | `{item['lane']}` |"
        for item in helpers  # type: ignore[union-attr]
    )
    return "\n".join(lines) + "\n"


def rust_string(value: str) -> str:
    return json.dumps(value)


def render_rust(manifest: dict[str, object]) -> str:
    command_lines = []
    for item in manifest["commands"]:  # type: ignore[union-attr]
        command_lines.append(
            "    CoverageEntry { name: %s, wire_command: %s, disposition: Disposition::%s, lane: %s },"
            % (
                rust_string(item["name"]),
                rust_string(item["wire_command"]),
                "".join(part.title() for part in item["disposition"].split("-")),
                rust_string(item["lane"]),
            )
        )
    helper_lines = []
    helper_refs = []
    for item in manifest["helpers"]:  # type: ignore[union-attr]
        helper_lines.append(
            "    CoverageEntry { name: %s, wire_command: %s, disposition: Disposition::%s, lane: %s },"
            % (
                rust_string(item["name"]),
                rust_string(item["wire_command"]),
                "".join(part.title() for part in item["disposition"].split("-")),
                rust_string(item["lane"]),
            )
        )
        if item["name"] not in EXTRA_HELPERS:
            helper_refs.append(
                f"    let _ = GmpClient::<UnixSocketConnection>::{item['name']};"
            )
    extra_refs = [
        f"    let _ = gvm_gmp::commands::tasks::{name};" for name in sorted(EXTRA_HELPERS)
    ]
    source = "\n".join(
        [
            "// SPDX-License-Identifier: AGPL-3.0-or-later",
            "// SPDX-FileCopyrightText: 2026 Greenbone AG",
            "",
            "// Generated by tools/coverage_manifest.py; do not edit manually.",
            "use gvm_client::GmpClient;",
            "use gvm_connection::UnixSocketConnection;",
            "",
            "use crate::{CoverageEntry, Disposition};",
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
            "#[allow(clippy::let_underscore_untyped)]",
            "pub fn compile_enforce_public_helper_surface() {",
            *helper_refs,
            *extra_refs,
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
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = build_manifest(args.rust_gvm_source.resolve())
    return check_or_write(outputs(manifest), args.check)


if __name__ == "__main__":
    raise SystemExit(main())
