#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG
"""Record exact Compose image identities for structured E2E artifacts."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

CANONICAL_GVMD_REPOSITORY = "registry.community.greenbone.net/community/gvmd"
RELEASE_TRIPLET = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")
IMMUTABLE_DIGEST = re.compile(r"^(?:[^@\s]+@)?sha256:[0-9a-f]{64}$")


def parse_compose_images(payload: str) -> list[dict[str, Any]]:
    payload = payload.strip()
    if not payload:
        return []
    try:
        value = json.loads(payload)
        return value if isinstance(value, list) else [value]
    except json.JSONDecodeError:
        return [json.loads(line) for line in payload.splitlines() if line.strip()]


def service_name(row: dict[str, Any], services: list[str]) -> str:
    explicit = str(row.get("Service") or row.get("Name") or "")
    if explicit:
        return explicit
    container = str(row.get("ContainerName") or "")
    matches = [
        service
        for service in services
        if container == service
        or re.search(rf"-{re.escape(service)}-\d+$", container) is not None
    ]
    return matches[0] if len(matches) == 1 else container


def normalize(
    rows: list[dict[str, Any]], inspect, services: list[str] | None = None
) -> list[dict[str, str]]:
    services = services or []
    images: list[dict[str, str]] = []
    for row in rows:
        image_id = str(row.get("ID") or row.get("Id") or row.get("Image") or "")
        digests = inspect(image_id) if image_id else []
        images.append(
            {
                "service": service_name(row, services),
                "repository": str(row.get("Repository") or ""),
                "tag": str(row.get("Tag") or ""),
                "digest": digests[0] if digests else image_id,
            }
        )
    return sorted(images, key=lambda item: item["service"])


def external_gvmd_provenance(rows: object) -> dict[str, object]:
    """Validate and classify the external provider's single gvmd image row."""
    if not isinstance(rows, list):
        raise ValueError("external runtime image descriptor must be a JSON array")
    gvmd_rows = [row for row in rows if isinstance(row, dict) and row.get("service") == "gvmd"]
    if len(gvmd_rows) != 1:
        raise ValueError("external runtime image descriptor must contain exactly one gvmd row")
    row = gvmd_rows[0]
    repository = row.get("repository")
    version = row.get("version")
    digest = row.get("digest")
    source_revision = row.get("source_revision", "")
    if not isinstance(repository, str) or not repository or any(char.isspace() for char in repository):
        raise ValueError("external gvmd repository must be a nonempty whitespace-free string")
    if not isinstance(version, str) or RELEASE_TRIPLET.fullmatch(version) is None:
        raise ValueError("external gvmd version must be an exact numeric release triplet")
    if not isinstance(digest, str) or IMMUTABLE_DIGEST.fullmatch(digest) is None:
        raise ValueError("external gvmd digest must be an immutable sha256 digest")
    if not isinstance(source_revision, str):
        raise ValueError("external gvmd source_revision must be a string when present")
    source_specific = repository != CANONICAL_GVMD_REPOSITORY
    if source_revision and SOURCE_REVISION.fullmatch(source_revision) is None:
        raise ValueError("external gvmd source_revision must be an exact lowercase commit SHA")
    if source_specific and not source_revision:
        raise ValueError(
            "source-specific external gvmd image must publish org.opencontainers.image.revision"
        )
    return {
        "version": version,
        "source_revision": source_revision,
        "digest": digest,
        "source_specific_image": source_specific,
    }


def build_compose_command(
    compose_files: list[str], project_directory: str | None = None
) -> list[str]:
    command = ["docker", "compose"]
    if project_directory is not None:
        command.extend(("--project-directory", project_directory))
    for path in compose_files:
        command.extend(("-f", path))
    return command


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose-file", action="append")
    parser.add_argument("--project-directory")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--external-gvmd-provenance", type=Path)
    args = parser.parse_args()
    if args.external_gvmd_provenance is not None:
        if args.compose_file or args.project_directory or args.output:
            parser.error("--external-gvmd-provenance cannot be combined with Compose output options")
        rows = json.loads(args.external_gvmd_provenance.read_text(encoding="utf-8"))
        print(json.dumps(external_gvmd_provenance(rows)))
        return 0
    if not args.compose_file or args.output is None:
        parser.error("--compose-file and --output are required for Compose image capture")
    compose_command = build_compose_command(
        args.compose_file, args.project_directory
    )
    compose = subprocess.run(
        [*compose_command, "images", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    configured_services = subprocess.run(
        [*compose_command, "config", "--services"],
        check=True,
        capture_output=True,
        text=True,
    )

    def inspect(image_id: str) -> list[str]:
        result = subprocess.run(
            ["docker", "image", "inspect", image_id, "--format", "{{json .RepoDigests}}"],
            check=True,
            capture_output=True,
            text=True,
        )
        value = json.loads(result.stdout)
        return value if isinstance(value, list) else []

    result = normalize(
        parse_compose_images(compose.stdout),
        inspect,
        configured_services.stdout.splitlines(),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
