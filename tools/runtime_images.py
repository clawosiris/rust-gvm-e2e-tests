#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG
"""Record exact Compose image identities for structured E2E artifacts."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


def parse_compose_images(payload: str) -> list[dict[str, Any]]:
    payload = payload.strip()
    if not payload:
        return []
    try:
        value = json.loads(payload)
        return value if isinstance(value, list) else [value]
    except json.JSONDecodeError:
        return [json.loads(line) for line in payload.splitlines() if line.strip()]


def normalize(rows: list[dict[str, Any]], inspect) -> list[dict[str, str]]:
    images: list[dict[str, str]] = []
    for row in rows:
        image_id = str(row.get("ID") or row.get("Id") or row.get("Image") or "")
        digests = inspect(image_id) if image_id else []
        images.append(
            {
                "service": str(row.get("Service") or row.get("Name") or ""),
                "repository": str(row.get("Repository") or ""),
                "tag": str(row.get("Tag") or ""),
                "digest": digests[0] if digests else image_id,
            }
        )
    return sorted(images, key=lambda item: item["service"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose-file", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    compose = subprocess.run(
        ["docker", "compose", "-f", args.compose_file, "images", "--format", "json"],
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

    result = normalize(parse_compose_images(compose.stdout), inspect)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
