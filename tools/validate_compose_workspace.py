#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG
"""Fail when Compose resolves the E2E workspace bind outside the checkout."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


def resolved_workspace_source(
    config: dict[str, Any],
    service: str = "rust-gvm-e2e",
    target: str = "/workspace",
) -> Path:
    services = config.get("services")
    if not isinstance(services, dict) or not isinstance(services.get(service), dict):
        raise ValueError(f"Compose service is missing: {service}")

    volumes = services[service].get("volumes")
    if not isinstance(volumes, list):
        raise ValueError(f"Compose service has no volumes: {service}")

    sources = [
        volume.get("source")
        for volume in volumes
        if isinstance(volume, dict)
        and volume.get("type") == "bind"
        and volume.get("target") == target
    ]
    if len(sources) != 1 or not isinstance(sources[0], str):
        raise ValueError(
            f"expected exactly one bind for {service}:{target}, found {sources!r}"
        )
    return Path(sources[0]).resolve()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose-file", required=True, action="append")
    parser.add_argument("--expected-workspace", required=True, type=Path)
    args = parser.parse_args()

    command = ["docker", "compose", "--profile", "runner"]
    for path in args.compose_file:
        command.extend(("-f", path))
    command.extend(("config", "--format", "json"))
    result = subprocess.run(command, check=True, capture_output=True, text=True)

    actual = resolved_workspace_source(json.loads(result.stdout))
    expected = args.expected_workspace.resolve()
    if actual != expected:
        raise SystemExit(
            f"Compose /workspace bind resolved to {actual}; expected {expected}"
        )
    print(f"validated Compose /workspace bind: {actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
