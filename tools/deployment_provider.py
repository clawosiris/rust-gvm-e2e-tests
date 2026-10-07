#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG
"""Validate public deployment-provider inputs without reading or printing secrets."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

DEPLOYMENT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
REQUIREMENTS = {"required", "optional", "forbidden"}
STATES = {"ready", "unavailable", "unhealthy", "unknown"}


def reject_unknown(value: dict, allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{label} has unknown fields: {', '.join(unknown)}")


def load_object(path: Path, label: str) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def validate_contract(contract: dict, catalog: dict) -> None:
    reject_unknown(
        contract,
        {"schema_version", "deployment_id", "allow_legacy_fallback", "features", "fixtures"},
        "contract",
    )
    if contract.get("schema_version") != 1:
        raise ValueError("contract schema_version must be 1")
    deployment_id = contract.get("deployment_id")
    if not isinstance(deployment_id, str) or not DEPLOYMENT_ID.fullmatch(deployment_id):
        raise ValueError("contract deployment_id is invalid")
    known_features = catalog.get("features")
    if catalog.get("schema_version") != 1 or not isinstance(known_features, dict):
        raise ValueError("feature catalog is invalid")
    features = contract.get("features", {})
    fixtures = contract.get("fixtures", {})
    if not isinstance(features, dict) or not isinstance(fixtures, dict):
        raise ValueError("contract features and fixtures must be objects")
    unknown = sorted(set(features) - set(known_features))
    if unknown:
        raise ValueError(f"contract has unmapped features: {', '.join(unknown)}")
    for namespace, values in (("feature", features), ("fixture", fixtures)):
        for name, requirement in values.items():
            if requirement not in REQUIREMENTS:
                raise ValueError(f"{namespace} {name} has invalid requirement {requirement!r}")
    legacy = contract.get("allow_legacy_fallback", [])
    if not isinstance(legacy, list) or not all(isinstance(name, str) for name in legacy):
        raise ValueError("legacy fallback must be a list of contracted optional feature names")
    invalid_legacy = sorted(
        name for name in set(legacy) if features.get(name) != "optional"
    )
    if invalid_legacy:
        raise ValueError(
            "legacy fallback is allowed only for contracted optional features: "
            + ", ".join(invalid_legacy)
        )


def validate_fixture_descriptor(descriptor: dict, deployment_id: str) -> None:
    reject_unknown(
        descriptor,
        {"schema_version", "deployment_id", "fixtures", "probes"},
        "fixture descriptor",
    )
    if descriptor.get("schema_version") != 1:
        raise ValueError("fixture descriptor schema_version must be 1")
    if descriptor.get("deployment_id") != deployment_id:
        raise ValueError("fixture descriptor deployment_id does not match contract")
    fixtures = descriptor.get("fixtures")
    probes = descriptor.get("probes", {})
    if not isinstance(fixtures, dict) or not isinstance(probes, dict):
        raise ValueError("fixture descriptor fixtures must be an object")
    for namespace, values in (("fixture", fixtures), ("probe", probes)):
        for name, evidence in values.items():
            if not isinstance(evidence, dict):
                raise ValueError(f"{namespace} {name} has invalid evidence")
            reject_unknown(evidence, {"state", "detail"}, f"{namespace} {name}")
            if evidence.get("state") not in STATES:
                raise ValueError(f"{namespace} {name} has an invalid state")
            detail = evidence.get("detail")
            if not isinstance(detail, str) or not detail.strip():
                raise ValueError(f"{namespace} {name} needs nonempty evidence detail")


def validate_external_provider(provider: dict, deployment_id: str) -> None:
    reject_unknown(
        provider,
        {"schema_version", "deployment_id", "transport", "runtime_images_path"},
        "external provider descriptor",
    )
    if provider.get("schema_version") != 1 or provider.get("deployment_id") != deployment_id:
        raise ValueError("external provider schema/deployment identity mismatch")
    transport = provider.get("transport")
    if not isinstance(transport, dict) or transport.get("kind") != "unix":
        raise ValueError("external provider currently requires transport.kind=unix")
    reject_unknown(transport, {"kind", "socket_path"}, "external provider transport")
    socket_path = transport.get("socket_path")
    if not isinstance(socket_path, str) or not socket_path.startswith("/") or ".." in Path(socket_path).parts:
        raise ValueError("external provider socket_path must be an absolute normalized path")
    runtime_images = provider.get("runtime_images_path")
    if (
        not isinstance(runtime_images, str)
        or not runtime_images.startswith("/")
        or ".." in Path(runtime_images).parts
    ):
        raise ValueError(
            "external provider runtime_images_path must be an absolute normalized path"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--catalog", default=Path("coverage/feature-catalog.json"), type=Path)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--provider", choices=("compose", "external"), required=True)
    parser.add_argument("--provider-descriptor", type=Path)
    args = parser.parse_args()

    contract = load_object(args.contract, "contract")
    catalog = load_object(args.catalog, "feature catalog")
    fixtures = load_object(args.fixtures, "fixture descriptor")
    validate_contract(contract, catalog)
    validate_fixture_descriptor(fixtures, contract["deployment_id"])
    if args.provider == "external":
        if args.provider_descriptor is None:
            raise ValueError("external provider requires --provider-descriptor")
        validate_external_provider(
            load_object(args.provider_descriptor, "external provider descriptor"),
            contract["deployment_id"],
        )
    elif args.provider_descriptor is not None:
        raise ValueError("compose provider does not accept an external provider descriptor")
    print(f"validated deployment provider {contract['deployment_id']} ({args.provider})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
