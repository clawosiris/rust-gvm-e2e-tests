#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

"""Resolve workflow inputs to immutable component revisions."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass


EXACT_SHA = re.compile(r"^[0-9a-f]{40}$")
SAFE_GIT_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
SAFE_IMAGE_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")


@dataclass(frozen=True)
class ResolvedRefs:
    rust_gvm_ref: str
    rust_gvm_sha: str
    gvm_rools_ref: str
    gvm_version: str


def exact_sha(value: str, source: str) -> str:
    if not EXACT_SHA.fullmatch(value):
        raise ValueError(
            f"{source} must be an exact 40-character lowercase hexadecimal commit SHA; "
            f"got {value!r}"
        )
    return value


def safe_git_ref(value: str, source: str) -> str:
    if (
        SAFE_GIT_REF.fullmatch(value) is None
        or ".." in value
        or "@{" in value
        or value.endswith(("/", ".", ".lock"))
    ):
        raise ValueError(f"{source} is not a safe branch or tag name: {value!r}")
    return value


def safe_image_tag(value: str) -> str:
    if SAFE_IMAGE_TAG.fullmatch(value) is None:
        raise ValueError(f"GVM version is not a safe container tag: {value!r}")
    return value


def resolve(
    *,
    event_name: str,
    default_rust_gvm_sha: str,
    dispatch_rust_gvm_ref: str = "",
    dispatch_gvm_rools_ref: str = "",
    dispatch_gvm_version: str = "",
    payload_component: str = "",
    payload_ref: str = "",
    payload_gvm_version: str = "",
) -> ResolvedRefs:
    rust_ref = default_rust_gvm_sha
    rools_ref = dispatch_gvm_rools_ref or "main"
    gvm_version = dispatch_gvm_version or "stable"

    if event_name == "workflow_dispatch":
        rust_ref = dispatch_rust_gvm_ref or default_rust_gvm_sha
    elif event_name == "repository_dispatch":
        if payload_component == "rust-gvm":
            if not payload_ref:
                raise ValueError("rust-gvm repository_dispatch requires client_payload.ref")
            rust_ref = payload_ref
        elif payload_component == "gvm-rools":
            if not payload_ref:
                raise ValueError("gvm-rools repository_dispatch requires client_payload.ref")
            rools_ref = payload_ref
        else:
            raise ValueError(
                "repository_dispatch client_payload.component must be rust-gvm or gvm-rools"
            )
        gvm_version = payload_gvm_version or gvm_version

    rust_sha = exact_sha(rust_ref, "rust-gvm ref")
    return ResolvedRefs(
        rust_gvm_ref=rust_ref,
        rust_gvm_sha=rust_sha,
        gvm_rools_ref=safe_git_ref(rools_ref, "gvm-rools ref"),
        gvm_version=safe_image_tag(gvm_version),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--default-rust-gvm-sha", required=True)
    parser.add_argument("--dispatch-rust-gvm-ref", default="")
    parser.add_argument("--dispatch-gvm-rools-ref", default="")
    parser.add_argument("--dispatch-gvm-version", default="")
    parser.add_argument("--payload-component", default="")
    parser.add_argument("--payload-ref", default="")
    parser.add_argument("--payload-gvm-version", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        refs = resolve(
            event_name=args.event_name,
            default_rust_gvm_sha=args.default_rust_gvm_sha,
            dispatch_rust_gvm_ref=args.dispatch_rust_gvm_ref,
            dispatch_gvm_rools_ref=args.dispatch_gvm_rools_ref,
            dispatch_gvm_version=args.dispatch_gvm_version,
            payload_component=args.payload_component,
            payload_ref=args.payload_ref,
            payload_gvm_version=args.payload_gvm_version,
        )
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    print(f"rust-gvm-ref={refs.rust_gvm_ref}")
    print(f"rust-gvm-sha={refs.rust_gvm_sha}")
    print(f"gvm-rools-ref={refs.gvm_rools_ref}")
    print(f"gvm-version={refs.gvm_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
