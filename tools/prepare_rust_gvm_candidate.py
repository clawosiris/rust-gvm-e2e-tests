#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Greenbone AG

"""Prepare an ephemeral Cargo workspace for an exact rust-gvm candidate."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path


CANONICAL_REPOSITORY = "https://github.com/greenbone-hive/rust-gvm.git"
RUST_GVM_PACKAGES = {"gvm-client", "gvm-connection", "gvm-gmp", "gvm-protocol"}
EXACT_SHA = re.compile(r"^[0-9a-f]{40}$")
DEPENDENCY = re.compile(
    r'^(?P<prefix>(?P<name>gvm-(?:client|connection|gmp|protocol))\s*=\s*\{'
    r'[^\n]*git\s*=\s*"https://github\.com/greenbone-hive/rust-gvm\.git"'
    r'[^\n]*rev\s*=\s*")(?P<sha>[0-9a-f]{40})(?P<suffix>"[^\n]*\})$',
    re.MULTILINE,
)


def validate_sha(sha: str) -> None:
    if not EXACT_SHA.fullmatch(sha):
        raise ValueError(
            "rust-gvm candidate must be an exact 40-character lowercase hexadecimal SHA"
        )


def rewrite_manifest(contents: str, sha: str) -> tuple[str, set[str]]:
    validate_sha(sha)
    replaced: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        name = match.group("name")
        if name in replaced:
            raise ValueError(f"duplicate canonical rust-gvm dependency {name}")
        replaced.add(name)
        return f'{match.group("prefix")}{sha}{match.group("suffix")}'

    rewritten = DEPENDENCY.sub(replace, contents)
    if replaced != RUST_GVM_PACKAGES:
        missing = ", ".join(sorted(RUST_GVM_PACKAGES - replaced))
        extra = ", ".join(sorted(replaced - RUST_GVM_PACKAGES))
        raise ValueError(
            f"expected exactly the four canonical rust-gvm dependencies; "
            f"missing=[{missing}] extra=[{extra}]"
        )
    return rewritten, replaced


def verify_lock(lockfile: Path, sha: str) -> None:
    expected = f"git+{CANONICAL_REPOSITORY}?rev={sha}#{sha}"
    with lockfile.open("rb") as stream:
        parsed = tomllib.load(stream)
    sources = {
        package["name"]: package.get("source")
        for package in parsed.get("package", [])
        if package.get("name") in RUST_GVM_PACKAGES
    }
    if set(sources) != RUST_GVM_PACKAGES:
        raise ValueError("Cargo.lock does not contain all four rust-gvm packages")
    mismatches = {name: source for name, source in sources.items() if source != expected}
    if mismatches:
        raise ValueError(f"Cargo.lock rust-gvm sources do not match {sha}: {mismatches}")


def prepare(
    *, workspace_manifest: Path, library_manifest: Path, lockfile: Path, sha: str
) -> None:
    validate_sha(sha)
    original = library_manifest.read_text(encoding="utf-8")
    rewritten, _ = rewrite_manifest(original, sha)
    if rewritten != original:
        library_manifest.write_text(rewritten, encoding="utf-8")
        subprocess.run(
            [
                "cargo",
                "update",
                "--manifest-path",
                str(workspace_manifest),
                "--package",
                "gvm-client",
                "--precise",
                sha,
            ],
            check=True,
        )
    verify_lock(lockfile, sha)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-manifest", required=True, type=Path)
    parser.add_argument("--library-manifest", required=True, type=Path)
    parser.add_argument("--lockfile", required=True, type=Path)
    parser.add_argument("--sha", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        prepare(
            workspace_manifest=args.workspace_manifest,
            library_manifest=args.library_manifest,
            lockfile=args.lockfile,
            sha=args.sha,
        )
    except (OSError, subprocess.CalledProcessError, ValueError, tomllib.TOMLDecodeError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"prepared all four rust-gvm dependencies at exact candidate {args.sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
