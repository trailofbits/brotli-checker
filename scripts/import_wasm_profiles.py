#!/usr/bin/env python3
# ruff: noqa: C901, EM101, EM102, PLR0913, PLR0915, PLR0917, TRY003
"""Build a reviewed family-specific Wasm catalog from paired known modules."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))

from brotli_binary_layout import inspect_layout  # noqa: E402
from brotli_wasm_profiles import load_wasm_profile_catalog, match_wasm_profiles  # noqa: E402

ANCHOR_COUNT = 16
SHA512_HEX_LENGTH = 128


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def identities(data: bytes) -> tuple[dict[str, Any], list[tuple[str, int]]]:
    layout = inspect_layout(data)
    if layout.get("kind") != "wasm":
        raise ValueError("Input is not a WebAssembly module")
    verified = []
    for function in layout.get("functions", []):
        identity = function.get("function_identity", {})
        if identity.get("status") == "verified_identity":
            verified.append((identity["profile_sha256"], function["size"]))
    if not verified:
        raise ValueError("Input has no verified WebAssembly function identities")
    return layout, verified


def qualification(
    package: str,
    version: str,
    tarball_url: str,
    tarball_sha512: str,
    wasm_sha256: str,
    source_commit: str,
    builder_commit: str,
    manifest_sha256: str,
    provenance_sha256: str,
    builder_archive_sha256: str,
    rebuild_wasm_sha256: str,
) -> dict[str, str]:
    if len(tarball_sha512) != SHA512_HEX_LENGTH or any(
        value not in "0123456789abcdef" for value in tarball_sha512
    ):
        raise ValueError("Package SHA-512 must be lowercase hexadecimal")
    for name, value, length in (
        ("source commit", source_commit, 40),
        ("builder commit", builder_commit, 40),
        ("manifest SHA-256", manifest_sha256, 64),
        ("provenance SHA-256", provenance_sha256, 64),
        ("builder archive SHA-256", builder_archive_sha256, 64),
    ):
        if len(value) != length or any(character not in "0123456789abcdef" for character in value):
            raise ValueError(f"Invalid lowercase hexadecimal {name}")
    return {
        "package": package,
        "package_version": version,
        "tarball_url": tarball_url,
        "tarball_sha512": tarball_sha512,
        "wasm_path": "package/brotli-core.wasm",
        "wasm_sha256": wasm_sha256,
        "source_commit": source_commit,
        "builder_commit": builder_commit,
        "manifest_sha256": manifest_sha256,
        "provenance_sha256": provenance_sha256,
        "builder_archive_sha256": builder_archive_sha256,
        "independent_rebuild_sha256": rebuild_wasm_sha256,
        "review": "paired affected/fixed package artifacts with opposite-state controls",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--affected-wasm", type=Path, required=True)
    parser.add_argument("--fixed-wasm", type=Path, required=True)
    parser.add_argument("--affected-package-version", required=True)
    parser.add_argument("--fixed-package-version", required=True)
    parser.add_argument("--affected-source-version", required=True)
    parser.add_argument("--fixed-source-version", required=True)
    parser.add_argument("--affected-tarball-url", required=True)
    parser.add_argument("--fixed-tarball-url", required=True)
    parser.add_argument("--affected-tarball-sha512", required=True)
    parser.add_argument("--fixed-tarball-sha512", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--implementation-family", required=True)
    for state in ("affected", "fixed"):
        parser.add_argument(f"--{state}-source-commit", required=True)
        parser.add_argument(f"--{state}-builder-commit", required=True)
        parser.add_argument(f"--{state}-manifest-sha256", required=True)
        parser.add_argument(f"--{state}-provenance-sha256", required=True)
        parser.add_argument(f"--{state}-builder-archive-sha256", required=True)
        parser.add_argument(f"--{state}-rebuilt-wasm", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    affected = args.affected_wasm.read_bytes()
    fixed = args.fixed_wasm.read_bytes()
    if (args.affected_rebuilt_wasm is None) != (args.fixed_rebuilt_wasm is None):
        parser.error("Both paired rebuilt Wasm inputs are required for source qualification")
    rebuilt = None
    if args.affected_rebuilt_wasm is not None and args.fixed_rebuilt_wasm is not None:
        rebuilt = (
            args.affected_rebuilt_wasm.read_bytes(),
            args.fixed_rebuilt_wasm.read_bytes(),
        )
        if rebuilt != (affected, fixed):
            parser.error(
                "Independent source rebuilds do not reproduce the reviewed package modules"
            )
    qualification_status = (
        "source_rebuild_verified" if rebuilt is not None else "pending_source_rebuild"
    )
    affected_layout, affected_values = identities(affected)
    fixed_layout, fixed_values = identities(fixed)
    affected_map = dict(affected_values)
    fixed_map = dict(fixed_values)
    affected_set, fixed_set = set(affected_map), set(fixed_map)
    affected_required = sorted(affected_set - fixed_set)
    fixed_required = sorted(fixed_set - affected_set)
    common = affected_set & fixed_set
    anchors = sorted(
        common, key=lambda value: (-min(affected_map[value], fixed_map[value]), value)
    )[:ANCHOR_COUNT]
    anchors.sort()
    if not affected_required or not fixed_required or len(anchors) != ANCHOR_COUNT:
        raise ValueError("Paired modules lack discriminating profiles or stable family anchors")

    def entry(
        state: str,
        data: bytes,
        layout: dict[str, Any],
        values: list[tuple[str, int]],
        required: list[str],
        package_version: str,
        source_version: str,
        tarball_url: str,
        tarball_sha512: str,
        source_commit: str,
        builder_commit: str,
        manifest_sha256: str,
        provenance_sha256: str,
        builder_archive_sha256: str,
        rebuild_wasm_sha256: str,
    ) -> dict[str, Any]:
        digest = hashlib.sha256(data).hexdigest()
        return {
            "id": f"{args.package}@{package_version}:{state}",
            "implementation_family": args.implementation_family,
            "source_version": source_version,
            "patch_status": f"{state}_code_match",
            "artifact_sha256": digest,
            "noncustom_sha256": layout["wasm_noncustom_sha256"],
            "artifact_size": len(data),
            "function_count": len(layout["functions"]),
            "verified_identity_count": len(values),
            "family_anchors": anchors,
            "required_profiles": required,
            "qualification": qualification(
                args.package,
                package_version,
                tarball_url,
                tarball_sha512,
                digest,
                source_commit,
                builder_commit,
                manifest_sha256,
                provenance_sha256,
                builder_archive_sha256,
                rebuild_wasm_sha256,
            ),
            "qualification_status": qualification_status,
        }

    document = {
        "schema_version": 1,
        "profiles": [
            entry(
                "vulnerable",
                affected,
                affected_layout,
                affected_values,
                affected_required,
                args.affected_package_version,
                args.affected_source_version,
                args.affected_tarball_url,
                args.affected_tarball_sha512,
                args.affected_source_commit,
                args.affected_builder_commit,
                args.affected_manifest_sha256,
                args.affected_provenance_sha256,
                args.affected_builder_archive_sha256,
                hashlib.sha256(rebuilt[0]).hexdigest() if rebuilt is not None else "",
            ),
            entry(
                "fixed",
                fixed,
                fixed_layout,
                fixed_values,
                fixed_required,
                args.fixed_package_version,
                args.fixed_source_version,
                args.fixed_tarball_url,
                args.fixed_tarball_sha512,
                args.fixed_source_commit,
                args.fixed_builder_commit,
                args.fixed_manifest_sha256,
                args.fixed_provenance_sha256,
                args.fixed_builder_archive_sha256,
                hashlib.sha256(rebuilt[1]).hexdigest() if rebuilt is not None else "",
            ),
        ],
    }
    if args.output.exists():
        parser.error("--output must be a new file")
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    catalog = load_wasm_profile_catalog(args.output)
    affected_result = match_wasm_profiles(affected, catalog, layout=affected_layout)
    fixed_result = match_wasm_profiles(fixed, catalog, layout=fixed_layout)
    if (
        affected_result.patch_status != "unknown"
        or fixed_result.patch_status != "unknown"
        or not affected_result.matches
        or not fixed_result.matches
        or affected_result.matches[0]["qualified_source_status"] != "vulnerable_code_match"
        or fixed_result.matches[0]["qualified_source_status"] != "fixed_code_match"
        or any(
            match_wasm_profiles(data, (opposite,), layout=layout).matches
            for data, layout, opposite in (
                (affected, affected_layout, catalog[1]),
                (fixed, fixed_layout, catalog[0]),
            )
        )
    ):
        args.output.unlink()
        parser.error("Generated WebAssembly profiles failed paired/opposite-state verification")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
