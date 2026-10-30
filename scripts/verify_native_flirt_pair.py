#!/usr/bin/env python3
"""Verify paired native FLIRT profiles and opposite-state negative controls."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))
from brotli_binary_data import file_data, sha256_data  # noqa: E402
from brotli_flirt import FlirtAssessment, load_flirt_bundle, match_flirt  # noqa: E402


def assessment(binary: Path, bundle: Path) -> FlirtAssessment:
    with binary.open("rb") as stream, file_data(stream, None) as data:
        return match_flirt(data, load_flirt_bundle(bundle))


def verify_own(binary: Path, bundle: Path, state: str) -> FlirtAssessment:
    result = assessment(binary, bundle)
    profiles = result.get("patch_profiles", [])
    if result["status"] != "recognized" or not profiles:
        msg = f"Native {state} profile did not match its own binary completely"
        raise ValueError(msg)
    if {item["source_state_provenance"] for item in profiles} != {state} or any(
        item["target_patch_status"] != "unknown" for item in profiles
    ):
        msg = f"Native {state} profile returned the wrong source-state population"
        raise ValueError(msg)
    return result


def verify_cross(binary: Path, bundle: Path, forbidden: str) -> None:
    profiles = assessment(binary, bundle).get("patch_profiles", [])
    if any(item["source_state_provenance"] == forbidden for item in profiles):
        msg = f"Opposite-state native {forbidden} profile matched completely"
        raise ValueError(msg)


def artifact_assertion(path: Path, state: str, result: FlirtAssessment) -> dict:
    profiles = [
        item
        for item in result.get("patch_profiles", [])
        if item["source_state_provenance"] == state
    ]
    if not profiles:
        msg = f"Exact native artifact has no complete {state} build provenance"
        raise ValueError(msg)
    provenance_by_id = {
        item["id"]: {
            **{
                key: item[key]
                for key in (
                    "id",
                    "format",
                    "abi",
                    "machine",
                    "elf_class",
                    "byteorder",
                    "source",
                    "source_sha256",
                    "headers_sha256",
                    "object_sha256",
                    "compiler",
                    "flags",
                    "build_note",
                )
            },
            "source_state": item["source_state_provenance"],
        }
        for item in profiles
    }
    provenance = [provenance_by_id[key] for key in sorted(provenance_by_id)]
    with path.open("rb") as stream, file_data(stream, None) as data:
        binary_sha256 = sha256_data(data)
        size = len(data)
    return {
        "sha256": binary_sha256,
        "size": size,
        "patch_status": f"{state}_code_match",
        "method": "paired_native_build_exact_artifact",
        "provenance": provenance,
        "negative_control": "opposite_source_state_rejected",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--affected-binary", required=True, type=Path)
    parser.add_argument("--affected-bundle", required=True, type=Path)
    parser.add_argument("--fixed-binary", required=True, type=Path)
    parser.add_argument("--fixed-bundle", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        affected = verify_own(args.affected_binary, args.affected_bundle, "vulnerable")
        fixed = verify_own(args.fixed_binary, args.fixed_bundle, "fixed")
        verify_cross(args.fixed_binary, args.affected_bundle, "vulnerable")
        verify_cross(args.affected_binary, args.fixed_bundle, "fixed")
        args.output.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "affected_match_count": len(affected["matches"]),
                    "fixed_match_count": len(fixed["matches"]),
                    "opposite_state_controls": "rejected",
                    "exact_artifact_assertions": [
                        artifact_assertion(args.affected_binary, "vulnerable", affected),
                        artifact_assertion(args.fixed_binary, "fixed", fixed),
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
