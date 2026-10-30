#!/usr/bin/env python3
"""Import independently reviewed paired-native assertions into a strict catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))

from brotli_native_artifacts import validate_native_artifacts  # noqa: E402

RUN = re.compile(r"https://github\.com/trailofbits/brotli-checker/actions/runs/[1-9][0-9]*")
PAIR_ASSERTION_COUNT = 2


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:  # noqa: C901, PLR0912 -- One strict import validation boundary.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pair", action="append", required=True, type=Path)
    parser.add_argument("--artifact", action="append", required=True, type=Path)
    parser.add_argument("--build-run-url", required=True)
    parser.add_argument("--build-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (
        RUN.fullmatch(args.build_run_url) is None
        or re.fullmatch(r"[0-9a-f]{40}", args.build_commit) is None
    ):
        parser.error("invalid native build run or commit identity")
    registry = json.loads((ROOT / "skills/brotli-checker/references/fingerprints.json").read_text())
    reviewed = {
        item["sha256"]: item["state"]
        for item in registry["fingerprints"]
        if item.get("implementation", "google_brotli_c") == "google_brotli_c"
    }
    available: dict[str, Path] = {}
    for path in args.artifact:
        if not path.is_file() or path.suffix.lower() not in {".dll", ".dylib"}:
            parser.error(f"native artifact is not a linked DLL/dylib: {path}")
        digest = sha256(path)
        if digest in available:
            parser.error("duplicate linked native artifact digest")
        available[digest] = path
    records = []
    for pair_path in args.pair:
        value = json.loads(pair_path.read_bytes())
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema_version",
                "affected_match_count",
                "fixed_match_count",
                "opposite_state_controls",
                "exact_artifact_assertions",
            }
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["opposite_state_controls"] != "rejected"
            or type(value["affected_match_count"]) is not int
            or type(value["fixed_match_count"]) is not int
            or value["affected_match_count"] <= 0
            or value["fixed_match_count"] <= 0
            or not isinstance(value["exact_artifact_assertions"], list)
            or len(value["exact_artifact_assertions"]) != PAIR_ASSERTION_COUNT
        ):
            parser.error(f"invalid paired verification: {pair_path}")
        for assertion in value["exact_artifact_assertions"]:
            if not isinstance(assertion, dict):
                parser.error(f"invalid paired assertion: {pair_path}")
            digest = assertion.get("sha256")
            patch_status = assertion.get("patch_status")
            if not isinstance(digest, str) or digest not in available:
                parser.error(f"paired assertion has no exact supplied artifact: {pair_path}")
            if not isinstance(patch_status, str) or patch_status not in {
                "fixed_code_match",
                "vulnerable_code_match",
            }:
                parser.error(f"invalid paired assertion patch status: {pair_path}")
            expected_state = "fixed" if patch_status == "fixed_code_match" else "vulnerable"
            provenance = assertion.get("provenance")
            if (
                not isinstance(provenance, list)
                or not provenance
                or any(
                    not isinstance(item, dict)
                    or not isinstance(item.get("source_sha256"), str)
                    or reviewed.get(item.get("source_sha256")) != expected_state
                    or item.get("source_state") != expected_state
                    for item in provenance
                )
            ):
                parser.error(
                    f"paired assertion lacks reviewed source-state provenance: {pair_path}"
                )
            artifact = available.pop(digest)
            if assertion.get("size") != artifact.stat().st_size:
                parser.error(f"paired assertion size mismatch: {artifact}")
            records.append(
                {
                    **assertion,
                    "artifact_name": artifact.name,
                    "build_run_url": args.build_run_url,
                    "build_commit": args.build_commit,
                }
            )
    if available:
        parser.error("supplied native artifact lacks a paired assertion")
    output = {"schema_version": 1, "artifacts": sorted(records, key=lambda row: row["sha256"])}
    validate_native_artifacts(output)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
