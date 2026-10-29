#!/usr/bin/env python3
"""Fail CI when mutation coverage is missing, invalid, or below the agreed floor."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

from mutation_shards import (
    MANIFEST_NAME,
    decode_population,
    population_sha256,
    report_population,
    sha256_file,
    shard_plan,
    validate_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "skills/brotli-checker/scripts"
MINIMUM_SCORE = 80
MAX_CLI_PARDONS = 4
STATUSES = ("zapped", "survived", "timeout", "error", "pardoned")


def cli_guard_pardon(row: dict) -> bool:
    path = Path(row["file_path"]).resolve()
    if path not in {
        SOURCE / "brotli_inventory.py",
        SOURCE / "brotli_binary_inventory.py",
        SOURCE / "brotli_binary_triage.py",
        SOURCE / "brotli_source_discovery.py",
    }:
        return False
    lines = path.read_text(encoding="utf-8").splitlines()
    line = row["line_number"]
    return (
        type(line) is int
        and 0 < line <= len(lines)
        and lines[line - 1] == 'if __name__ == "__main__":'
        and row["operator"] == "comparison"
        and row["description"] == "== to !="
    )


def validate_results(report: dict) -> tuple[list[dict], Counter]:
    if report.get("skipped_files"):
        msg = "Some source files could not be instrumented."
        raise ValueError(msg)
    summary = report["summary"]
    results = report["results"]
    if not isinstance(results, list) or not results:
        msg = "No mutants were tested."
        raise ValueError(msg)
    counts = Counter(row["status"] for row in results)
    if counts.keys() - set(STATUSES):
        msg = "Unrecognized mutant verdict."
        raise ValueError(msg)
    expected_counts = {"total": len(results), **{key: counts[key] for key in STATUSES}}
    if any(
        type(summary.get(key)) is not int or summary[key] != value
        for key, value in expected_counts.items()
    ):
        msg = "Mutation summary disagrees with individual results."
        raise ValueError(msg)
    return results, counts


def check_report(report: dict, expected_files: set[Path]) -> float:
    results, counts = validate_results(report)
    pardons = [row for row in results if row["status"] == "pardoned"]
    pardon_locations = {(row["file_path"], row["line_number"]) for row in pardons}
    if (
        counts["error"]
        or len(pardons) > MAX_CLI_PARDONS
        or len(pardon_locations) != len(pardons)
        or not all(map(cli_guard_pardon, pardons))
    ):
        msg = "Mutation run contains errors or unapproved pardons."
        raise ValueError(msg)
    tested = [row for row in results if row["status"] != "pardoned"]
    assessed = {Path(row["file_path"]).resolve() for row in tested}
    if expected_files - assessed:
        msg = "Mutation results do not cover every scanner module."
        raise ValueError(msg)
    if not tested:
        msg = "No unpardoned mutants were tested."
        raise ValueError(msg)
    score = 100 * (counts["zapped"] + counts["timeout"]) / len(tested)
    if score < MINIMUM_SCORE:
        msg = f"Mutation score {score:.2f}% is below {MINIMUM_SCORE}%."
        raise ValueError(msg)
    return score


def combine_reports(reports: list[dict]) -> dict:
    results = []
    seen_files: set[str] = set()
    for report in reports:
        rows, _ = validate_results(report)
        files = {Path(row["file_path"]).name for row in rows}
        if files & seen_files:
            msg = "Mutation shards overlap source files."
            raise ValueError(msg)
        seen_files.update(files)
        for row in rows:
            path = SOURCE / Path(row["file_path"]).name
            if not path.is_file():
                msg = "Mutation shard contains an unknown scanner module."
                raise ValueError(msg)
            results.append({**row, "file_path": str(path)})
    counts = Counter(row["status"] for row in results)
    return {
        "summary": {"total": len(results), **{key: counts[key] for key in STATUSES}},
        "results": results,
    }


def _load_manifested_report(path: Path) -> tuple[dict, dict, Counter]:  # noqa: C901
    raw = path.read_bytes()
    report = json.loads(raw)
    if not isinstance(report, dict):
        msg = "Mutation report root must be an object."
        raise ValueError(msg)  # noqa: TRY004 - JSON value boundary.
    rows, _ = validate_results(report)
    manifest_path = path.parent / MANIFEST_NAME
    manifest = validate_manifest(json.loads(manifest_path.read_text(encoding="utf-8")))
    module = manifest["module"]
    source = SOURCE / f"{module}.py"
    if not source.is_file():
        msg = "Mutation shard manifest names an unknown scanner module."
        raise ValueError(msg)
    plan = shard_plan(module)
    shard = manifest["shard"]
    if shard not in plan or manifest["operators"] != list(plan[shard]):
        msg = "Mutation shard manifest is not in the maintained operator plan."
        raise ValueError(msg)
    if manifest["source_sha256"] != sha256_file(source):
        msg = "Mutation shard source identity does not match the checked-out scanner."
        raise ValueError(msg)
    if manifest["report_sha256"] != hashlib.sha256(raw).hexdigest():
        msg = "Mutation shard report digest does not match its manifest."
        raise ValueError(msg)
    if len(rows) != manifest["shard_mutant_count"]:
        msg = "Mutation shard result count does not match its manifest."
        raise ValueError(msg)
    allowed_operators = set(plan[shard])
    for row in rows:
        if (
            Path(row.get("file_path", "")).name != source.name
            or row.get("operator") not in allowed_operators
        ):
            msg = "Mutation shard result is outside its declared file/operator population."
            raise ValueError(msg)
    result_population = report_population(rows)
    if population_sha256(result_population) != manifest["shard_result_population_sha256"]:
        msg = "Mutation shard result population digest does not match its manifest."
        raise ValueError(msg)
    population = decode_population(manifest["shard_population"])
    return report, manifest, population


def combine_manifested_reports(  # noqa: C901 - One cross-shard validation boundary.
    paths: list[Path], *, expected_modules: set[str] | None = None
) -> dict:
    """Combine hash-bound operator shards only after proving the complete maintained plan."""
    expected = (
        expected_modules
        if expected_modules is not None
        else {path.stem for path in SOURCE.glob("*.py")}
    )
    by_module: dict[str, dict[str, tuple[dict, dict, Counter]]] = {}
    for path in paths:
        report, manifest, population = _load_manifested_report(path)
        module, shard = manifest["module"], manifest["shard"]
        if shard in by_module.setdefault(module, {}):
            msg = "Duplicate mutation operator shard."
            raise ValueError(msg)
        by_module[module][shard] = report, manifest, population
    if set(by_module) != expected:
        msg = "Mutation shards do not cover exactly every scanner module."
        raise ValueError(msg)

    results = []
    for module in sorted(by_module):
        shards = by_module[module]
        plan = shard_plan(module)
        if set(shards) != set(plan):
            msg = f"Mutation operator shards are incomplete for {module}."
            raise ValueError(msg)
        manifests = [value[1] for value in shards.values()]
        default_counts = {item["default_mutant_count"] for item in manifests}
        default_digests = {item["default_population_sha256"] for item in manifests}
        if len(default_counts) != 1 or len(default_digests) != 1:
            msg = f"Mutation shards disagree about the default population for {module}."
            raise ValueError(msg)
        combined_population = Counter()
        for shard in plan:
            report, _, population = shards[shard]
            combined_population.update(population)
            results.extend(
                {**row, "file_path": str(SOURCE / f"{module}.py")} for row in report["results"]
            )
        if sum(combined_population.values()) != next(iter(default_counts)) or population_sha256(
            combined_population
        ) != next(iter(default_digests)):
            msg = f"Mutation operator shards change the default population for {module}."
            raise ValueError(msg)
    counts = Counter(row["status"] for row in results)
    return {
        "summary": {"total": len(results), **{key: counts[key] for key in STATUSES}},
        "results": results,
    }


def _reject_mixed_manifest_modes(manifests: list[bool]) -> None:
    if any(manifests) and not all(manifests):
        msg = "Mutation evidence mixes manifested and legacy shards."
        raise ValueError(msg)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "reports", nargs="*", type=Path, default=[Path("coverage/gremlins/gremlins.json")]
    )
    args = parser.parse_args(argv)
    try:
        manifests = [(path.parent / MANIFEST_NAME).is_file() for path in args.reports]
        _reject_mixed_manifest_modes(manifests)
        if manifests and all(manifests):
            report = combine_manifested_reports(args.reports)
        else:
            reports = [json.loads(path.read_text(encoding="utf-8")) for path in args.reports]
            report = combine_reports(reports) if len(reports) > 1 else reports[0]
        score = check_report(report, {path.resolve() for path in SOURCE.glob("*.py")})
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"Mutation check failed: {error}", file=sys.stderr)
        return 1
    print(f"Mutation score: {score:.2f}% (minimum {MINIMUM_SCORE}%).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
