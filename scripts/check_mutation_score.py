#!/usr/bin/env python3
"""Fail CI when mutation coverage is missing, invalid, or below the agreed floor."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "report", nargs="?", type=Path, default=Path("coverage/gremlins/gremlins.json")
    )
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        score = check_report(report, {path.resolve() for path in SOURCE.glob("*.py")})
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"Mutation check failed: {error}", file=sys.stderr)
        return 1
    print(f"Mutation score: {score:.2f}% (minimum {MINIMUM_SCORE}%).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
