#!/usr/bin/env python3
"""Run one planned mutation shard and bind its complete population to a manifest."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mutation_shards import (
    DEFAULT_OPERATORS,
    MANIFEST_NAME,
    MANIFEST_SCHEMA_VERSION,
    ROOT,
    SOURCE,
    encode_population,
    population_entry,
    population_sha256,
    report_population,
    sha256_file,
    shard_plan,
)

if TYPE_CHECKING:
    from pytest_gremlins.instrumentation.gremlin import Gremlin

REPORT_DIR = ROOT / "coverage/gremlins"
REPORT_PATH = REPORT_DIR / "gremlins.json"
MANIFEST_PATH = REPORT_DIR / MANIFEST_NAME


def _gremlin_population(gremlins: list[Gremlin]) -> Counter:
    result = Counter()
    for gremlin in gremlins:
        result[
            population_entry(
                operator=gremlin.operator_name,
                line_number=gremlin.line_number,
                column=gremlin.original_node.col_offset,
                end_line=gremlin.original_node.end_lineno,
                end_column=gremlin.original_node.end_col_offset,
                description=gremlin.description,
                pardoned=gremlin.pardoned,
            )
        ] += 1
    return result


def _gremlin_result_population(gremlins: list[Gremlin]) -> Counter[tuple[str, str, int, str, bool]]:
    return Counter(
        (
            gremlin.gremlin_id,
            gremlin.operator_name,
            gremlin.line_number,
            gremlin.description,
            gremlin.pardoned,
        )
        for gremlin in gremlins
    )


def derive_populations(
    module: str, shard: str
) -> tuple[Counter[tuple[str, int, str, bool]], Counter[tuple[str, int, str, bool]]]:
    """Derive default and planned populations with pytest-gremlins' owning transformer."""
    from pytest_gremlins.instrumentation.transformer import (  # noqa: PLC0415
        get_default_registry,
        transform_source,
    )

    source_path = SOURCE / f"{module}.py"
    source = source_path.read_text(encoding="utf-8")
    registry = get_default_registry()
    if tuple(registry.available()) != DEFAULT_OPERATORS:
        msg = "pytest-gremlins default operator registry changed"
        raise ValueError(msg)
    default_gremlins, _ = transform_source(source, str(source_path), registry.get_all())
    default_population = _gremlin_population(default_gremlins)
    grouped_population: Counter[tuple[str, int, str, bool]] = Counter()
    selected_population = Counter()
    for label, operators in shard_plan(module).items():
        gremlins, _ = transform_source(source, str(source_path), registry.get_all(list(operators)))
        population = _gremlin_population(gremlins)
        grouped_population.update(population)
        if label == shard:
            selected_population = population
    if grouped_population != default_population:
        msg = "Planned operator groups change pytest-gremlins' default mutant population"
        raise ValueError(msg)
    if not selected_population:
        msg = "Planned mutation shard has no mutants"
        raise ValueError(msg)
    return default_population, selected_population


def derive_shard_populations(module: str, shard: str) -> tuple[Counter, Counter, Counter]:
    """Return default spans, selected spans, and selected report identities."""
    from pytest_gremlins.instrumentation.transformer import (  # noqa: PLC0415
        get_default_registry,
        transform_source,
    )

    default_population, selected_population = derive_populations(module, shard)
    source_path = SOURCE / f"{module}.py"
    source = source_path.read_text(encoding="utf-8")
    registry = get_default_registry()
    selected, _ = transform_source(
        source, str(source_path), registry.get_all(list(shard_plan(module)[shard]))
    )
    return default_population, selected_population, _gremlin_result_population(selected)


def _load_report() -> tuple[bytes, dict[str, Any]]:
    try:
        raw = REPORT_PATH.read_bytes()
        report = json.loads(raw)
    except (OSError, json.JSONDecodeError, RecursionError) as error:
        msg = "Mutation shard did not produce a valid JSON report"
        raise ValueError(msg) from error
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        msg = "Mutation shard report has no result population"
        raise ValueError(msg)  # noqa: TRY004 - JSON value boundary.
    return raw, report


def _write_manifest(value: dict[str, Any]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="shard.", suffix=".json", dir=REPORT_DIR)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(MANIFEST_PATH)
    finally:
        with contextlib.suppress(FileNotFoundError):
            Path(temporary).unlink()


def _completed_manifest(  # noqa: PLR0913 - All bound identities are explicit.
    *,
    module: str,
    shard: str,
    operators: tuple[str, ...],
    source_path: Path,
    source_sha256: str,
    default_population: Counter,
    expected_population: Counter,
    expected_result_population: Counter,
) -> dict[str, Any]:
    raw, report = _load_report()
    rows = report["results"]
    if any(Path(row.get("file_path", "")).resolve() != source_path.resolve() for row in rows):
        msg = "Mutation shard report contains an unexpected source file"
        raise ValueError(msg)
    observed_population = report_population(rows)
    if observed_population != expected_result_population:
        msg = "Mutation shard report does not match the owning transformer's population"
        raise ValueError(msg)
    if sha256_file(source_path) != source_sha256:
        msg = "Mutation shard source changed while tests were running"
        raise ValueError(msg)
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "module": module,
        "shard": shard,
        "operators": list(operators),
        "source_sha256": source_sha256,
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "default_mutant_count": sum(default_population.values()),
        "default_population_sha256": population_sha256(default_population),
        "shard_mutant_count": sum(expected_population.values()),
        "shard_population": encode_population(expected_population),
        "shard_population_sha256": population_sha256(expected_population),
        "shard_result_population_sha256": population_sha256(expected_result_population),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module")
    parser.add_argument("shard")
    args = parser.parse_args(argv)
    source_path = SOURCE / f"{args.module}.py"
    plan = shard_plan(args.module)
    if not source_path.is_file() or args.shard not in plan:
        parser.error("module/shard is not present in the maintained mutation plan")

    try:
        populations = derive_shard_populations(args.module, args.shard)
        default_population, expected_population, expected_result_population = populations
    except (OSError, SyntaxError, ValueError) as error:
        parser.error(str(error))
    source_sha256 = sha256_file(source_path)
    REPORT_PATH.unlink(missing_ok=True)
    MANIFEST_PATH.unlink(missing_ok=True)
    operators = plan[args.shard]
    command = [
        sys.executable,
        "-m",
        "pytest",
        "--gremlins",
        "--no-cov",
        "--gremlin-executor=subprocess",
        f"--gremlin-targets={source_path.relative_to(ROOT)}",
        f"--gremlin-operators={','.join(operators)}",
    ]
    completed = subprocess.run(command, cwd=ROOT, check=False)  # noqa: S603 - fixed local toolchain
    if completed.returncode:
        return completed.returncode
    try:
        manifest = _completed_manifest(
            module=args.module,
            shard=args.shard,
            operators=operators,
            source_path=source_path,
            source_sha256=source_sha256,
            default_population=default_population,
            expected_population=expected_population,
            expected_result_population=expected_result_population,
        )
        _write_manifest(manifest)
    except (OSError, TypeError, ValueError) as error:
        print(f"Mutation shard validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
