"""Shared mutation-shard plan and evidence validation primitives."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "skills/brotli-checker/scripts"
MANIFEST_NAME = "shard.json"
MANIFEST_SCHEMA_VERSION = 2
SHA256_HEX_CHARS = 64
POPULATION_ENTRY_FIELDS = 7
DEFAULT_OPERATORS = ("comparison", "arithmetic", "boolean", "boundary", "return")
SPLIT_GROUPS = {
    "comparison": ("comparison",),
    "arithmetic-boundary": ("arithmetic", "boundary"),
    "boolean-return": ("boolean", "return"),
}
SPLIT_MODULES = frozenset(
    {
        "brotli_binary_graph",
        "brotli_binary_layout",
        "brotli_debug_companions",
        "brotli_inventory",
        "brotli_package_provenance",
        "brotli_payloads",
    }
)
MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "module",
        "shard",
        "operators",
        "source_sha256",
        "report_sha256",
        "default_mutant_count",
        "default_population_sha256",
        "shard_mutant_count",
        "shard_population",
        "shard_population_sha256",
        "shard_result_population_sha256",
    }
)

type PopulationEntry = tuple[str, int, int, int, int, str, bool]
type ResultEntry = tuple[str, str, int, str, bool]


def shard_plan(module: str) -> dict[str, tuple[str, ...]]:
    """Return the exact operator groups for one scanner module."""
    if module in SPLIT_MODULES:
        return dict(SPLIT_GROUPS)
    return {"all": DEFAULT_OPERATORS}


def expected_ci_shards() -> tuple[tuple[str, str], ...]:
    """Return the complete deterministic CI matrix from maintained scanner sources."""
    result = []
    for path in sorted(SOURCE.glob("*.py")):
        result.extend((path.stem, shard) for shard in shard_plan(path.stem))
    return tuple(result)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def population_entry(  # noqa: PLR0913 - A source span has four independent coordinates.
    *,
    operator: object,
    line_number: object,
    column: object,
    end_line: object,
    end_column: object,
    description: object,
    pardoned: object,
) -> PopulationEntry:
    if (
        not isinstance(operator, str)
        or operator not in DEFAULT_OPERATORS
        or type(line_number) is not int
        or line_number <= 0
        or type(column) is not int
        or column < 0
        or type(end_line) is not int
        or end_line < line_number
        or type(end_column) is not int
        or end_column < 0
        or not isinstance(description, str)
        or not description
        or not isinstance(pardoned, bool)
    ):
        msg = "Invalid mutation population entry"
        raise ValueError(msg)
    return operator, line_number, column, end_line, end_column, description, pardoned


def report_population(rows: list[dict[str, Any]]) -> Counter[ResultEntry]:
    result: Counter[ResultEntry] = Counter()
    for row in rows:
        if not isinstance(row, dict):
            msg = "Mutation result must be an object"
            raise ValueError(msg)  # noqa: TRY004 - JSON value boundary.
        gremlin_id = row.get("gremlin_id")
        operator = row.get("operator")
        line_number = row.get("line_number")
        description = row.get("description")
        if (
            not isinstance(gremlin_id, str)
            or not gremlin_id
            or not isinstance(operator, str)
            or operator not in DEFAULT_OPERATORS
            or type(line_number) is not int
            or line_number <= 0
            or not isinstance(description, str)
            or not description
        ):
            msg = "Invalid mutation result identity"
            raise ValueError(msg)
        identity = (
            gremlin_id,
            operator,
            line_number,
            description,
            row.get("status") == "pardoned",
        )
        result[identity] += 1
    return result


def population_sha256(population: Counter[tuple]) -> str:
    expanded = [entry for entry, count in population.items() for _ in range(count)]
    encoded = json.dumps(sorted(expanded), separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def encode_population(population: Counter[PopulationEntry]) -> list[list[object]]:
    """Return the exact span-bearing population in a canonical JSON domain."""
    return [list(entry) for entry, count in sorted(population.items()) for _ in range(count)]


def decode_population(value: object) -> Counter[PopulationEntry]:
    if not isinstance(value, list) or not value:
        msg = "Invalid mutation shard span population"
        raise ValueError(msg)
    result: Counter[PopulationEntry] = Counter()
    for item in value:
        if not isinstance(item, list) or len(item) != POPULATION_ENTRY_FIELDS:
            msg = "Invalid mutation shard span population"
            raise ValueError(msg)
        result[
            population_entry(
                operator=item[0],
                line_number=item[1],
                column=item[2],
                end_line=item[3],
                end_column=item[4],
                description=item[5],
                pardoned=item[6],
            )
        ] += 1
    return result


def validate_manifest(value: object) -> dict[str, Any]:  # noqa: C901 - Strict manifest boundary.
    if not isinstance(value, dict) or set(value) != MANIFEST_FIELDS:
        msg = "Invalid mutation shard manifest fields"
        raise ValueError(msg)
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != MANIFEST_SCHEMA_VERSION
    ):
        msg = "Invalid mutation shard manifest schema"
        raise ValueError(msg)
    if not isinstance(value["module"], str) or not isinstance(value["shard"], str):
        msg = "Invalid mutation shard identity"
        raise ValueError(msg)  # noqa: TRY004 - JSON value boundary.
    operators = value["operators"]
    if not isinstance(operators, list) or not all(isinstance(item, str) for item in operators):
        msg = "Invalid mutation shard operator population"
        raise ValueError(msg)
    for field in (
        "source_sha256",
        "report_sha256",
        "default_population_sha256",
        "shard_population_sha256",
        "shard_result_population_sha256",
    ):
        digest = value[field]
        if (
            not isinstance(digest, str)
            or len(digest) != SHA256_HEX_CHARS
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            msg = f"Invalid mutation shard digest: {field}"
            raise ValueError(msg)
    for field in ("default_mutant_count", "shard_mutant_count"):
        if type(value[field]) is not int or value[field] <= 0:
            msg = f"Invalid mutation shard count: {field}"
            raise ValueError(msg)
    population = decode_population(value["shard_population"])
    if (
        sum(population.values()) != value["shard_mutant_count"]
        or population_sha256(population) != value["shard_population_sha256"]
    ):
        msg = "Mutation shard span population disagrees with its manifest"
        raise ValueError(msg)
    return value
