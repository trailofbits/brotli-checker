import copy
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import check_mutation_score as gate
import mutation_shards as shards
import pytest
import run_mutation_shard as runner

ARCHIVE_PARAMETER_TEST = "test_ar_cpio_and_rpm_payloads_are_traversed_without_extraction"
ARCHIVE_PARAMETER_NODE_PREFIX = f"tests/test_inventory.py::TestInventory::{ARCHIVE_PARAMETER_TEST}"
ARCHIVE_PARAMETER_NODE_IDS = tuple(
    f"{ARCHIVE_PARAMETER_NODE_PREFIX}[{archive}]" for archive in ("ar", "cpio", "rpm")
)


@pytest.fixture
def report():
    return {
        "summary": {
            "total": 5,
            "zapped": 4,
            "survived": 1,
            "timeout": 0,
            "error": 0,
            "pardoned": 0,
        },
        "results": [
            {"status": "survived" if index == 4 else "zapped", "file_path": "scanner.py"}
            for index in range(5)
        ],
    }


def test_gate_accepts_exact_floor_and_rejects_lower_score(report):
    assert gate.check_report(report, set()) == 80
    report["results"][0]["status"] = "survived"
    report["summary"].update(zapped=3, survived=2)
    with pytest.raises(ValueError, match="below"):
        gate.check_report(report, set())


def test_shards_preserve_global_score_and_reject_overlap_or_missing_modules(report):
    first = copy.deepcopy(report)
    second = copy.deepcopy(report)
    names = ["brotli_inventory.py", "brotli_dependencies.py"]
    for shard, name in zip((first, second), names, strict=True):
        for row in shard["results"]:
            row["file_path"] = "/other/runner/" + name
    merged = gate.combine_reports([first, second])
    expected = {gate.SOURCE / name for name in names}
    assert gate.check_report(merged, expected) == 80
    with pytest.raises(ValueError, match="overlap"):
        gate.combine_reports([first, first])
    with pytest.raises(ValueError, match="every scanner module"):
        gate.check_report(merged, expected | {gate.SOURCE / "brotli_source_leads.py"})
    second["skipped_files"] = {names[1]: "failed instrumentation"}
    with pytest.raises(ValueError, match="instrumented"):
        gate.combine_reports([first, second])


@pytest.mark.parametrize("status", ["error", "pardoned", "unknown"])
def test_runner_errors_and_unapproved_verdicts_cannot_pass(report, status):
    report["results"][0]["status"] = status
    report["summary"]["zapped"] -= 1
    report["summary"][status] = 1
    with pytest.raises((ValueError, KeyError)):
        gate.check_report(report, set())


def test_empty_skipped_missing_and_inflated_reports_fail_closed(report, tmp_path):
    for invalid in (
        {"summary": report["summary"], "results": []},
        {**report, "skipped_files": {"scanner.py": "instrumentation failed"}},
        {**report, "summary": {**report["summary"], "total": 500}},
    ):
        with pytest.raises(ValueError, match=r"No mutants|instrumented|disagrees"):
            gate.check_report(invalid, set())
    with pytest.raises(ValueError, match="every scanner module"):
        gate.check_report(report, {tmp_path / "missing.py"})
    assert gate.main([str(tmp_path / "absent.json")]) == 1
    broken = tmp_path / "broken.json"
    broken.write_text("[]")
    assert gate.main([str(broken)]) == 1


@pytest.mark.parametrize(
    "script",
    [
        "brotli_inventory.py",
        "brotli_binary_inventory.py",
        "brotli_binary_triage.py",
        "brotli_source_discovery.py",
    ],
)
def test_only_documented_cli_guard_pardons_are_accepted(report, tmp_path, script):
    path = gate.SOURCE / script
    line = path.read_text().splitlines().index('if __name__ == "__main__":') + 1
    pardon = {
        "file_path": str(path),
        "line_number": line,
        "operator": "comparison",
        "description": "== to !=",
        "status": "pardoned",
    }
    report["results"].append(pardon)
    report["summary"].update(total=6, pardoned=1)
    assert gate.check_report(report, set()) == 80
    invalid = copy.deepcopy(report)
    invalid["results"][-1]["line_number"] -= 1
    with pytest.raises(ValueError, match="unapproved pardons"):
        gate.check_report(invalid, set())
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report))
    # A valid score cannot hide all the other missing scanner modules.
    assert gate.main([str(report_path)]) == 1


def test_duplicate_cli_pardons_cannot_hide_mutants(report):
    path = gate.SOURCE / "brotli_inventory.py"
    line = path.read_text().splitlines().index('if __name__ == "__main__":') + 1
    pardon = {
        "file_path": str(path),
        "line_number": line,
        "operator": "comparison",
        "description": "== to !=",
        "status": "pardoned",
    }
    report["results"].extend([pardon, copy.deepcopy(pardon)])
    report["summary"].update(total=7, pardoned=2)
    with pytest.raises(ValueError, match="unapproved pardons"):
        gate.check_report(report, set())


def test_binary_archive_parameter_node_ids_can_be_reselected():
    result = subprocess.run(  # noqa: S603 - fixed local test runner and node IDs
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--no-cov",
            "-p",
            "no:gremlins",
            "-o",
            "addopts=--strict-config --strict-markers",
            *ARCHIVE_PARAMETER_NODE_IDS,
        ],
        check=False,
        capture_output=True,
        cwd=gate.ROOT,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "3 passed" in result.stdout


def test_unapproved_cli_guard_operator_is_rejected(report):
    path = gate.SOURCE / "brotli_inventory.py"
    line = path.read_text().splitlines().index('if __name__ == "__main__":') + 1
    report["results"].append(
        {
            "file_path": str(path),
            "line_number": line,
            "operator": "comparison",
            "description": "== to <=",
            "status": "pardoned",
        }
    )
    report["summary"].update(total=6, pardoned=1)
    with pytest.raises(ValueError, match="unapproved pardons"):
        gate.check_report(report, set())


def _manifested_shards(tmp_path: Path, module: str) -> list[Path]:
    populations = {}
    for shard, operators in shards.shard_plan(module).items():
        populations[shard] = Counter(
            {
                (operator, index, index, index, index + 1, f"{operator} mutation", False): 1
                for index, operator in enumerate(operators, 1)
            }
        )
    default_population = sum(populations.values(), Counter())
    paths = []
    for shard, population in populations.items():
        directory = tmp_path / f"{module}-{shard}"
        directory.mkdir(parents=True)
        rows = [
            {
                "gremlin_id": f"{module}-{shard}-{index}",
                "file_path": f"/runner/{module}.py",
                "line_number": line,
                "operator": operator,
                "description": description,
                "status": "zapped",
            }
            for index, (operator, line, _, _, _, description, _) in enumerate(
                population.elements(), 1
            )
        ]
        report = {
            "summary": {
                "total": len(rows),
                "zapped": len(rows),
                "survived": 0,
                "timeout": 0,
                "error": 0,
                "pardoned": 0,
            },
            "results": rows,
        }
        report_path = directory / "gremlins.json"
        raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        report_path.write_bytes(raw)
        manifest = {
            "schema_version": shards.MANIFEST_SCHEMA_VERSION,
            "module": module,
            "shard": shard,
            "operators": list(shards.shard_plan(module)[shard]),
            "source_sha256": shards.sha256_file(shards.SOURCE / f"{module}.py"),
            "report_sha256": hashlib.sha256(raw).hexdigest(),
            "default_mutant_count": sum(default_population.values()),
            "default_population_sha256": shards.population_sha256(default_population),
            "shard_mutant_count": sum(population.values()),
            "shard_population": shards.encode_population(population),
            "shard_population_sha256": shards.population_sha256(population),
            "shard_result_population_sha256": shards.population_sha256(
                shards.report_population(rows)
            ),
        }
        (directory / shards.MANIFEST_NAME).write_text(json.dumps(manifest))
        paths.append(report_path)
    return paths


def _rewrite_manifest(path: Path, **changes) -> None:
    manifest_path = path.parent / shards.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    manifest.update(changes)
    manifest_path.write_text(json.dumps(manifest))


def test_manifested_operator_shards_reconstruct_default_population(tmp_path):
    module = "brotli_binary_graph"
    paths = _manifested_shards(tmp_path, module)

    combined = gate.combine_manifested_reports(paths, expected_modules={module})

    assert combined["summary"]["total"] == 5
    assert {row["operator"] for row in combined["results"]} == set(shards.DEFAULT_OPERATORS)
    assert gate.check_report(combined, {shards.SOURCE / f"{module}.py"}) == 100


def test_manifested_shards_reject_missing_duplicate_and_disagreeing_plans(tmp_path):
    module = "brotli_binary_layout"
    paths = _manifested_shards(tmp_path, module)
    with pytest.raises(ValueError, match="incomplete"):
        gate.combine_manifested_reports(paths[:-1], expected_modules={module})
    with pytest.raises(ValueError, match="Duplicate"):
        gate.combine_manifested_reports([*paths, paths[0]], expected_modules={module})

    (paths[0].parent / shards.MANIFEST_NAME).unlink()
    with pytest.raises(FileNotFoundError):
        gate.combine_manifested_reports(paths, expected_modules={module})

    paths = _manifested_shards(tmp_path / "operators", module)
    _rewrite_manifest(paths[0], operators=["return"])
    with pytest.raises(ValueError, match="operator plan"):
        gate.combine_manifested_reports(paths, expected_modules={module})

    paths = _manifested_shards(tmp_path / "population", module)
    _rewrite_manifest(paths[0], default_mutant_count=999)
    with pytest.raises(ValueError, match="disagree"):
        gate.combine_manifested_reports(paths, expected_modules={module})


def test_manifested_shards_reject_wrong_operator_report_and_source_identity(tmp_path):
    module = "brotli_debug_companions"
    paths = _manifested_shards(tmp_path, module)
    path = paths[0]
    report = json.loads(path.read_text())
    report["results"][0]["operator"] = "return"
    raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    _rewrite_manifest(path, report_sha256=hashlib.sha256(raw).hexdigest())
    with pytest.raises(ValueError, match="outside"):
        gate.combine_manifested_reports(paths, expected_modules={module})

    paths = _manifested_shards(tmp_path / "source", module)
    _rewrite_manifest(paths[0], source_sha256="0" * 64)
    with pytest.raises(ValueError, match="source identity"):
        gate.combine_manifested_reports(paths, expected_modules={module})


def test_manifested_shards_reject_changed_counts_and_population_digests(tmp_path):
    module = "brotli_package_provenance"
    paths = _manifested_shards(tmp_path, module)
    _rewrite_manifest(paths[0], shard_mutant_count=999)
    with pytest.raises(ValueError, match=r"span population|result count"):
        gate.combine_manifested_reports(paths, expected_modules={module})

    paths = _manifested_shards(tmp_path / "digest", module)
    _rewrite_manifest(paths[0], shard_population_sha256="0" * 64)
    with pytest.raises(ValueError, match=r"span population|population digest"):
        gate.combine_manifested_reports(paths, expected_modules={module})


def test_manifested_shards_bind_exact_spans_and_selected_gremlin_ids(tmp_path):
    module = "brotli_binary_graph"
    paths = _manifested_shards(tmp_path, module)
    path = paths[0]

    manifest_path = path.parent / shards.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    manifest["shard_population"][0][2] += 1
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="span population"):
        gate.combine_manifested_reports(paths, expected_modules={module})

    paths = _manifested_shards(tmp_path / "identity", module)
    path = paths[0]
    report = json.loads(path.read_text())
    report["results"][0]["gremlin_id"] = "duplicate-selection"
    raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    _rewrite_manifest(path, report_sha256=hashlib.sha256(raw).hexdigest())
    with pytest.raises(ValueError, match="result population"):
        gate.combine_manifested_reports(paths, expected_modules={module})


def test_ci_mutation_matrix_matches_the_maintained_shard_plan():
    workflow = (gate.ROOT / ".github/workflows/checks.yml").read_text()
    configured = set(
        re.findall(
            r"^\s+- module: ([a-z0-9_]+)\n\s+shard: ([a-z0-9-]+)$",
            workflow,
            flags=re.MULTILINE,
        )
    )
    assert configured == set(shards.expected_ci_shards())
    assert len(configured) == len(shards.expected_ci_shards())
    assert "scripts/run_mutation_shard.py" in workflow


@pytest.mark.parametrize("module", sorted(shards.SPLIT_MODULES))
def test_owning_transformer_confirms_split_population(module):
    pytest.importorskip("pytest_gremlins")
    first_shard = next(iter(shards.shard_plan(module)))
    default, selected = runner.derive_populations(module, first_shard)
    assert default
    assert selected
