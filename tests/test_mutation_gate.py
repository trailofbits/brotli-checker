import copy
import json

import check_mutation_score as gate
import pytest


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
