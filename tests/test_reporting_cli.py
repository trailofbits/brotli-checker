import contextlib
import io
import json
from argparse import Namespace

import brotli_inventory as inventory
import brotli_report_finalizer as finalizer
import brotli_reporting_cli as reporting
import pytest


def run(*arguments):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = inventory.main(list(map(str, arguments)))
    return code, stdout.getvalue(), stderr.getvalue()


def test_source_only_fixed_report_has_envelope_without_optional_tool_gaps(monkeypatch):
    def unavailable(_name):
        raise finalizer.importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(finalizer.importlib.metadata, "distribution", unavailable)
    code, output, error = run(
        "--brotli-version",
        "1.1.1",
        "--no-flirt",
        "--json",
    )
    report = json.loads(output)

    assert code == 0
    assert error == ""
    assert report["coverage"]["gap_count"] == 0
    assert report["evidence_envelope"]["scanner"]["sha256"]
    assert {item["version"] for item in report["evidence_envelope"]["optional_tools"]} == {
        "unavailable"
    }
    assert report["comparison"] is None
    assert report["policy_decision"] == {"fail": False, "reasons": []}


def test_affected_and_coverage_fail_policies_are_explicit(tmp_path):
    affected, affected_output, _ = run(
        "--brotli-version",
        "1.2.0",
        "--no-flirt",
        "--fail-on",
        "affected",
        "--json",
    )
    opaque = tmp_path / "payload.snap"
    opaque.write_bytes(b"opaque")
    coverage, coverage_output, _ = run(
        opaque,
        "--no-flirt",
        "--fail-on",
        "coverage",
        "--json",
    )

    assert affected == 1
    assert json.loads(affected_output)["policy_decision"]["fail"] is True
    assert coverage == 1
    coverage_report = json.loads(coverage_output)
    assert coverage_report["coverage"]["gap_count"] > 0
    assert coverage_report["policy_decision"]["fail"] is True


def test_baseline_round_trip_and_new_affected_policy(tmp_path):
    baseline_code, baseline_output, _ = run("--brotli-version", "1.1.1", "--no-flirt", "--json")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(baseline_output)

    code, output, error = run(
        "--brotli-version",
        "1.1.1",
        "--no-flirt",
        "--baseline",
        baseline,
        "--fail-on",
        "new_affected",
        "--json",
    )
    report = json.loads(output)

    assert baseline_code == 0
    assert code == 0
    assert error == ""
    assert report["comparison"]["comparable"] is True
    assert report["comparison"]["new"] == []
    assert report["policy_decision"]["fail"] is False


def test_no_xrefs_configuration_drift_blocks_baseline_labels(tmp_path):
    _, baseline_output, _ = run(
        "--brotli-version",
        "1.1.1",
        "--no-flirt",
        "--no-xrefs",
        "--json",
    )
    baseline = tmp_path / "baseline.json"
    baseline.write_text(baseline_output)

    _, output, _ = run(
        "--brotli-version",
        "1.1.1",
        "--no-flirt",
        "--baseline",
        baseline,
        "--json",
    )
    comparison = json.loads(output)["comparison"]

    assert comparison["comparable"] is False
    assert "Incompatible catalogs" in comparison["reasons"]
    assert comparison["new"] == comparison["unchanged"] == comparison["absent"] == []


def test_sarif_is_rendered_from_pre_attach_envelope():
    code, output, error = run(
        "--brotli-version",
        "1.2.0",
        "--no-flirt",
        "--sarif",
    )
    sarif = json.loads(output)

    assert code == 1
    assert error == ""
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["properties"]["report_sha256"]
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def reporting_args(tmp_path, **overrides):
    values = {
        "vendor_snapshot": [],
        "flirt": False,
        "flirt_references": None,
        "catalog": None,
        "debug_file": [],
        "code_references": tmp_path / "references.json",
    }
    values.update(overrides)
    return Namespace(**values)


def test_vendor_snapshot_identity_reads_the_exact_allowed_boundary(tmp_path, monkeypatch):
    snapshot = tmp_path / "vendor.json"
    snapshot.write_bytes(b"abc")
    monkeypatch.setattr(reporting, "MAX_FEED_BYTES", 3)
    captured = []
    sentinel = object()

    def collect(**kwargs):
        captured.append(kwargs)
        return sentinel

    monkeypatch.setattr(reporting, "collect_cli_identities", collect)
    evidence = reporting.CliEvidence(
        reporting_args(tmp_path, vendor_snapshot=[snapshot]), tmp_path / "fingerprints.json"
    )

    assert evidence.before is sentinel
    assert captured[0]["vendor_feeds"][0].data == b"abc"
    snapshot.write_bytes(b"abcd")
    with pytest.raises(ValueError, match="exceeds metadata byte budget"):
        evidence.collect()


def test_enabled_flirt_uses_packaged_bundle_when_no_override_is_supplied(tmp_path, monkeypatch):
    captured = []

    def collect(**kwargs):
        captured.append(kwargs)
        return object()

    monkeypatch.setattr(reporting, "collect_cli_identities", collect)
    reporting.CliEvidence(
        reporting_args(tmp_path, flirt=True),
        tmp_path / "fingerprints.json",
    )

    assert captured[0]["flirt_bundle"] == reporting.DEFAULT_FLIRT_BUNDLE
