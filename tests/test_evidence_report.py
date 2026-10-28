import copy
from typing import cast

import brotli_evidence_report as subject
import pytest


def report(*, findings=None, gaps=None, root="/scope", limit=10):
    findings = findings or []
    gaps = gaps or []
    return {
        "schema_version": 1,
        "scope": [root],
        "findings": findings,
        "relations": [],
        "coverage": {
            "files_seen": 2,
            "files_read": 2,
            "bytes_read": 100,
            "expanded_items_read": 0,
            "expanded_bytes_read": 0,
            "archives_attempted": 0,
            "archives_opened": 0,
            "gap_count": len(gaps),
            "gap_details_retained": len(gaps),
            "gap_details_omitted": 0,
            "gaps": gaps,
            "excluded": [".git"],
            "symlinks_followed": False,
            "symlink_targets_checked_directly": 0,
            "limits": {"max_files": limit, "max_file_bytes": None},
        },
    }


def finding(path, status="unknown", *, offset=12, reason="inspect"):
    return {
        "path": path,
        "kind": "binary_candidate",
        "patch_status": status,
        "reason": reason,
        "evidence": {"file_offset": offset, "line": 7, "sha256": "a" * 64},
    }


def envelope(value, *, root_catalog="a" * 64, scanner_version="1.0"):
    return subject.build_envelope(
        value,
        scanner=subject.ToolIdentity("brotli-checker", scanner_version, "b" * 64),
        catalogs=(subject.EvidenceIdentity("catalog", "binary", root_catalog),),
        feeds=(subject.EvidenceIdentity("advisory", "snapshot", "c" * 64),),
        optional_tools=(subject.ToolIdentity("python-flirt", "0.10.2", None),),
    )


def test_envelope_is_deterministic_and_binds_inputs():
    first = report(findings=[finding("/scope/a")])
    second = copy.deepcopy(first)
    second["coverage"]["limits"] = {
        "max_file_bytes": None,
        "max_files": 10,
    }

    left = envelope(first)
    right = envelope(second)

    assert left == right
    assert left.roots == ("/scope",)
    assert left.catalogs[0].sha256 == "a" * 64
    assert left.report_sha256 == right.report_sha256
    assert len(left.findings) == 1
    assert left.coverage.complete is True
    assert subject.canonical_json(subject.envelope_json(left))
    assert subject.envelope_sha256(left) == subject.envelope_sha256(right)


def test_version_only_empty_scope_is_reproducible_and_scanner_digest_is_required():
    value = report()
    value["scope"] = []

    bound = envelope(value)

    assert bound.roots == ()
    with pytest.raises(ValueError, match="requires a SHA-256"):
        subject.build_envelope(
            value,
            scanner=subject.ToolIdentity("brotli-checker", "1.0", None),
        )


def test_finding_fingerprint_ignores_offsets_but_not_semantics():
    first = envelope(report(findings=[finding("/scope/a", offset=10)]))
    shifted = envelope(report(findings=[finding("/scope/a", offset=999)]))
    changed = envelope(report(findings=[finding("/scope/a", reason="different")]))

    assert first.findings[0].fingerprint == shifted.findings[0].fingerprint
    assert first.report_sha256 != shifted.report_sha256
    assert first.findings[0].fingerprint != changed.findings[0].fingerprint

    with_transient_id = report(findings=[finding("/scope/a")])
    with_transient_id["findings"][0]["artifact_id"] = "temporary-run-42"
    assert envelope(with_transient_id).findings[0].fingerprint == first.findings[0].fingerprint


def test_comparable_reports_label_new_unchanged_and_absent():
    before = envelope(report(findings=[finding("/scope/old"), finding("/scope/same")]))
    after = envelope(
        report(findings=[finding("/scope/same"), finding("/scope/new", "vulnerable_source")])
    )

    comparison = subject.compare_envelopes(before, after)

    assert comparison.comparable is True
    assert [item.path for item in comparison.new] == ["/scope/new"]
    assert [item.path for item in comparison.unchanged] == ["/scope/same"]
    assert [item.path for item in comparison.absent] == ["/scope/old"]


@pytest.mark.parametrize(
    ("before", "after", "reason"),
    [
        (envelope(report(root="/one")), envelope(report(root="/two")), "roots"),
        (
            envelope(report(), root_catalog="a" * 64),
            envelope(report(), root_catalog="d" * 64),
            "catalogs",
        ),
        (envelope(report(limit=10)), envelope(report(limit=11)), "limits"),
        (
            envelope(report(gaps=[{"path": "/skipped", "reason": "limit"}])),
            envelope(report()),
            "Coverage gaps",
        ),
    ],
)
def test_incompatible_reports_never_label_findings(before, after, reason):
    comparison = subject.compare_envelopes(before, after)

    assert comparison.comparable is False
    assert any(reason in value for value in comparison.reasons)
    assert comparison.new == comparison.unchanged == comparison.absent == ()


def test_coverage_shape_prevents_skipped_paths_from_becoming_absent():
    before_report = report(
        findings=[finding("/scope/missing")],
        gaps=[{"path": "/scope/skipped", "reason": "budget"}],
    )
    after_report = report(findings=[])

    comparison = subject.compare_envelopes(envelope(before_report), envelope(after_report))

    assert comparison.comparable is False
    assert comparison.absent == ()


def test_complete_reports_can_compare_when_files_are_added():
    before_report = report(findings=[])
    after_report = report(findings=[finding("/scope/new")])
    after_report["coverage"].update(files_seen=3, files_read=3, bytes_read=150)

    comparison = subject.compare_envelopes(envelope(before_report), envelope(after_report))

    assert comparison.comparable is True
    assert [item.path for item in comparison.new] == ["/scope/new"]


def test_inconsistent_coverage_gap_counts_are_rejected():
    value = report(gaps=[{"path": "/skip", "reason": "budget"}])
    value["coverage"]["gap_details_retained"] = 0

    with pytest.raises(ValueError, match="gap counts"):
        envelope(value)


def test_sarif_is_deterministic_view_with_levels_and_coverage_gaps():
    value = report(
        findings=[
            finding("/scope/z", "fixed_source", reason="fixed"),
            finding("/scope/a", "vulnerable_source", reason="affected"),
        ],
        gaps=[{"path": "/scope/unread", "reason": "budget exhausted"}],
    )
    bound = envelope(value)

    sarif = subject.render_sarif(value, bound)

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "binary_candidate",
        "coverage-gap",
    ]
    assert [(row["ruleId"], row["level"]) for row in run["results"]] == [
        ("binary_candidate", "error"),
        ("binary_candidate", "note"),
        ("coverage-gap", "warning"),
    ]
    assert subject.canonical_json(sarif) == subject.canonical_json(
        subject.render_sarif(value, bound)
    )
    changed = copy.deepcopy(value)
    changed["findings"][0]["reason"] = "changed"
    with pytest.raises(ValueError, match="does not match"):
        subject.render_sarif(changed, bound)


def test_explicit_fail_policies_do_not_change_default():
    value = report(findings=[finding("/scope/a", "vulnerable_source")])
    before = envelope(report(findings=[]))
    after = envelope(value)
    comparison = subject.compare_envelopes(before, after)

    assert subject.evaluate_fail_policy(value).fail is False
    assert subject.evaluate_fail_policy(value, policy="affected").fail is True
    assert subject.evaluate_fail_policy(value, policy="coverage").fail is False
    assert (
        subject.evaluate_fail_policy(value, policy="new_affected", comparison=comparison).fail
        is True
    )
    incompatible = subject.ReportComparison(
        comparable=False, reasons=("gap",), new=(), unchanged=(), absent=()
    )
    decision = subject.evaluate_fail_policy(value, policy="new_affected", comparison=incompatible)
    assert decision.fail is True
    assert "requires comparable" in decision.reasons[0]


def test_canonical_json_rejects_nonfinite_and_nonjson_values():
    assert subject.canonical_json({"items": ("a", "b")}) == subject.canonical_json(
        {"items": ["a", "b"]}
    )
    with pytest.raises(ValueError, match="non-finite"):
        subject.canonical_json({"value": float("nan")})
    with pytest.raises(ValueError, match="non-JSON"):
        subject.canonical_json({"value": {1, 2}})


def test_stored_envelope_round_trip_and_baseline_tampering_detection():
    value = report(findings=[finding("/scope/a")])
    bound = envelope(value)
    stored = {**value, subject.ENVELOPE_FIELD: subject.envelope_json(bound)}

    decoded_report, decoded = subject.verify_report_envelope(stored)

    assert decoded_report == value
    assert decoded == bound
    tampered = copy.deepcopy(stored)
    tampered_findings = cast("list[dict[str, object]]", tampered["findings"])
    tampered_findings[0]["reason"] = "changed after envelope"
    with pytest.raises(ValueError, match="digest does not match"):
        subject.verify_report_envelope(tampered)
    malformed = copy.deepcopy(stored)
    malformed[subject.ENVELOPE_FIELD]["roots"].append("/out-of-order")
    with pytest.raises(ValueError, match="canonical form"):
        subject.verify_report_envelope(malformed)
