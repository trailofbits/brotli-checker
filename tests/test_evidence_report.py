import copy
import hashlib
from dataclasses import FrozenInstanceError
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


@pytest.mark.parametrize(
    "field", ["catalogs", "feeds", "relation_fingerprints", "gap_fingerprints", "report_sha256"]
)
def test_baseline_null_required_hash_is_a_validation_error_not_assertion(field):
    value = subject.envelope_json(envelope(report()))
    if field in {"catalogs", "feeds"}:
        value[field][0]["sha256"] = None
    elif field.endswith("fingerprints"):
        value[field] = [None]
    else:
        value[field] = None
    with pytest.raises(ValueError, match="SHA-256 identity is required"):
        subject.decode_envelope(value)


def test_unbound_catalog_cannot_create_reproducibility_envelope():
    with pytest.raises(ValueError, match="SHA-256 identity is required"):
        subject.build_envelope(
            report(),
            scanner=subject.ToolIdentity("scanner", "1", "b" * 64),
            catalogs=(subject.EvidenceIdentity("catalog", "missing", cast("str", None)),),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("files_seen", -1),
        ("files_read", True),
        ("gap_count", 1),
        ("gap_details_omitted", 1),
        ("gap_details_retained", 1),
        ("excluded", ".git"),
        ("excluded", [1]),
        ("symlinks_followed", "false"),
        ("gaps", None),
        ("limits", None),
    ],
    ids=[
        "negative",
        "boolean-count",
        "hidden-gap",
        "omitted-gap",
        "retained-gap",
        "exclusion-type",
        "exclusion-item",
        "symlink-type",
        "gap-type",
        "limits-type",
    ],
)
def test_invalid_coverage_cannot_become_comparable(field, value):
    document = report()
    document["coverage"][field] = value
    with pytest.raises(ValueError, match=r"(?i)coverage"):
        envelope(document)


@pytest.mark.parametrize("value", [True, -1, "10"], ids=["boolean", "negative", "string"])
def test_invalid_effective_limit_is_not_canonical(value):
    document = report()
    document["coverage"]["limits"]["max_files"] = value
    with pytest.raises(ValueError, match="coverage limit"):
        envelope(document)


def test_duplicate_catalog_and_tool_names_cannot_hide_conflicting_identities():
    scanner = subject.ToolIdentity("scanner", "1", "b" * 64)
    with pytest.raises(ValueError, match="Duplicate evidence"):
        subject.build_envelope(
            report(),
            scanner=scanner,
            catalogs=(
                subject.EvidenceIdentity("catalog", "binary", "a" * 64),
                subject.EvidenceIdentity("catalog", "binary", "c" * 64),
            ),
        )
    with pytest.raises(ValueError, match="Duplicate tool"):
        subject.build_envelope(
            report(),
            scanner=scanner,
            optional_tools=(
                subject.ToolIdentity("decoder", "1"),
                subject.ToolIdentity("decoder", "2"),
            ),
        )


def test_evidence_order_is_canonical_and_snapshot_objects_are_immutable():
    scanner = subject.ToolIdentity("scanner", "1", "a" * 64)
    catalogs = (
        subject.EvidenceIdentity("catalog", "z", "b" * 64),
        subject.EvidenceIdentity("catalog", "a", "c" * 64),
    )
    tools = (subject.ToolIdentity("z", "1"), subject.ToolIdentity("a", "1"))
    first = subject.build_envelope(
        report(), scanner=scanner, catalogs=catalogs, optional_tools=tools
    )
    second = subject.build_envelope(
        report(),
        scanner=scanner,
        catalogs=tuple(reversed(catalogs)),
        optional_tools=tuple(reversed(tools)),
    )
    assert first == second
    assert [item.name for item in first.catalogs] == ["a", "z"]
    assert [item.name for item in first.optional_tools] == ["a", "z"]
    decision = subject.evaluate_fail_policy(report(), policy="coverage")
    comparison = subject.compare_envelopes(first, second)
    for snapshot, field, replacement in (
        (first, "report_sha256", "f" * 64),
        (first.coverage, "gap_count", 10),
        (comparison, "comparable", False),
        (decision, "fail", True),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(snapshot, field, replacement)
    expected = hashlib.sha256(subject.canonical_json(subject.envelope_json(first))).hexdigest()
    assert subject.envelope_sha256(first) == expected


@pytest.mark.parametrize("field", ["findings", "relations", "gaps"])
def test_report_populations_accept_exact_budget_and_reject_overflow(monkeypatch, field):
    monkeypatch.setattr(subject, "MAX_REPORT_ITEMS", 3)
    value = report()
    if field == "findings":
        value[field] = [finding(f"/scope/{i}") for i in range(3)]
    elif field == "relations":
        value[field] = [{"source": "a", "target": str(i)} for i in range(3)]
    else:
        value["coverage"].update(
            gaps=[{"path": str(i), "reason": "unread"} for i in range(3)],
            gap_count=3,
            gap_details_retained=3,
        )
    bound = envelope(value)
    subject.decode_envelope(subject.envelope_json(bound))
    if field == "gaps":
        value["coverage"]["gaps"].append({"path": "extra", "reason": "unread"})
        value["coverage"]["gap_count"] += 1
        value["coverage"]["gap_details_retained"] += 1
    else:
        value[field].append(copy.deepcopy(value[field][0]))
    with pytest.raises(ValueError, match="excessive"):
        envelope(value)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("schema_version",), True),
        (("roots",), "/scope"),
        (("roots",), [1]),
        (("limits", "max_files"), True),
        (("limits", "max_files"), -1),
        (("scanner", "name"), ""),
        (("scanner", "version"), ""),
        (("scanner", "sha256"), None),
        (("catalogs", 0, "category"), ""),
        (("catalogs", 0, "name"), ""),
        (("optional_tools", 0, "name"), ""),
        (("optional_tools", 0, "version"), ""),
        (("coverage", "excluded"), [1]),
        (("coverage", "gap_count"), 1),
        (("findings", 0, "path"), None),
    ],
    ids=[
        "schema-bool",
        "roots-type",
        "root-item",
        "limit-bool",
        "limit-negative",
        "scanner-name",
        "scanner-version",
        "scanner-hash",
        "catalog-category",
        "catalog-name",
        "tool-name",
        "tool-version",
        "exclusions",
        "gap-count",
        "finding-path",
    ],
)
def test_malformed_stored_identity_is_rejected_without_uncaught_errors(path, replacement):
    stored = subject.envelope_json(envelope(report(findings=[finding("/scope/a")])))
    parent = stored
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = replacement
    with pytest.raises(ValueError, match=r"(?i)invalid|required|counts|unsupported"):
        subject.decode_envelope(stored)


def test_omitted_gap_details_remain_incomplete_after_storage_round_trip():
    value = report(gaps=[{"path": "unread", "reason": "limit"}])
    value["coverage"].update(gap_count=3, gap_details_omitted=2)
    first = envelope(value)
    second = subject.decode_envelope(subject.envelope_json(first))
    assert second.coverage.gap_count == 3
    assert second.coverage.gap_details_retained == 1
    assert second.coverage.gap_details_omitted == 2
    assert second.coverage.complete is False
    assert subject.compare_envelopes(first, second).comparable is False


def test_sarif_unknown_and_coverage_gaps_are_explicit_warnings():
    value = report(findings=[finding("/scope/unresolved")], gaps=[{"reason": "unread"}])
    rows = subject.render_sarif(value, envelope(value))["runs"][0]["results"]
    assert all(row["level"] == "warning" for row in rows)
    assert rows[1]["properties"]["coverage_gap"] is True
    assert "locations" not in rows[1]
    assert subject.evaluate_fail_policy({}, policy="coverage").fail is True
    assert (
        subject.evaluate_fail_policy({"coverage": {"gap_count": "0"}}, policy="coverage").fail
        is True
    )
    assert subject.evaluate_fail_policy(value, policy="new_affected").fail is True


@pytest.mark.parametrize(
    ("kind", "name", "version"),
    [("scanner", "", "1"), ("scanner", "s", ""), ("tool", "", "1"), ("tool", "t", "")],
)
def test_building_envelope_requires_each_tool_identity_field(kind, name, version):
    identity = subject.ToolIdentity(name, version, "a" * 64)
    with pytest.raises(ValueError, match=r"identity|identities"):
        subject.build_envelope(
            report(),
            scanner=identity if kind == "scanner" else subject.ToolIdentity("s", "1", "b" * 64),
            optional_tools=(identity,) if kind == "tool" else (),
        )


@pytest.mark.parametrize(("category", "name"), [("", "catalog"), ("catalog", "")])
def test_building_envelope_requires_each_catalog_identity_field(category, name):
    with pytest.raises(ValueError, match="identities"):
        subject.build_envelope(
            report(),
            scanner=subject.ToolIdentity("s", "1", "a" * 64),
            catalogs=(subject.EvidenceIdentity(category, name, "b" * 64),),
        )


def test_catalog_and_tool_elements_cannot_be_mutated_after_envelope_binding():
    bound = envelope(report())
    for item in (*bound.catalogs, *bound.feeds, bound.scanner, *bound.optional_tools):
        with pytest.raises(FrozenInstanceError):
            setattr(item, "name", "rebound")  # noqa: B010 -- Test runtime frozen-field enforcement.


@pytest.mark.parametrize("field", ["excluded", "symlinks_followed"])
def test_changed_traversal_policy_cannot_label_prior_finding_absent(field):
    before = envelope(report(findings=[finding("/scope/vendor/decoder")]))
    current = report()
    current["coverage"][field] = [".git", "vendor"] if field == "excluded" else True
    comparison = subject.compare_envelopes(before, envelope(current))
    assert comparison.comparable is False
    assert comparison.absent == ()


def test_nested_evidence_arrays_keep_semantics_while_ignoring_location_noise():
    original = finding("/scope/a")
    original["evidence"]["calls"] = [{"name": "decoder", "file_offset": 10}]
    shifted = copy.deepcopy(original)
    shifted["evidence"]["calls"][0]["file_offset"] = 100
    changed = copy.deepcopy(shifted)
    changed["evidence"]["calls"][0]["name"] = "unresolved"
    signatures = [
        envelope(report(findings=[item])).findings[0].fingerprint
        for item in (original, shifted, changed)
    ]
    assert signatures[0] == signatures[1]
    assert signatures[0] != signatures[2]


def test_disabled_archive_limit_round_trips_as_zero_not_missing():
    value = report()
    value["coverage"]["limits"]["archive_depth"] = 0
    bound = envelope(value)
    restored = subject.decode_envelope(subject.envelope_json(bound))
    assert dict(restored.limits)["archive_depth"] == 0


def test_report_roots_must_be_a_string_array_and_sarif_fixed_versions_are_notes():
    for roots in ("/scope", [1]):
        value = report()
        value["scope"] = roots
        with pytest.raises(ValueError, match="root list"):
            envelope(value)
    value = report(findings=[finding("/scope/version", "upstream_fixed_version")])
    row = subject.render_sarif(value, envelope(value))["runs"][0]["results"][0]
    assert row["level"] == "note"


@pytest.mark.parametrize(
    "path",
    [
        ("scanner", "sha256"),
        ("catalogs", 0, "sha256"),
        ("coverage", "files_read"),
        ("findings", 0, "path"),
        ("optional_tools",),
    ],
    ids=["scanner", "catalog", "coverage", "finding", "envelope"],
)
def test_missing_required_stored_fields_raise_validation_error_not_key_error(path):
    stored = subject.envelope_json(envelope(report(findings=[finding("/scope/a")])))
    parent = stored
    for key in path[:-1]:
        parent = parent[key]
    del parent[path[-1]]
    with pytest.raises(ValueError, match=r"Invalid|Unsupported"):
        subject.decode_envelope(stored)


def test_nonstring_hash_and_nonstring_json_keys_are_validation_errors():
    with pytest.raises(ValueError, match="SHA-256"):
        subject.build_envelope(
            report(), scanner=subject.ToolIdentity("scanner", "1", cast("str", 1))
        )
    with pytest.raises(ValueError, match="non-JSON"):
        subject.canonical_json({1: "not-a-string-key"})


def test_oversized_stored_finding_population_is_rejected(monkeypatch):
    stored = subject.envelope_json(
        envelope(report(findings=[finding("/scope/a"), finding("/scope/b")]))
    )
    monkeypatch.setattr(subject, "MAX_REPORT_ITEMS", 1)
    with pytest.raises(ValueError, match="envelope findings"):
        subject.decode_envelope(stored)
