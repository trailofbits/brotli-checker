import json
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import brotli_report_finalizer as subject
import pytest
from brotli_evidence_report import canonical_json, verify_report_envelope
from test_evidence_report import finding, report


def identities():
    return (
        subject.tool_identity("brotli-checker", "0.3.0", b"scanner"),
        (subject.evidence_identity("catalog", "binary", b"catalog"),),
        (subject.evidence_identity("advisory", "snapshot", b"feed"),),
        (subject.tool_identity("python-flirt", "0.10.2"),),
    )


def finalize(value, **kwargs):
    scanner, catalogs, feeds, tools = identities()
    return subject.finalize_report(
        value,
        scanner=scanner,
        catalogs=catalogs,
        feeds=feeds,
        optional_tools=tools,
        **kwargs,
    )


def test_finalizer_builds_envelope_before_attaching_derived_views():
    value = report(findings=[finding("/scope/a")])
    value["findings"][0]["evidence"]["analysis_records"] = (
        {"kind": "package", "paths": ("a", "b")},
    )

    result = finalize(value)

    assert result.comparison is None
    assert result.policy.fail is False
    assert result.report["comparison"] is None
    assert result.report["policy_decision"] == {"fail": False, "reasons": []}
    stripped, decoded = verify_report_envelope(result.report)
    assert canonical_json(stripped) == canonical_json(value)
    assert decoded == result.envelope
    assert result.sarif["runs"][0]["properties"]["report_sha256"] == (result.envelope.report_sha256)


def test_finalizer_compares_explicit_baseline_bytes_and_applies_new_policy():
    before = finalize(report(findings=[]))
    baseline = json.dumps(before.report).encode()

    after = finalize(
        report(findings=[finding("/scope/new", "vulnerable_source")]),
        baseline=baseline,
        fail_policy="new_affected",
    )

    assert after.comparison is not None
    assert after.comparison.comparable is True
    assert [item.path for item in after.comparison.new] == ["/scope/new"]
    assert after.policy.fail is True
    assert after.report["comparison"]["new"][0]["path"] == "/scope/new"


def test_finalizer_accepts_explicit_baseline_path(tmp_path):
    baseline = finalize(report())
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(baseline.report))

    current = finalize(report(), baseline=path)

    assert current.comparison is not None
    assert current.comparison.comparable is True


def test_finalizer_rejects_tampered_and_prefinalized_reports():
    baseline = finalize(report(findings=[finding("/scope/a")])).report
    baseline["findings"][0]["reason"] = "tampered"
    with pytest.raises(ValueError, match="digest does not match"):
        finalize(report(), baseline=baseline)
    with pytest.raises(ValueError, match="already finalized"):
        finalize(baseline)


def test_identity_helpers_hash_supplied_bytes_only():
    evidence = subject.evidence_identity("catalog", "fixture", b"bytes")
    tool = subject.tool_identity("tool", "1", b"binary")

    assert len(evidence.sha256) == 64
    assert len(tool.sha256 or "") == 64


def test_finalize_with_changed_identities_records_comparison_blocking_gap():
    scanner, catalogs, feeds, tools = identities()
    state = subject.FinalizationIdentities(
        scanner=scanner,
        catalogs=catalogs,
        feeds=feeds,
        optional_tools=tools,
        gaps=("Finalization inputs changed during scan: catalogs/config",),
        input_changed=True,
    )

    finalized = subject.finalize_with_identities(report(), state)

    assert finalized.report["coverage"]["gap_count"] == 1
    assert finalized.report["coverage"]["gaps"] == [
        {
            "path": "<evidence-inputs>",
            "reason": "Finalization inputs changed during scan: catalogs/config",
        }
    ]
    assert finalized.envelope.coverage.complete is False


def test_identity_collector_hashes_stable_files_data_and_tool_availability(tmp_path, monkeypatch):
    scanner_a, scanner_b = tmp_path / "a.py", tmp_path / "b.py"
    catalog = tmp_path / "catalog.json"
    scanner_a.write_bytes(b"a")
    scanner_b.write_bytes(b"b")
    catalog.write_bytes(b"catalog")

    class Distribution:
        version = "5.0.9"

        @staticmethod
        def read_text(name):
            return {"METADATA": "metadata", "RECORD": "record"}.get(name)

    def distribution(name):
        if name == "capstone":
            return Distribution()
        raise subject.importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(subject.importlib.metadata, "distribution", distribution)
    collected = subject.collect_finalization_identities(
        scanner_name="brotli-checker",
        scanner_version="0.3.0",
        scanner_files=(
            subject.IdentityPath("scanner", "b.py", scanner_b),
            subject.IdentityPath("scanner", "a.py", scanner_a),
        ),
        catalog_files=(subject.IdentityPath("catalog", "binary", catalog),),
        feed_data=(subject.IdentityData("feed", "vendor", b"snapshot"),),
        optional_tools=(
            subject.OptionalToolSpec("capstone", "capstone"),
            subject.OptionalToolSpec("python-flirt", "missing"),
        ),
        analysis_config={"xrefs": True, "deployment_roots": []},
    )

    assert collected.scanner.sha256 is not None
    binary_catalog = next(item for item in collected.catalogs if item.name == "binary")
    assert binary_catalog.sha256 == subject.hashlib.sha256(b"catalog").hexdigest()
    assert collected.feeds[0].sha256 == subject.hashlib.sha256(b"snapshot").hexdigest()
    assert [(item.name, item.version) for item in collected.optional_tools] == [
        ("capstone", "5.0.9"),
        ("python-flirt", "unavailable"),
    ]
    capstone = next(item for item in collected.optional_tools if item.name == "capstone")
    assert (
        capstone.sha256
        == subject.hashlib.sha256(b"capstone\x005.0.9\x00metadata\x00record").hexdigest()
    )
    assert collected.gaps == ()
    assert collected.input_changed is False
    assert any(item.category == "analysis-config" for item in collected.catalogs)

    reversed_order = subject.collect_finalization_identities(
        scanner_name="brotli-checker",
        scanner_version="0.3.0",
        scanner_files=(
            subject.IdentityPath("scanner", "a.py", scanner_a),
            subject.IdentityPath("scanner", "b.py", scanner_b),
        ),
    )
    assert reversed_order.scanner == collected.scanner

    scanner_a.write_bytes(b"changed")
    changed = subject.collect_finalization_identities(
        scanner_name="brotli-checker",
        scanner_version="0.3.0",
        scanner_files=(
            subject.IdentityPath("scanner", "a.py", scanner_a),
            subject.IdentityPath("scanner", "b.py", scanner_b),
        ),
        optional_tools=(),
    )
    verified = subject.verify_identity_stability(reversed_order, changed)
    assert verified.scanner == reversed_order.scanner
    assert verified.input_changed is True
    assert verified.gaps == ("Finalization inputs changed during scan: scanner",)


def test_cli_identity_helper_binds_all_effective_catalogs_and_analysis_flags(tmp_path):
    scripts = tmp_path / "skills/brotli-checker/scripts"
    references = tmp_path / "references.json"
    fingerprints = tmp_path / "fingerprints.json"
    flirt_bundle = tmp_path / "flirt.json"
    flirt_pat = tmp_path / "custom-signatures.pat"
    extra_catalog = tmp_path / "extra.json"
    scripts.mkdir(parents=True)
    (scripts / "scanner.py").write_text("scanner")
    for path in (references, fingerprints, flirt_pat, extra_catalog):
        path.write_text(path.name)
    flirt_bundle.write_text(json.dumps({"pat_file": flirt_pat.name}))

    first = subject.collect_cli_identities(
        scanner_version="0.3.0",
        analysis_config={"xrefs": True},
        code_references=references,
        source_fingerprints=fingerprints,
        flirt_bundle=flirt_bundle,
        extra_catalog_files=(subject.IdentityPath("catalog", "provider-snapshot", extra_catalog),),
        repository_root=tmp_path,
        optional_tools=(),
    )
    second = subject.collect_cli_identities(
        scanner_version="0.3.0",
        analysis_config={"xrefs": False},
        code_references=references,
        source_fingerprints=fingerprints,
        flirt_bundle=flirt_bundle,
        flirt_pat=flirt_pat,
        repository_root=tmp_path,
        optional_tools=(),
    )

    assert {item.name for item in first.catalogs} == {
        "binary-references",
        "source-fingerprints",
        "flirt-manifest",
        "flirt-patterns",
        "provider-snapshot",
        "effective",
    }
    assert first.catalogs != second.catalogs
    assert subject.resolve_flirt_identity_paths(flirt_bundle) == (flirt_bundle, flirt_pat)
    with pytest.raises(ValueError, match="does not match"):
        subject.collect_cli_identities(
            scanner_version="0.3.0",
            analysis_config={},
            code_references=references,
            source_fingerprints=fingerprints,
            flirt_bundle=flirt_bundle,
            flirt_pat=tmp_path / "wrong.pat",
            repository_root=tmp_path,
            optional_tools=(),
        )

    missing_bundle, missing_pat = tmp_path / "missing.json", tmp_path / "missing.pat"
    source_only = subject.collect_cli_identities(
        scanner_version="0.3.0",
        analysis_config={"flirt_requested": False},
        code_references=references,
        source_fingerprints=fingerprints,
        flirt_bundle=missing_bundle,
        flirt_pat=missing_pat,
        repository_root=tmp_path,
        optional_tools=(),
    )
    requested = subject.collect_cli_identities(
        scanner_version="0.3.0",
        analysis_config={"flirt_requested": True},
        code_references=references,
        source_fingerprints=fingerprints,
        flirt_bundle=missing_bundle,
        flirt_pat=missing_pat,
        repository_root=tmp_path,
        optional_tools=(),
    )
    assert source_only.gaps == ()
    assert {item.name for item in source_only.catalogs} >= {
        "flirt-manifest",
        "flirt-patterns",
    }
    assert len(requested.gaps) == 2


def test_identity_collector_rejects_symlinks_and_duplicate_names(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"source")
    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(ValueError, match="non-symlink"):
        subject.collect_finalization_identities(
            scanner_name="scanner",
            scanner_version="1",
            scanner_files=(subject.IdentityPath("scanner", "source", link),),
        )
    with pytest.raises(ValueError, match="Duplicate scanner"):
        subject.collect_finalization_identities(
            scanner_name="scanner",
            scanner_version="1",
            scanner_files=(
                subject.IdentityPath("scanner", "same", source),
                subject.IdentityPath("scanner", "same", source),
            ),
        )


def test_identity_collector_rejects_mid_hash_file_mutation(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"source")
    real_fstat = subject.os.fstat
    calls = 0

    def changed(descriptor):
        nonlocal calls
        calls += 1
        result = real_fstat(descriptor)
        if calls == 1:
            return result
        return SimpleNamespace(
            st_dev=result.st_dev,
            st_ino=result.st_ino,
            st_size=result.st_size,
            st_mtime_ns=result.st_mtime_ns + 1,
            st_ctime_ns=result.st_ctime_ns,
        )

    monkeypatch.setattr(subject.os, "fstat", changed)
    with pytest.raises(ValueError, match="changed while hashing"):
        subject.collect_finalization_identities(
            scanner_name="scanner",
            scanner_version="1",
            scanner_files=(subject.IdentityPath("scanner", "source", source),),
        )


@pytest.mark.parametrize(
    ("value_factory", "field"),
    [
        (lambda: finalize(report()), "comparison"),
        (lambda: subject.IdentityPath("scanner", "name", subject.Path("path")), "name"),
        (lambda: subject.IdentityData("feed", "name", b"data"), "name"),
        (lambda: subject.OptionalToolSpec("tool", "distribution"), "name"),
        (
            lambda: subject.FinalizationIdentities(
                scanner=identities()[0],
                catalogs=(),
                feeds=(),
                optional_tools=(),
                gaps=(),
            ),
            "input_changed",
        ),
    ],
)
def test_finalization_evidence_values_are_immutable(value_factory, field):
    with pytest.raises(FrozenInstanceError):
        setattr(value_factory(), field, "changed")


def test_identity_hashing_rejects_directories_and_uses_bounded_final_read(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="regular non-symlink"):
        subject._stable_path_sha256(tmp_path)  # noqa: SLF001 - file identity boundary

    source = tmp_path / "source"
    source.write_bytes(b"abc")
    monkeypatch.setattr(subject, "IDENTITY_CHUNK_BYTES", 2)
    original_pread = subject.os.pread
    requested = []

    def recording_pread(descriptor, size, offset):
        requested.append((size, offset))
        return original_pread(descriptor, size, offset)

    monkeypatch.setattr(subject.os, "pread", recording_pread)
    assert (
        subject._stable_path_sha256(  # noqa: SLF001 - bounded read contract
            source
        )
        == subject.hashlib.sha256(b"abc").hexdigest()
    )
    assert requested == [(2, 0), (1, 2)]


@pytest.mark.parametrize(
    ("scanner_name", "scanner_version", "include_file"),
    [("", "1", True), ("scanner", "", True), ("scanner", "1", False)],
)
def test_identity_collection_requires_each_scanner_identity_field(
    tmp_path, scanner_name, scanner_version, include_file
):
    source = tmp_path / "source.py"
    source.write_text("source")
    files = (subject.IdentityPath("scanner", "source.py", source),) if include_file else ()
    with pytest.raises(ValueError, match="requires name, version"):
        subject.collect_finalization_identities(
            scanner_name=scanner_name,
            scanner_version=scanner_version,
            scanner_files=files,
        )


def test_unlinked_flirt_pattern_is_not_part_of_catalog_identity(tmp_path):
    scripts = tmp_path / "skills/brotli-checker/scripts"
    scripts.mkdir(parents=True)
    (scripts / "scanner.py").write_text("scanner")
    references = tmp_path / "references.json"
    fingerprints = tmp_path / "fingerprints.json"
    unlinked = tmp_path / "unlinked.pat"
    for path in (references, fingerprints, unlinked):
        path.write_text(path.name)

    collected = subject.collect_cli_identities(
        scanner_version="0.3.0",
        analysis_config={"flirt_requested": False},
        code_references=references,
        source_fingerprints=fingerprints,
        flirt_pat=unlinked,
        repository_root=tmp_path,
        optional_tools=(),
    )

    assert "flirt-patterns" not in {item.name for item in collected.catalogs}


@pytest.mark.parametrize("pat_file", [1, "../outside.pat", "patterns.txt"])
def test_flirt_manifest_rejects_nonadjacent_or_nonpattern_names(tmp_path, pat_file):
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps({"pat_file": pat_file}))
    with pytest.raises(ValueError, match="Invalid FLIRT manifest pat_file"):
        subject.resolve_flirt_identity_paths(bundle)


def test_flirt_manifest_and_baseline_byte_limits_accept_exact_size(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle.json"
    raw = b'{"pat_file":"patterns.pat"}'
    bundle.write_bytes(raw)
    monkeypatch.setattr(subject, "MAX_FLIRT_MANIFEST_BYTES", len(raw))
    assert subject.resolve_flirt_identity_paths(bundle) == (bundle, tmp_path / "patterns.pat")

    baseline = tmp_path / "baseline.json"
    baseline.write_bytes(b"{}")
    monkeypatch.setattr(subject, "MAX_BASELINE_BYTES", 2)
    assert subject._baseline_json(baseline) == {}  # noqa: SLF001 - byte boundary
    assert subject._baseline_json(b"{}") == {}  # noqa: SLF001 - byte boundary
    assert subject._baseline_json("{}") == {}  # noqa: SLF001 - character boundary


@pytest.mark.parametrize(("category", "name"), [("", "name"), ("catalog", "")])
def test_evidence_identity_requires_each_label(category, name):
    with pytest.raises(ValueError, match="requires category and name"):
        subject.evidence_identity(category, name, b"data")


@pytest.mark.parametrize(("name", "version"), [("", "1"), ("tool", "")])
def test_tool_identity_requires_each_label(name, version):
    with pytest.raises(ValueError, match="requires name and version"):
        subject.tool_identity(name, version)


@pytest.mark.parametrize("coverage_value", [None, {"gaps": "invalid"}])
def test_identity_gaps_require_mutable_report_coverage(coverage_value):
    value = report()
    value["coverage"] = coverage_value
    scanner, catalogs, feeds, tools = identities()
    state = subject.FinalizationIdentities(
        scanner=scanner,
        catalogs=catalogs,
        feeds=feeds,
        optional_tools=tools,
        gaps=("changed",),
    )
    with pytest.raises(ValueError, match="cannot retain"):
        subject.finalize_with_identities(value, state)
