"""CLI-independent canonical report finalization and safe baseline comparison."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from brotli_binary_data import sha256_data
from brotli_evidence_report import (
    COMPARISON_FIELD,
    ENVELOPE_FIELD,
    POLICY_FIELD,
    SELF_METADATA_FIELDS,
    EvidenceIdentity,
    PolicyDecision,
    ReportComparison,
    ReproducibilityEnvelope,
    ToolIdentity,
    build_envelope,
    canonical_json,
    compare_envelopes,
    envelope_json,
    evaluate_fail_policy,
    render_sarif,
    verify_report_envelope,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from brotli_binary_data import Buffer

MAX_BASELINE_BYTES = 64 * 1024 * 1024
MAX_FLIRT_MANIFEST_BYTES = 8 * 1024 * 1024
IDENTITY_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class FinalizedReport:
    report: dict[str, Any]
    envelope: ReproducibilityEnvelope
    comparison: ReportComparison | None
    sarif: dict[str, Any]
    policy: PolicyDecision


@dataclass(frozen=True)
class IdentityPath:
    category: str
    name: str
    path: Path


@dataclass(frozen=True)
class IdentityData:
    category: str
    name: str
    data: Buffer


@dataclass(frozen=True)
class OptionalToolSpec:
    name: str
    distribution: str


DEFAULT_OPTIONAL_TOOLS = (
    OptionalToolSpec("capstone", "capstone"),
    OptionalToolSpec("pyelftools", "pyelftools"),
    OptionalToolSpec("python-flirt", "python-flirt"),
    OptionalToolSpec("zstandard", "zstandard"),
)


@dataclass(frozen=True)
class FinalizationIdentities:
    scanner: ToolIdentity
    catalogs: tuple[EvidenceIdentity, ...]
    feeds: tuple[EvidenceIdentity, ...]
    optional_tools: tuple[ToolIdentity, ...]
    gaps: tuple[str, ...]
    input_changed: bool = False


def _stat_signature(item: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )


def _stable_path_sha256(path: Path) -> str:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            msg = f"Identity path is not a regular non-symlink file: {path}"
            raise ValueError(msg)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        msg = f"Cannot open identity path: {path}: {error}"
        raise ValueError(msg) from error
    try:
        before = os.fstat(descriptor)
        if _stat_signature(metadata) != _stat_signature(before):
            msg = f"Identity path changed while opening: {path}"
            raise ValueError(msg)
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(
                descriptor,
                min(IDENTITY_CHUNK_BYTES, before.st_size - offset),
                offset,
            )
            if not chunk:
                msg = f"Identity path changed while hashing: {path}"
                raise ValueError(msg)
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
        if _stat_signature(before) != _stat_signature(after):
            msg = f"Identity path changed while hashing: {path}"
            raise ValueError(msg)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _aggregate_identity(paths: tuple[IdentityPath, ...]) -> str:
    names = [item.name for item in paths]
    if len(names) != len(set(names)):
        msg = "Duplicate scanner identity file name"
        raise ValueError(msg)
    digest = hashlib.sha256()
    for item in sorted(paths, key=lambda value: value.name):
        digest.update(item.name.encode() + b"\0")
        digest.update(bytes.fromhex(_stable_path_sha256(item.path)))
    return digest.hexdigest()


def _optional_tool(spec: OptionalToolSpec) -> tuple[ToolIdentity, str | None]:
    try:
        distribution = importlib.metadata.distribution(spec.distribution)
    except importlib.metadata.PackageNotFoundError:
        return (
            ToolIdentity(spec.name, "unavailable", None),
            f"Optional tool unavailable: {spec.name} ({spec.distribution})",
        )
    version = distribution.version
    metadata = distribution.read_text("METADATA") or ""
    record = distribution.read_text("RECORD") or ""
    digest = hashlib.sha256(
        (spec.distribution + "\0" + version + "\0" + metadata + "\0" + record).encode()
    ).hexdigest()
    return ToolIdentity(spec.name, version, digest), None


def collect_finalization_identities(  # noqa: PLR0913 -- Independent evidence populations.
    *,
    scanner_name: str,
    scanner_version: str,
    scanner_files: tuple[IdentityPath, ...],
    catalog_files: tuple[IdentityPath, ...] = (),
    feed_data: tuple[IdentityData, ...] = (),
    optional_tools: tuple[OptionalToolSpec, ...] = (),
    analysis_config: Mapping[str, Any] | None = None,
) -> FinalizationIdentities:
    """Collect effective local identities at scan start without importing optional tools."""
    if not scanner_name or not scanner_version or not scanner_files:
        msg = "Scanner identity requires name, version, and maintained source files"
        raise ValueError(msg)
    scanner = ToolIdentity(
        scanner_name,
        scanner_version,
        _aggregate_identity(scanner_files),
    )
    catalog_identities = [
        EvidenceIdentity(item.category, item.name, _stable_path_sha256(item.path))
        for item in catalog_files
    ]
    if analysis_config is not None:
        digest = hashlib.sha256(canonical_json(dict(analysis_config))).hexdigest()
        catalog_identities.append(EvidenceIdentity("analysis-config", "effective", digest))
    catalogs = tuple(sorted(catalog_identities))
    feeds = tuple(
        sorted(
            EvidenceIdentity(item.category, item.name, sha256_data(item.data)) for item in feed_data
        )
    )
    identities = []
    for spec in optional_tools:
        identity, _ = _optional_tool(spec)
        identities.append(identity)
    return FinalizationIdentities(
        scanner,
        catalogs,
        feeds,
        tuple(sorted(identities)),
        (),
    )


def verify_identity_stability(
    before: FinalizationIdentities, after: FinalizationIdentities
) -> FinalizationIdentities:
    """Keep scan-start identities and mark any input mutation as a comparison-blocking gap."""
    changed = []
    for label, first, second in (
        ("scanner", before.scanner, after.scanner),
        ("catalogs/config", before.catalogs, after.catalogs),
        ("vendor feeds", before.feeds, after.feeds),
        ("optional tools", before.optional_tools, after.optional_tools),
    ):
        if first != second:
            changed.append(label)
    if not changed and not before.input_changed:
        return before
    reason = "Finalization inputs changed during scan: " + ", ".join(changed or ("unknown",))
    gaps = before.gaps if reason in before.gaps else (*before.gaps, reason)
    return FinalizationIdentities(
        scanner=before.scanner,
        catalogs=before.catalogs,
        feeds=before.feeds,
        optional_tools=before.optional_tools,
        gaps=gaps,
        input_changed=True,
    )


def collect_cli_identities(  # noqa: PLR0913 -- CLI evidence sources are explicit.
    *,
    scanner_version: str,
    analysis_config: Mapping[str, Any],
    code_references: Path,
    source_fingerprints: Path,
    flirt_bundle: Path | None = None,
    flirt_pat: Path | None = None,
    extra_catalog_files: tuple[IdentityPath, ...] = (),
    vendor_feeds: tuple[IdentityData, ...] = (),
    repository_root: Path | None = None,
    optional_tools: tuple[OptionalToolSpec, ...] = DEFAULT_OPTIONAL_TOOLS,
) -> FinalizationIdentities:
    """Collect the maintained CLI implementation and its effective local evidence inputs."""
    scripts = (
        repository_root / "skills/brotli-checker/scripts"
        if repository_root is not None
        else Path(__file__).resolve().parent
    )
    scanner_files = tuple(
        IdentityPath(
            "scanner",
            path.relative_to(repository_root).as_posix()
            if repository_root is not None
            else path.name,
            path,
        )
        for path in sorted(scripts.glob("*.py"))
    )
    catalogs = [
        IdentityPath("catalog", "binary-references", code_references),
        IdentityPath("catalog", "source-fingerprints", source_fingerprints),
        *extra_catalog_files,
    ]
    optional_catalogs = []
    gaps = []
    if flirt_bundle is not None and flirt_bundle.is_file():
        _, resolved_pat = resolve_flirt_identity_paths(flirt_bundle)
        if flirt_pat is not None and flirt_pat.resolve() != resolved_pat.resolve():
            msg = "Supplied FLIRT PAT does not match the manifest pat_file"
            raise ValueError(msg)
        flirt_pat = resolved_pat
    if flirt_bundle is not None and flirt_pat is None:
        flirt_pat = flirt_bundle.with_suffix(".pat")
    if flirt_bundle is not None and flirt_pat is not None:
        for name, path in (("flirt-manifest", flirt_bundle), ("flirt-patterns", flirt_pat)):
            if path.is_file():
                catalogs.append(IdentityPath("catalog", name, path))
            else:
                marker = hashlib.sha256(f"unavailable:{name}".encode()).hexdigest()
                optional_catalogs.append(EvidenceIdentity("catalog", name, marker))
                if analysis_config.get("flirt_requested") is True:
                    gaps.append(f"Requested optional catalog unavailable: {name}: {path}")
    collected = collect_finalization_identities(
        scanner_name="brotli-checker",
        scanner_version=scanner_version,
        scanner_files=scanner_files,
        catalog_files=tuple(catalogs),
        feed_data=vendor_feeds,
        optional_tools=optional_tools,
        analysis_config=analysis_config,
    )
    return FinalizationIdentities(
        scanner=collected.scanner,
        catalogs=tuple(sorted((*collected.catalogs, *optional_catalogs))),
        feeds=collected.feeds,
        optional_tools=collected.optional_tools,
        gaps=tuple(gaps),
    )


def resolve_flirt_identity_paths(bundle: Path) -> tuple[Path, Path]:
    """Resolve only the validated adjacent PAT basename declared by a supplied manifest."""
    before = _stable_path_sha256(bundle)
    with bundle.open("rb") as stream:
        raw = stream.read(MAX_FLIRT_MANIFEST_BYTES + 1)
    if len(raw) > MAX_FLIRT_MANIFEST_BYTES:
        msg = "FLIRT manifest exceeds identity parsing limit"
        raise ValueError(msg)
    after = _stable_path_sha256(bundle)
    if before != after:
        msg = "FLIRT manifest changed while resolving pat_file"
        raise ValueError(msg)
    try:
        manifest = json.loads(raw)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as error:
        msg = "Invalid FLIRT manifest JSON for identity collection"
        raise ValueError(msg) from error
    if not isinstance(manifest, dict):
        msg = "Invalid FLIRT manifest for identity collection"
        raise ValueError(msg)  # noqa: TRY004 -- Manifest is a value boundary.
    pat_file = manifest.get("pat_file")
    if (
        not isinstance(pat_file, str)
        or Path(pat_file).name != pat_file
        or not pat_file.endswith(".pat")
    ):
        msg = "Invalid FLIRT manifest pat_file"
        raise ValueError(msg)
    return bundle, bundle.parent / pat_file


def evidence_identity(category: str, name: str, data: Buffer) -> EvidenceIdentity:
    if not category or not name:
        msg = "Evidence identity requires category and name"
        raise ValueError(msg)
    return EvidenceIdentity(category, name, sha256_data(data))


def tool_identity(name: str, version: str, data: Buffer | None = None) -> ToolIdentity:
    if not name or not version:
        msg = "Tool identity requires name and version"
        raise ValueError(msg)
    return ToolIdentity(name, version, sha256_data(data) if data is not None else None)


def _finding_json(item: Any) -> dict[str, str]:  # noqa: ANN401 -- Frozen report type.
    return {
        "fingerprint": item.fingerprint,
        "path": item.path,
        "kind": item.kind,
        "patch_status": item.patch_status,
    }


def comparison_json(comparison: ReportComparison | None) -> dict[str, Any] | None:
    if comparison is None:
        return None
    return {
        "comparable": comparison.comparable,
        "reasons": list(comparison.reasons),
        "new": [_finding_json(item) for item in comparison.new],
        "unchanged": [_finding_json(item) for item in comparison.unchanged],
        "absent": [_finding_json(item) for item in comparison.absent],
    }


def policy_json(policy: PolicyDecision) -> dict[str, Any]:
    return {"fail": policy.fail, "reasons": list(policy.reasons)}


def _baseline_json(value: Path | bytes | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, Path):
        with value.open("rb") as stream:
            raw = stream.read(MAX_BASELINE_BYTES + 1)
        if len(raw) > MAX_BASELINE_BYTES:
            msg = "Baseline report exceeds byte limit"
            raise ValueError(msg)
        source: bytes | str = raw
    elif isinstance(value, (bytes, str)):
        source = value
        if len(source) > MAX_BASELINE_BYTES:
            msg = "Baseline report exceeds byte limit"
            raise ValueError(msg)
    elif isinstance(value, dict):
        return json.loads(canonical_json(value))
    else:
        msg = "Baseline must be an explicit Path, JSON bytes/text, or object"
        raise TypeError(msg)
    try:
        decoded = json.loads(source)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as error:
        msg = "Invalid baseline report JSON"
        raise ValueError(msg) from error
    if not isinstance(decoded, dict):
        msg = "Baseline report root must be an object"
        raise ValueError(msg)  # noqa: TRY004 -- Baseline JSON is a value boundary.
    return decoded


def finalize_report(  # noqa: PLR0913 -- Evidence identities are explicit independent inputs.
    report: dict[str, Any],
    *,
    scanner: ToolIdentity,
    catalogs: tuple[EvidenceIdentity, ...] = (),
    feeds: tuple[EvidenceIdentity, ...] = (),
    optional_tools: tuple[ToolIdentity, ...] = (),
    baseline: Path | bytes | str | dict[str, Any] | None = None,
    fail_policy: Literal["none", "affected", "coverage", "new_affected"] = "none",
) -> FinalizedReport:
    """Build the envelope before attaching derived comparison and policy metadata."""
    if SELF_METADATA_FIELDS.intersection(report):
        msg = "Report is already finalized or contains reserved self metadata"
        raise ValueError(msg)
    base_report = json.loads(canonical_json(report))
    envelope = build_envelope(
        base_report,
        scanner=scanner,
        catalogs=catalogs,
        feeds=feeds,
        optional_tools=optional_tools,
    )
    sarif = render_sarif(base_report, envelope)
    comparison = None
    if baseline is not None:
        _, baseline_envelope = verify_report_envelope(_baseline_json(baseline))
        comparison = compare_envelopes(baseline_envelope, envelope)
    policy = evaluate_fail_policy(
        base_report,
        policy=fail_policy,
        comparison=comparison,
    )
    finalized = {
        **base_report,
        ENVELOPE_FIELD: envelope_json(envelope),
        COMPARISON_FIELD: comparison_json(comparison),
        POLICY_FIELD: policy_json(policy),
    }
    return FinalizedReport(finalized, envelope, comparison, sarif, policy)


def finalize_with_identities(
    report: dict[str, Any],
    identities: FinalizationIdentities,
    *,
    baseline: Path | bytes | str | dict[str, Any] | None = None,
    fail_policy: Literal["none", "affected", "coverage", "new_affected"] = "none",
) -> FinalizedReport:
    """Finalize with collected identities and retain any mid-scan mutation as a coverage gap."""
    prepared = json.loads(canonical_json(report))
    if identities.gaps:
        coverage = prepared.get("coverage")
        if not isinstance(coverage, dict) or not isinstance(coverage.get("gaps"), list):
            msg = "Report coverage cannot retain finalization identity gaps"
            raise ValueError(msg)
        existing = {item.get("reason") for item in coverage["gaps"] if isinstance(item, dict)}
        additions = [
            {"path": "<evidence-inputs>", "reason": reason}
            for reason in identities.gaps
            if reason not in existing
        ]
        coverage["gaps"].extend(additions)
        coverage["gap_count"] += len(additions)
        coverage["gap_details_retained"] += len(additions)
    return finalize_report(
        prepared,
        scanner=identities.scanner,
        catalogs=identities.catalogs,
        feeds=identities.feeds,
        optional_tools=identities.optional_tools,
        baseline=baseline,
        fail_policy=fail_policy,
    )


# Short public name used by CLI glue; the explicit name remains useful to API readers.
finalize = finalize_report
