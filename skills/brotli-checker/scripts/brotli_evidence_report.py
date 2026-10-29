"""Deterministic evidence envelopes, comparison, SARIF, and opt-in fail policies."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Literal, cast

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
MAX_REPORT_ITEMS = 100_000
UNSTABLE_FIELDS = frozenset(
    {
        "additional_section_offsets",
        "address",
        "artifact_id",
        "artifact_index",
        "elapsed_seconds",
        "file_offset",
        "line",
        "offset",
        "virtual_addresses",
    }
)
DEFAULT_AFFECTED_STATUSES = frozenset(
    {
        "affected_port_source",
        "mixed_code_matches",
        "potentially_vulnerable",
        "vulnerable_code_match",
        "vulnerable_source",
    }
)
ENVELOPE_FIELD = "evidence_envelope"
COMPARISON_FIELD = "comparison"
POLICY_FIELD = "policy_decision"
SELF_METADATA_FIELDS = frozenset({ENVELOPE_FIELD, COMPARISON_FIELD, POLICY_FIELD})


@dataclass(frozen=True, order=True)
class EvidenceIdentity:
    category: str
    name: str
    sha256: str


@dataclass(frozen=True, order=True)
class ToolIdentity:
    name: str
    version: str
    sha256: str | None = None


@dataclass(frozen=True, order=True)
class FindingSignature:
    fingerprint: str
    path: str
    kind: str
    patch_status: str


@dataclass(frozen=True)
class CoverageSignature:
    files_seen: int
    files_read: int
    bytes_read: int
    expanded_items_read: int
    expanded_bytes_read: int
    archives_attempted: int
    archives_opened: int
    gap_count: int
    gap_details_retained: int
    gap_details_omitted: int
    excluded: tuple[str, ...]
    symlinks_followed: bool
    symlink_targets_checked_directly: int

    @property
    def complete(self) -> bool:
        return self.gap_count == 0 and self.gap_details_omitted == 0

    @property
    def comparison_shape(self) -> tuple[Any, ...]:
        return (
            self.excluded,
            self.symlinks_followed,
        )


@dataclass(frozen=True)
class ReproducibilityEnvelope:
    schema_version: int
    report_schema_version: int
    roots: tuple[str, ...]
    scanner: ToolIdentity
    catalogs: tuple[EvidenceIdentity, ...]
    feeds: tuple[EvidenceIdentity, ...]
    optional_tools: tuple[ToolIdentity, ...]
    limits: tuple[tuple[str, int | None], ...]
    coverage: CoverageSignature
    report_sha256: str
    findings: tuple[FindingSignature, ...]
    relation_fingerprints: tuple[str, ...]
    gap_fingerprints: tuple[str, ...]


@dataclass(frozen=True)
class ReportComparison:
    comparable: bool
    reasons: tuple[str, ...]
    new: tuple[FindingSignature, ...]
    unchanged: tuple[FindingSignature, ...]
    absent: tuple[FindingSignature, ...]


@dataclass(frozen=True)
class PolicyDecision:
    fail: bool
    reasons: tuple[str, ...]


def _validate_json(value: Any) -> None:  # noqa: ANN401 -- Recursive JSON domain validation.
    stack = [value]
    seen = 0
    while stack:
        item = stack.pop()
        seen += 1
        if seen > MAX_REPORT_ITEMS * 100:
            msg = "Report JSON node limit reached"
            raise ValueError(msg)
        if item is None or isinstance(item, (str, bool, int)):
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                msg = "Report contains a non-finite number"
                raise ValueError(msg)
            continue
        if isinstance(item, (list, tuple)):
            stack.extend(item)
            continue
        if isinstance(item, dict) and all(isinstance(key, str) for key in item):
            stack.extend(item.values())
            continue
        msg = f"Report contains a non-JSON value: {type(item).__name__}"
        raise ValueError(msg)


def canonical_json(value: Any) -> bytes:  # noqa: ANN401 -- Public JSON value contract.
    """Return one stable UTF-8 JSON encoding after validating the JSON domain."""
    _validate_json(value)
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _digest(value: Any) -> str:  # noqa: ANN401 -- Internal canonical JSON hashing.
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _stable(value: Any) -> Any:  # noqa: ANN401 -- Recursive JSON normalization.
    if isinstance(value, (list, tuple)):
        return [_stable(item) for item in value]
    if isinstance(value, dict):
        return {key: _stable(item) for key, item in value.items() if key not in UNSTABLE_FIELDS}
    return value


def _nonnegative(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        msg = f"Invalid coverage field: {field}"
        raise ValueError(msg)
    return value


def _coverage(value: object) -> CoverageSignature:
    if not isinstance(value, dict):
        msg = "Report coverage must be an object"
        raise ValueError(msg)  # noqa: TRY004 -- Malformed report is a value error.
    excluded = value.get("excluded", [])
    if not isinstance(excluded, list) or not all(isinstance(item, str) for item in excluded):
        msg = "Invalid coverage excluded paths"
        raise ValueError(msg)
    followed = value.get("symlinks_followed")
    if not isinstance(followed, bool):
        msg = "Invalid coverage symlink policy"
        raise ValueError(msg)  # noqa: TRY004 -- Malformed report is a value error.
    gaps = value.get("gaps")
    if not isinstance(gaps, list):
        msg = "Invalid coverage gap population"
        raise ValueError(msg)  # noqa: TRY004 -- Malformed report is a value error.
    result = CoverageSignature(
        *(
            _nonnegative(value.get(field), field)
            for field in (
                "files_seen",
                "files_read",
                "bytes_read",
                "expanded_items_read",
                "expanded_bytes_read",
                "archives_attempted",
                "archives_opened",
                "gap_count",
                "gap_details_retained",
                "gap_details_omitted",
            )
        ),
        tuple(sorted(set(excluded))),
        followed,
        _nonnegative(
            value.get("symlink_targets_checked_directly"),
            "symlink_targets_checked_directly",
        ),
    )
    if len(gaps) != result.gap_details_retained or result.gap_count != (
        result.gap_details_retained + result.gap_details_omitted
    ):
        msg = "Coverage gap counts do not match retained and omitted details"
        raise ValueError(msg)
    return result


def _sha256(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) != hashlib.sha256().digest_size * 2
        or any(character not in "0123456789abcdef" for character in value)
    ):
        msg = f"Invalid SHA-256 identity: {field}"
        raise ValueError(msg)
    return value


def _required_sha256(value: str | None, field: str) -> str:
    digest = _sha256(value, field)
    if digest is None:
        message = f"SHA-256 identity is required: {field}"
        raise ValueError(message)
    return digest


def _validate_evidence(items: tuple[EvidenceIdentity, ...]) -> tuple[EvidenceIdentity, ...]:
    unique = set()
    for item in items:
        if not item.category or not item.name:
            msg = "Evidence identities require category and name"
            raise ValueError(msg)
        _required_sha256(item.sha256, f"{item.category}:{item.name}")
        key = item.category, item.name
        if key in unique:
            msg = f"Duplicate evidence identity: {item.category}:{item.name}"
            raise ValueError(msg)
        unique.add(key)
    return tuple(sorted(items))


def _validate_tools(items: tuple[ToolIdentity, ...]) -> tuple[ToolIdentity, ...]:
    unique = set()
    for item in items:
        if not item.name or not item.version:
            msg = "Tool identities require name and version"
            raise ValueError(msg)
        _sha256(item.sha256, item.name)
        if item.name in unique:
            msg = f"Duplicate tool identity: {item.name}"
            raise ValueError(msg)
        unique.add(item.name)
    return tuple(sorted(items))


def _finding_signatures(value: object) -> tuple[FindingSignature, ...]:
    if not isinstance(value, list) or len(value) > MAX_REPORT_ITEMS:
        msg = "Invalid or excessive report findings"
        raise ValueError(msg)
    rows = []
    for item in value:
        if not isinstance(item, dict):
            msg = "Report finding must be an object"
            raise ValueError(msg)  # noqa: TRY004 -- Malformed report is a value error.
        stable = _stable(item)
        rows.append(
            FindingSignature(
                _digest(stable),
                str(item.get("path", "")),
                str(item.get("kind", "unknown")),
                str(item.get("patch_status", "unknown")),
            )
        )
    return tuple(sorted(set(rows)))


def build_envelope(  # noqa: C901 -- Canonical report and evidence validation share one boundary.
    report: dict[str, Any],
    *,
    scanner: ToolIdentity,
    catalogs: tuple[EvidenceIdentity, ...] = (),
    feeds: tuple[EvidenceIdentity, ...] = (),
    optional_tools: tuple[ToolIdentity, ...] = (),
) -> ReproducibilityEnvelope:
    """Bind canonical report evidence to exact scanner inputs and effective coverage."""
    _validate_json(report)
    if type(report.get("schema_version")) is not int:
        msg = "Invalid report schema version"
        raise ValueError(msg)
    scope = report.get("scope")
    if not isinstance(scope, list) or not all(isinstance(item, str) for item in scope):
        msg = "Report scope must be a root list"
        raise ValueError(msg)
    coverage_value = report.get("coverage")
    coverage = _coverage(coverage_value)
    coverage_value = cast("dict[str, Any]", coverage_value)
    limits_value = coverage_value.get("limits")
    if not isinstance(limits_value, dict):
        msg = "Report coverage limits must be an object"
        raise ValueError(msg)  # noqa: TRY004 -- Malformed report is a value error.
    limits = []
    for key, value in limits_value.items():
        if not isinstance(key, str) or (
            value is not None and (type(value) is not int or value < 0)
        ):
            msg = "Invalid report coverage limit"
            raise ValueError(msg)
        limits.append((key, value))
    if not scanner.name or not scanner.version:
        msg = "Scanner identity requires name and version"
        raise ValueError(msg)
    if scanner.sha256 is None:
        msg = "Scanner identity requires a SHA-256 digest"
        raise ValueError(msg)
    _sha256(scanner.sha256, scanner.name)
    relations = report.get("relations", [])
    gaps = coverage_value.get("gaps", [])
    if not isinstance(relations, list) or len(relations) > MAX_REPORT_ITEMS:
        msg = "Invalid or excessive report relations"
        raise ValueError(msg)
    if not isinstance(gaps, list) or len(gaps) > MAX_REPORT_ITEMS:
        msg = "Invalid or excessive report gaps"
        raise ValueError(msg)
    return ReproducibilityEnvelope(
        1,
        report["schema_version"],
        tuple(sorted(set(scope))),
        scanner,
        _validate_evidence(catalogs),
        _validate_evidence(feeds),
        _validate_tools(optional_tools),
        tuple(sorted(limits)),
        coverage,
        hashlib.sha256(canonical_json(report)).hexdigest(),
        _finding_signatures(report.get("findings")),
        tuple(sorted({_digest(_stable(item)) for item in relations})),
        tuple(sorted({_digest(_stable(item)) for item in gaps})),
    )


def envelope_json(envelope: ReproducibilityEnvelope) -> dict[str, Any]:
    """Return the canonical JSON-domain representation of one immutable envelope."""

    def tool(item: ToolIdentity) -> dict[str, Any]:
        return {"name": item.name, "version": item.version, "sha256": item.sha256}

    def evidence(item: EvidenceIdentity) -> dict[str, str]:
        return {"category": item.category, "name": item.name, "sha256": item.sha256}

    return {
        "schema_version": envelope.schema_version,
        "report_schema_version": envelope.report_schema_version,
        "roots": list(envelope.roots),
        "scanner": tool(envelope.scanner),
        "catalogs": [evidence(item) for item in envelope.catalogs],
        "feeds": [evidence(item) for item in envelope.feeds],
        "optional_tools": [tool(item) for item in envelope.optional_tools],
        "limits": dict(envelope.limits),
        "coverage": {
            "files_seen": envelope.coverage.files_seen,
            "files_read": envelope.coverage.files_read,
            "bytes_read": envelope.coverage.bytes_read,
            "expanded_items_read": envelope.coverage.expanded_items_read,
            "expanded_bytes_read": envelope.coverage.expanded_bytes_read,
            "archives_attempted": envelope.coverage.archives_attempted,
            "archives_opened": envelope.coverage.archives_opened,
            "gap_count": envelope.coverage.gap_count,
            "gap_details_retained": envelope.coverage.gap_details_retained,
            "gap_details_omitted": envelope.coverage.gap_details_omitted,
            "excluded": list(envelope.coverage.excluded),
            "symlinks_followed": envelope.coverage.symlinks_followed,
            "symlink_targets_checked_directly": (
                envelope.coverage.symlink_targets_checked_directly
            ),
        },
        "report_sha256": envelope.report_sha256,
        "findings": [
            {
                "fingerprint": item.fingerprint,
                "path": item.path,
                "kind": item.kind,
                "patch_status": item.patch_status,
            }
            for item in envelope.findings
        ],
        "relation_fingerprints": list(envelope.relation_fingerprints),
        "gap_fingerprints": list(envelope.gap_fingerprints),
    }


def envelope_sha256(envelope: ReproducibilityEnvelope) -> str:
    return hashlib.sha256(canonical_json(envelope_json(envelope))).hexdigest()


def _decoded_tool(value: object, field: str, *, digest_required: bool) -> ToolIdentity:
    if not isinstance(value, dict) or set(value) != {"name", "version", "sha256"}:
        msg = f"Invalid envelope tool identity: {field}"
        raise ValueError(msg)
    name, version, digest = value["name"], value["version"], value["sha256"]
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        msg = f"Invalid envelope tool identity: {field}"
        raise ValueError(msg)
    if digest_required and digest is None:
        msg = f"Envelope tool digest is required: {field}"
        raise ValueError(msg)
    return ToolIdentity(name, version, _sha256(digest, field))


def _decoded_evidence(value: object, field: str) -> EvidenceIdentity:
    if not isinstance(value, dict) or set(value) != {"category", "name", "sha256"}:
        msg = f"Invalid envelope evidence identity: {field}"
        raise ValueError(msg)
    category, name = value["category"], value["name"]
    if not isinstance(category, str) or not category or not isinstance(name, str) or not name:
        msg = f"Invalid envelope evidence identity: {field}"
        raise ValueError(msg)
    digest = _required_sha256(value["sha256"], field)
    return EvidenceIdentity(category, name, digest)


def _decoded_hashes(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        msg = f"Invalid envelope hash population: {field}"
        raise ValueError(msg)  # noqa: TRY004 -- Stored envelope is a value boundary.
    hashes = []
    for index, item in enumerate(value):
        digest = _required_sha256(item, f"{field}[{index}]")
        hashes.append(digest)
    if len(hashes) != len(set(hashes)):
        msg = f"Duplicate envelope hash: {field}"
        raise ValueError(msg)
    return tuple(sorted(hashes))


def decode_envelope(  # noqa: C901, PLR0912, PLR0915 -- Strict stored schema reconstruction.
    value: object,
) -> ReproducibilityEnvelope:
    """Decode a stored envelope with the same invariants as freshly built evidence."""
    expected = {
        "schema_version",
        "report_schema_version",
        "roots",
        "scanner",
        "catalogs",
        "feeds",
        "optional_tools",
        "limits",
        "coverage",
        "report_sha256",
        "findings",
        "relation_fingerprints",
        "gap_fingerprints",
    }
    if not isinstance(value, dict) or set(value) != expected:
        msg = "Invalid evidence envelope fields"
        raise ValueError(msg)
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        msg = "Unsupported evidence envelope schema"
        raise ValueError(msg)
    if type(value["report_schema_version"]) is not int:
        msg = "Invalid envelope report schema"
        raise ValueError(msg)
    roots = value["roots"]
    if not isinstance(roots, list) or not all(isinstance(item, str) for item in roots):
        msg = "Invalid envelope roots"
        raise ValueError(msg)
    limits_value = value["limits"]
    if not isinstance(limits_value, dict):
        msg = "Invalid envelope limits"
        raise ValueError(msg)  # noqa: TRY004 -- Stored envelope is a value boundary.
    limits = []
    for key, limit in limits_value.items():
        if not isinstance(key, str) or (
            limit is not None and (type(limit) is not int or limit < 0)
        ):
            msg = "Invalid envelope limit"
            raise ValueError(msg)
        limits.append((key, limit))
    coverage_value = value["coverage"]
    coverage_fields = {
        "files_seen",
        "files_read",
        "bytes_read",
        "expanded_items_read",
        "expanded_bytes_read",
        "archives_attempted",
        "archives_opened",
        "gap_count",
        "gap_details_retained",
        "gap_details_omitted",
        "excluded",
        "symlinks_followed",
        "symlink_targets_checked_directly",
    }
    if not isinstance(coverage_value, dict) or set(coverage_value) != coverage_fields:
        msg = "Invalid envelope coverage fields"
        raise ValueError(msg)
    excluded = coverage_value["excluded"]
    followed = coverage_value["symlinks_followed"]
    if (
        not isinstance(excluded, list)
        or not all(isinstance(item, str) for item in excluded)
        or not isinstance(followed, bool)
    ):
        msg = "Invalid envelope coverage policy"
        raise ValueError(msg)
    coverage = CoverageSignature(
        *(
            _nonnegative(coverage_value[field], field)
            for field in (
                "files_seen",
                "files_read",
                "bytes_read",
                "expanded_items_read",
                "expanded_bytes_read",
                "archives_attempted",
                "archives_opened",
                "gap_count",
                "gap_details_retained",
                "gap_details_omitted",
            )
        ),
        tuple(sorted(set(excluded))),
        followed,
        _nonnegative(
            coverage_value["symlink_targets_checked_directly"],
            "symlink_targets_checked_directly",
        ),
    )
    if coverage.gap_count != coverage.gap_details_retained + coverage.gap_details_omitted:
        msg = "Envelope coverage gap counts are inconsistent"
        raise ValueError(msg)
    findings_value = value["findings"]
    if not isinstance(findings_value, list) or len(findings_value) > MAX_REPORT_ITEMS:
        msg = "Invalid envelope findings"
        raise ValueError(msg)
    findings = []
    for index, item in enumerate(findings_value):
        if not isinstance(item, dict) or set(item) != {
            "fingerprint",
            "path",
            "kind",
            "patch_status",
        }:
            msg = f"Invalid envelope finding: {index}"
            raise ValueError(msg)
        digest = _sha256(item["fingerprint"], f"findings[{index}]")
        if digest is None or not all(
            isinstance(item[field], str) for field in ("path", "kind", "patch_status")
        ):
            msg = f"Invalid envelope finding: {index}"
            raise ValueError(msg)
        findings.append(FindingSignature(digest, item["path"], item["kind"], item["patch_status"]))
    if len(findings) != len(set(findings)):
        msg = "Duplicate envelope finding"
        raise ValueError(msg)
    catalogs_value, feeds_value, tools_value = (
        value["catalogs"],
        value["feeds"],
        value["optional_tools"],
    )
    if not all(isinstance(items, list) for items in (catalogs_value, feeds_value, tools_value)):
        msg = "Invalid envelope evidence populations"
        raise ValueError(msg)
    envelope = ReproducibilityEnvelope(
        1,
        value["report_schema_version"],
        tuple(sorted(set(roots))),
        _decoded_tool(value["scanner"], "scanner", digest_required=True),
        _validate_evidence(
            tuple(
                _decoded_evidence(item, f"catalogs[{index}]")
                for index, item in enumerate(catalogs_value)
            )
        ),
        _validate_evidence(
            tuple(
                _decoded_evidence(item, f"feeds[{index}]") for index, item in enumerate(feeds_value)
            )
        ),
        _validate_tools(
            tuple(
                _decoded_tool(item, f"optional_tools[{index}]", digest_required=False)
                for index, item in enumerate(tools_value)
            )
        ),
        tuple(sorted(limits)),
        coverage,
        _required_sha256(value["report_sha256"], "report_sha256"),
        tuple(sorted(findings)),
        _decoded_hashes(value["relation_fingerprints"], "relation_fingerprints"),
        _decoded_hashes(value["gap_fingerprints"], "gap_fingerprints"),
    )
    if envelope_json(envelope) != value:
        msg = "Evidence envelope is not in canonical form"
        raise ValueError(msg)
    return envelope


def verify_report_envelope(
    report_with_envelope: dict[str, Any],
) -> tuple[dict[str, Any], ReproducibilityEnvelope]:
    """Strip self metadata and verify a stored baseline envelope against canonical report bytes."""
    if ENVELOPE_FIELD not in report_with_envelope:
        msg = "Baseline report lacks an evidence envelope"
        raise ValueError(msg)
    report = {
        key: value for key, value in report_with_envelope.items() if key not in SELF_METADATA_FIELDS
    }
    envelope = decode_envelope(report_with_envelope[ENVELOPE_FIELD])
    if hashlib.sha256(canonical_json(report)).hexdigest() != envelope.report_sha256:
        msg = "Baseline report digest does not match its evidence envelope"
        raise ValueError(msg)
    if report.get("schema_version") != envelope.report_schema_version:
        msg = "Baseline report schema does not match its evidence envelope"
        raise ValueError(msg)
    return report, envelope


def compare_envelopes(
    before: ReproducibilityEnvelope, after: ReproducibilityEnvelope
) -> ReportComparison:
    """Compare findings only when evidence scope and complete coverage are compatible."""
    reasons = []
    for label, left, right in (
        ("envelope schema", before.schema_version, after.schema_version),
        ("report schema", before.report_schema_version, after.report_schema_version),
        ("roots", before.roots, after.roots),
        ("scanner", before.scanner, after.scanner),
        ("catalogs", before.catalogs, after.catalogs),
        ("feeds", before.feeds, after.feeds),
        ("optional tools", before.optional_tools, after.optional_tools),
        ("limits", before.limits, after.limits),
        ("coverage shape", before.coverage.comparison_shape, after.coverage.comparison_shape),
    ):
        if left != right:
            reasons.append(f"Incompatible {label}")
    if not before.coverage.complete or not after.coverage.complete:
        reasons.append("Coverage gaps prevent comparison")
    if reasons:
        return ReportComparison(
            comparable=False, reasons=tuple(reasons), new=(), unchanged=(), absent=()
        )
    old = {item.fingerprint: item for item in before.findings}
    new = {item.fingerprint: item for item in after.findings}
    return ReportComparison(
        comparable=True,
        reasons=(),
        new=tuple(new[key] for key in sorted(new.keys() - old.keys())),
        unchanged=tuple(new[key] for key in sorted(new.keys() & old.keys())),
        absent=tuple(old[key] for key in sorted(old.keys() - new.keys())),
    )


def _sarif_level(status: str) -> str:
    if status in DEFAULT_AFFECTED_STATUSES:
        return "error"
    if status.startswith("fixed") or status in {"fixed_source", "upstream_fixed_version"}:
        return "note"
    return "warning"


def render_sarif(report: dict[str, Any], envelope: ReproducibilityEnvelope) -> dict[str, Any]:
    """Render deterministic SARIF 2.1.0 as a view of canonical report JSON."""
    if hashlib.sha256(canonical_json(report)).hexdigest() != envelope.report_sha256:
        msg = "SARIF input report does not match its reproducibility envelope"
        raise ValueError(msg)
    findings = report.get("findings", [])
    coverage = report.get("coverage", {})
    gaps = coverage.get("gaps", []) if isinstance(coverage, dict) else []
    rules = sorted(
        {str(item.get("kind", "unknown")) for item in findings if isinstance(item, dict)}
        | ({"coverage-gap"} if gaps else set())
    )
    signature_by_digest = {item.fingerprint: item for item in envelope.findings}
    results = []
    for item in findings:
        stable_digest = _digest(_stable(item))
        signature = signature_by_digest[stable_digest]
        result: dict[str, Any] = {
            "ruleId": signature.kind,
            "level": _sarif_level(signature.patch_status),
            "message": {"text": str(item.get("reason", "Scanner finding"))},
            "partialFingerprints": {"brotliChecker/v1": signature.fingerprint},
            "properties": {
                "patch_status": signature.patch_status,
                "evidence_fingerprint": signature.fingerprint,
            },
        }
        if signature.path:
            result["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": signature.path}}}
            ]
        results.append(result)
    for gap in gaps:
        if not isinstance(gap, dict):
            continue
        result = {
            "ruleId": "coverage-gap",
            "level": "warning",
            "message": {"text": str(gap.get("reason", "Coverage gap"))},
            "properties": {"coverage_gap": True},
        }
        if path := gap.get("path"):
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": path}}}]
        results.append(result)
    results.sort(
        key=lambda item: (
            item["ruleId"],
            item.get("locations", [{}])[0]
            .get("physicalLocation", {})
            .get("artifactLocation", {})
            .get("uri", ""),
            item["message"]["text"],
        )
    )
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": envelope.scanner.name,
                        "version": envelope.scanner.version,
                        "rules": [
                            {"id": rule, "shortDescription": {"text": rule}} for rule in rules
                        ],
                    }
                },
                "results": results,
                "properties": {
                    "report_sha256": envelope.report_sha256,
                    "envelope_sha256": envelope_sha256(envelope),
                    "envelope_schema_version": envelope.schema_version,
                },
            }
        ],
    }


def evaluate_fail_policy(
    report: dict[str, Any],
    *,
    policy: Literal["none", "affected", "coverage", "new_affected"] = "none",
    comparison: ReportComparison | None = None,
    affected_statuses: frozenset[str] = DEFAULT_AFFECTED_STATUSES,
) -> PolicyDecision:
    """Evaluate one explicit policy without changing scanner default exit semantics."""
    if policy == "none":
        return PolicyDecision(fail=False, reasons=())
    if policy == "coverage":
        coverage = report.get("coverage", {})
        count = coverage.get("gap_count") if isinstance(coverage, dict) else None
        if type(count) is not int:
            return PolicyDecision(fail=True, reasons=("Coverage status is unavailable",))
        return PolicyDecision(
            fail=bool(count), reasons=("Coverage gaps are present",) if count else ()
        )
    if policy == "affected":
        findings = report.get("findings", [])
        statuses = {item.get("patch_status") for item in findings if isinstance(item, dict)}
        affected = sorted(statuses & affected_statuses)
        return PolicyDecision(
            fail=bool(affected),
            reasons=tuple(f"Affected status present: {status}" for status in affected),
        )
    if comparison is None or not comparison.comparable:
        return PolicyDecision(
            fail=True, reasons=("New-affected policy requires comparable reports",)
        )
    affected = sorted(
        item.fingerprint for item in comparison.new if item.patch_status in affected_statuses
    )
    return PolicyDecision(
        fail=bool(affected),
        reasons=tuple(f"New affected finding: {value}" for value in affected),
    )
