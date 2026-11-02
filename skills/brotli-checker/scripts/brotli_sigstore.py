# ruff: noqa: EM101, EM102, TRY003
"""Offline Sigstore verification bound to captured trust and policy bytes."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from brotli_attestations import parse_evidence_document
from brotli_binary_triage import run_bounded

if TYPE_CHECKING:
    from collections.abc import Sequence

SHA256_HEX = re.compile(r"[0-9a-f]{64}")
RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
MAX_FRESHNESS_SECONDS = 10 * 365 * 24 * 60 * 60
MAX_TOOL_OUTPUT_BYTES = 1024 * 1024
TOOL_TIMEOUT_SECONDS = 30
EXPECTED_SIGSTORE_VERSION = "sigstore 4.2.0"


@dataclass(frozen=True)
class SigstorePolicy:
    certificate_identity: str
    certificate_oidc_issuer: str
    evaluation_time: datetime
    trust_config_expires_at: datetime
    max_signature_age_seconds: int
    max_future_skew_seconds: int
    semantic_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.certificate_identity, str)
            or not self.certificate_identity
            or not isinstance(self.certificate_oidc_issuer, str)
            or not self.certificate_oidc_issuer
        ):
            raise ValueError("Sigstore identity and issuer must be explicit")
        if self.evaluation_time.tzinfo is None or self.trust_config_expires_at.tzinfo is None:
            raise ValueError("Sigstore policy times must be timezone-aware")
        if self.trust_config_expires_at < self.evaluation_time:
            raise ValueError("Captured Sigstore trust configuration is stale")
        if type(self.max_signature_age_seconds) is not int or not (
            0 <= self.max_signature_age_seconds <= MAX_FRESHNESS_SECONDS
        ):
            raise ValueError("Invalid Sigstore maximum signature age")
        if type(self.max_future_skew_seconds) is not int or not (
            0 <= self.max_future_skew_seconds <= 24 * 60 * 60
        ):
            raise ValueError("Invalid Sigstore future skew")
        canonical = "\0".join(
            (
                self.certificate_identity,
                self.certificate_oidc_issuer,
                self.evaluation_time.isoformat(),
                self.trust_config_expires_at.isoformat(),
                str(self.max_signature_age_seconds),
                str(self.max_future_skew_seconds),
            )
        ).encode()
        object.__setattr__(self, "semantic_sha256", hashlib.sha256(canonical).hexdigest())


def _utc_time(value: object, name: str) -> datetime:
    if not isinstance(value, str) or RFC3339_UTC.fullmatch(value) is None:
        raise ValueError(f"Sigstore {name} must be an RFC3339 UTC second")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def load_sigstore_policy(raw: bytes) -> SigstorePolicy:
    value = parse_evidence_document(raw)
    expected = {
        "schema_version",
        "certificate_identity",
        "certificate_oidc_issuer",
        "evaluation_time",
        "trust_config_expires_at",
        "max_signature_age_seconds",
        "max_future_skew_seconds",
    }
    if (
        set(value) != expected
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("Invalid Sigstore policy schema")
    return SigstorePolicy(
        certificate_identity=value["certificate_identity"],
        certificate_oidc_issuer=value["certificate_oidc_issuer"],
        evaluation_time=_utc_time(value["evaluation_time"], "evaluation_time"),
        trust_config_expires_at=_utc_time(
            value["trust_config_expires_at"], "trust_config_expires_at"
        ),
        max_signature_age_seconds=value["max_signature_age_seconds"],
        max_future_skew_seconds=value["max_future_skew_seconds"],
    )


def _integrated_times(bundle: dict) -> tuple[int, ...]:
    material = bundle.get("verificationMaterial")
    entries = material.get("tlogEntries") if isinstance(material, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError("Sigstore freshness requires a transparency-log integrated time")
    result = []
    for entry in entries:
        value = entry.get("integratedTime") if isinstance(entry, dict) else None
        if isinstance(value, str) and value.isascii() and value.isdigit():
            value = int(value)
        if type(value) is not int or value < 0:
            raise ValueError("Invalid Sigstore transparency-log integrated time")
        result.append(value)
    return tuple(result)


def _check_freshness(times: Sequence[int], policy: SigstorePolicy) -> dict:
    evaluated = int(policy.evaluation_time.timestamp())
    for integrated in times:
        age = evaluated - integrated
        if age < -policy.max_future_skew_seconds:
            raise ValueError("Sigstore signing time is after the allowed future skew")
        if age > policy.max_signature_age_seconds:
            raise ValueError("Sigstore signature exceeds the allowed age")
    return {
        "evaluation_time": policy.evaluation_time.isoformat(),
        "trust_config_expires_at": policy.trust_config_expires_at.isoformat(),
        "integrated_times": sorted(times),
        "max_signature_age_seconds": policy.max_signature_age_seconds,
        "max_future_skew_seconds": policy.max_future_skew_seconds,
        "status": "verified_within_local_policy_window",
    }


def _trusted_executable(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("Sigstore verifier path must be absolute")
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise ValueError("Sigstore verifier must be an executable regular file")
    return resolved


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sigstore_bundle(
    bundle_raw: bytes,
    trust_config_raw: bytes,
    policy_raw: bytes,
    *,
    artifact_sha256: str,
    verifier_path: Path,
) -> dict:
    """Verify a captured bundle without consulting TUF, Rekor, or any URL."""
    policy = load_sigstore_policy(policy_raw)
    bundle_document = parse_evidence_document(bundle_raw)
    freshness = _check_freshness(_integrated_times(bundle_document), policy)
    if not isinstance(artifact_sha256, str) or SHA256_HEX.fullmatch(artifact_sha256) is None:
        raise ValueError("Sigstore verification requires an exact SHA-256")
    verifier = _trusted_executable(verifier_path)
    verifier_sha256 = _file_sha256(verifier)
    version = run_bounded([str(verifier), "--version"], TOOL_TIMEOUT_SECONDS, MAX_TOOL_OUTPUT_BYTES)
    if version["limited"] or version["returncode"] != 0:
        raise ValueError("Cannot identify the isolated Sigstore verifier")
    if version["output"].strip() != EXPECTED_SIGSTORE_VERSION:
        raise ValueError(
            f"Unqualified Sigstore verifier version: {version['output'].strip() or 'empty'}"
        )
    with tempfile.TemporaryDirectory(prefix="brotli-sigstore-") as temporary:
        directory = Path(temporary)
        bundle_path, trust_path = directory / "bundle.json", directory / "trust.json"
        bundle_path.write_bytes(bundle_raw)
        trust_path.write_bytes(trust_config_raw)
        command = [
            str(verifier),
            "--trust-config",
            str(trust_path),
            "verify",
            "identity",
            "--bundle",
            str(bundle_path),
            "--offline",
            "--cert-identity",
            policy.certificate_identity,
            "--cert-oidc-issuer",
            policy.certificate_oidc_issuer,
            f"sha256:{artifact_sha256}",
        ]
        completed = run_bounded(command, TOOL_TIMEOUT_SECONDS, MAX_TOOL_OUTPUT_BYTES)
    if completed["limited"]:
        raise ValueError(f"Offline Sigstore verifier incomplete: {completed['reason']}")
    if completed["returncode"] != 0:
        detail = completed["output"].strip()
        raise ValueError(
            f"Offline Sigstore verification failed ({completed['returncode']}): {detail}"
        )
    if _file_sha256(verifier) != verifier_sha256:
        raise ValueError("Sigstore verifier changed during verification")

    return {
        "signature_status": "verified",
        "evidence_strength": "verified_sigstore_bundle",
        "mode": "artifact_digest",
        "bundle_sha256": hashlib.sha256(bundle_raw).hexdigest(),
        "trust_config_sha256": hashlib.sha256(trust_config_raw).hexdigest(),
        "policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
        "trust_policy_fingerprint": policy.semantic_sha256,
        "certificate_identity": policy.certificate_identity,
        "certificate_oidc_issuer": policy.certificate_oidc_issuer,
        "subject_sha256": [artifact_sha256],
        "verifier_path": str(verifier),
        "verifier_sha256": verifier_sha256,
        "verifier_version": EXPECTED_SIGSTORE_VERSION,
        "verifier_version_output_sha256": hashlib.sha256(version["output"].encode()).hexdigest(),
        "verifier_output_sha256": hashlib.sha256(completed["output"].encode()).hexdigest(),
        "predicate_status": "authenticated_claim_not_independently_verified",
        "freshness": freshness,
        "patch_status": "unknown",
    }
