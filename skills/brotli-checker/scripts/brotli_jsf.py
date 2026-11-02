# ruff: noqa: C901, EM101, EM102, PLR2004, TRY003, TRY004
"""Offline CycloneDX JSF verification with external Ed25519 trust."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from brotli_attestations import parse_evidence_document

MAX_KEYS = 32
MAX_COMPONENTS = 100_000
MAX_FRESHNESS_SECONDS = 10 * 365 * 24 * 60 * 60
SHA256_HEX = re.compile(r"[0-9A-Fa-f]{64}")
RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})")


@dataclass(frozen=True)
class JsfPolicy:
    keys: tuple[bytes, ...]
    evaluation_time: datetime
    trust_expires_at: datetime
    max_document_age_seconds: int
    max_future_skew_seconds: int
    semantic_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not 1 <= len(self.keys) <= MAX_KEYS or len(set(self.keys)) != len(self.keys):
            raise ValueError("Invalid JSF trusted key population")
        if any(not isinstance(key, bytes) or len(key) != 32 for key in self.keys):
            raise ValueError("JSF trusted keys must be unique Ed25519 public keys")
        if self.evaluation_time.tzinfo is None or self.trust_expires_at.tzinfo is None:
            raise ValueError("JSF policy times must be timezone-aware")
        if self.trust_expires_at < self.evaluation_time:
            raise ValueError("JSF trust policy is stale")
        if type(self.max_document_age_seconds) is not int or not (
            0 <= self.max_document_age_seconds <= MAX_FRESHNESS_SECONDS
        ):
            raise ValueError("Invalid JSF maximum document age")
        if type(self.max_future_skew_seconds) is not int or not (
            0 <= self.max_future_skew_seconds <= 24 * 60 * 60
        ):
            raise ValueError("Invalid JSF future skew")
        canonical = "\0".join(
            (
                *(base64.b64encode(key).decode("ascii") for key in sorted(self.keys)),
                self.evaluation_time.isoformat(),
                self.trust_expires_at.isoformat(),
                str(self.max_document_age_seconds),
                str(self.max_future_skew_seconds),
            )
        ).encode()
        object.__setattr__(self, "semantic_sha256", hashlib.sha256(canonical).hexdigest())


def _time(value: object, name: str) -> datetime:
    if not isinstance(value, str) or RFC3339.fullmatch(value) is None:
        raise ValueError(f"JSF {name} must be an RFC3339 timestamp")
    parsed = datetime.fromisoformat(value)
    return parsed.astimezone(UTC)


def _base64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Expected base64 public key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("Invalid base64 public key") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("Noncanonical base64 public key")
    return decoded


def _base64url(value: object) -> bytes:
    if not isinstance(value, str) or "=" in value or re.fullmatch(r"[A-Za-z0-9_-]*", value) is None:
        raise ValueError("Invalid JSF base64url value")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise ValueError("Invalid JSF base64url value") from error
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValueError("Noncanonical JSF base64url value")
    return decoded


def load_jsf_policy(raw: bytes) -> JsfPolicy:
    value = parse_evidence_document(raw)
    if (
        set(value)
        != {
            "schema_version",
            "public_keys",
            "evaluation_time",
            "trust_expires_at",
            "max_document_age_seconds",
            "max_future_skew_seconds",
        }
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("Invalid JSF policy schema")
    keys = value["public_keys"]
    if not isinstance(keys, list):
        raise ValueError("Invalid JSF trusted key population")
    return JsfPolicy(
        keys=tuple(_base64(key) for key in keys),
        evaluation_time=_time(value["evaluation_time"], "evaluation_time"),
        trust_expires_at=_time(value["trust_expires_at"], "trust_expires_at"),
        max_document_age_seconds=value["max_document_age_seconds"],
        max_future_skew_seconds=value["max_future_skew_seconds"],
    )


def _document_time(document: dict, policy: JsfPolicy) -> dict:
    metadata = document.get("metadata")
    timestamp = metadata.get("timestamp") if isinstance(metadata, dict) else None
    signed_time = _time(timestamp, "signed metadata.timestamp")
    age = int((policy.evaluation_time - signed_time).total_seconds())
    if age < -policy.max_future_skew_seconds:
        raise ValueError("JSF document time is after the allowed future skew")
    if age > policy.max_document_age_seconds:
        raise ValueError("JSF document exceeds the allowed age")
    return {
        "document_time": signed_time.isoformat(),
        "evaluation_time": policy.evaluation_time.isoformat(),
        "trust_expires_at": policy.trust_expires_at.isoformat(),
        "max_document_age_seconds": policy.max_document_age_seconds,
        "max_future_skew_seconds": policy.max_future_skew_seconds,
        "status": "verified_within_local_policy_window",
    }


def _trusted_candidates(signature: dict, policy: JsfPolicy) -> tuple[bytes, ...]:
    public_key = signature.get("publicKey")
    if public_key is None:
        return policy.keys
    if not isinstance(public_key, dict) or set(public_key) != {"kty", "crv", "x"}:
        raise ValueError("Unsupported JSF public key")
    if public_key["kty"] != "OKP" or public_key["crv"] != "Ed25519":
        raise ValueError("Unsupported JSF public key")
    key = _base64url(public_key["x"])
    if key not in policy.keys:
        raise ValueError("JSF embedded public key is not explicitly trusted")
    return (key,)


def _component_hashes(document: dict) -> list[str]:
    pending = []
    components = document.get("components", [])
    if isinstance(components, list):
        pending.extend(components)
    metadata = document.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
        pending.append(metadata["component"])
    hashes, visited = set(), 0
    while pending:
        component = pending.pop()
        visited += 1
        if visited > MAX_COMPONENTS:
            raise ValueError("CycloneDX component population exceeds limit")
        if not isinstance(component, dict):
            raise ValueError("Invalid CycloneDX component")
        children = component.get("components", [])
        if not isinstance(children, list):
            raise ValueError("Invalid nested CycloneDX components")
        pending.extend(children)
        values = component.get("hashes", [])
        if not isinstance(values, list):
            raise ValueError("Invalid CycloneDX component hashes")
        for item in values:
            if not isinstance(item, dict) or set(item) != {"alg", "content"}:
                raise ValueError("Invalid CycloneDX component hash")
            digest = item["content"]
            if item["alg"] == "SHA-256":
                if not isinstance(digest, str) or SHA256_HEX.fullmatch(digest) is None:
                    raise ValueError("Invalid CycloneDX SHA-256 component hash")
                hashes.add(digest.lower())
    return sorted(hashes)


def verify_jsf_document(raw: bytes, policy_raw: bytes) -> dict:
    """Verify one single-signature CycloneDX JSF document and its freshness."""
    import rfc8785  # noqa: PLC0415 -- Optional backend.
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PublicKey,
    )

    document = parse_evidence_document(raw)
    policy = load_jsf_policy(policy_raw)
    signature = document.get("signature")
    allowed = {"algorithm", "value", "keyId", "publicKey"}
    if (
        not isinstance(signature, dict)
        or set(signature) - allowed
        or not {
            "algorithm",
            "value",
        }
        <= set(signature)
    ):
        raise ValueError("Unsupported JSF signature object")
    if signature["algorithm"] != "Ed25519":
        raise ValueError("Unsupported JSF signature algorithm")
    if "keyId" in signature and not isinstance(signature["keyId"], str):
        raise ValueError("Invalid JSF keyId hint")
    signature_bytes = _base64url(signature["value"])
    if len(signature_bytes) != 64:
        raise ValueError("Invalid Ed25519 signature length")
    unsigned = copy.deepcopy(document)
    del unsigned["signature"]["value"]
    try:
        canonical = rfc8785.dumps(unsigned)
    except rfc8785.CanonicalizationError as error:
        raise ValueError("JSF document is not valid RFC8785 input") from error

    verified = []
    for key in _trusted_candidates(signature, policy):
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(signature_bytes, canonical)
        except InvalidSignature:
            continue
        verified.append(hashlib.sha256(key).hexdigest())
    if not verified:
        raise ValueError("JSF signature was not made by an explicitly trusted key")
    return {
        "signature_status": "verified",
        "evidence_strength": "verified_cyclonedx_jsf",
        "document_sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_payload_sha256": hashlib.sha256(canonical).hexdigest(),
        "policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
        "trust_policy_fingerprint": policy.semantic_sha256,
        "verified_keys": sorted(verified),
        "subject_sha256": _component_hashes(document),
        "predicate_status": "authenticated_bom_claim_not_independently_verified",
        "freshness": _document_time(document, policy),
        "patch_status": "unknown",
    }
