"""Offline DSSE verification with explicit local keys; claims never become patch proof."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import stat
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

ED25519_PUBLIC_BYTES = 32
ED25519_SIGNATURE_BYTES = 64
SHA256_HEX_CHARS = 64
MAX_TYPE_CHARS = 1024
MAX_JSON_NODES = 100000
MAX_JSON_DEPTH = 64

MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_KEYS = 32
MAX_SIGNATURES = 32
MAX_SUBJECTS = 10000
MAX_ATTESTATIONS = 64
MAX_KEYID_CHARS = 1024
READ_CHUNK_BYTES = 1024 * 1024
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


@dataclass(frozen=True)
class TrustPolicy:
    keys: tuple[bytes, ...]
    threshold: int
    predicate_types: tuple[str, ...]
    semantic_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _validate_policy(self.keys, self.threshold, self.predicate_types)
        canonical = json.dumps(
            {
                "keys": sorted(base64.b64encode(key).decode("ascii") for key in self.keys),
                "predicate_types": sorted(self.predicate_types),
                "threshold": self.threshold,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        object.__setattr__(self, "semantic_sha256", hashlib.sha256(canonical).hexdigest())


@dataclass(frozen=True)
class CapturedDocument:
    label: str
    raw: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.label, str) or not self.label:
            message = "Captured attestation label must be nonempty"
            raise ValueError(message)
        if not isinstance(self.raw, bytes) or len(self.raw) > MAX_DOCUMENT_BYTES:
            message = "Captured attestation bytes are invalid or over limit"
            raise ValueError(message)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()


@dataclass(frozen=True)
class AttestationInputs:
    policy: CapturedDocument | None
    bundles: tuple[CapturedDocument, ...]

    def __post_init__(self) -> None:
        if self.policy is not None and not isinstance(self.policy, CapturedDocument):
            message = "Invalid captured attestation trust policy"
            raise ValueError(message)
        if not isinstance(self.bundles, tuple) or len(self.bundles) > MAX_ATTESTATIONS:
            message = "Invalid captured attestation population"
            raise ValueError(message)
        if any(not isinstance(item, CapturedDocument) for item in self.bundles):
            message = "Invalid captured attestation document"
            raise ValueError(message)
        labels = [item.label for item in self.bundles]
        if len(labels) != len(set(labels)):
            message = "Duplicate captured attestation label"
            raise ValueError(message)


def _object_pairs(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            message = "Duplicate JSON key"
            raise ValueError(message)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    message = f"Nonfinite JSON constant: {value}"
    raise ValueError(message)


def _check_json_budget(value: object) -> None:
    pending = [(value, 0)]
    seen = 0
    while pending:
        item, depth = pending.pop()
        seen += 1
        if seen > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            message = "Attestation JSON structure budget exceeded"
            raise ValueError(message)
        if isinstance(item, float) and not math.isfinite(item):
            message = "Nonfinite attestation JSON number"
            raise ValueError(message)
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)


def _document(raw: bytes) -> dict:
    if len(raw) > MAX_DOCUMENT_BYTES:
        message = "Attestation document exceeds byte limit"
        raise ValueError(message)
    try:
        value = json.loads(raw, object_pairs_hook=_object_pairs, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        message = "Invalid attestation JSON"
        raise ValueError(message) from error
    if not isinstance(value, dict):
        message = "Attestation document must be an object"
        raise ValueError(message)  # noqa: TRY004 -- Malformed serialized value.
    _check_json_budget(value)
    return value


def _stat_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def capture_document(path: Path) -> CapturedDocument:
    """Capture one bounded stable local document for later parsing and identity binding."""
    path = path.expanduser().absolute()
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        message = f"Attestation input is not a regular non-symlink file: {path}"
        raise ValueError(message)
    if metadata.st_size > MAX_DOCUMENT_BYTES:
        message = f"Attestation input exceeds byte limit: {path}"
        raise ValueError(message)
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        before = os.fstat(descriptor)
        if _stat_signature(metadata) != _stat_signature(before):
            message = f"Attestation input changed while opening: {path}"
            raise ValueError(message)
        chunks = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(
                descriptor,
                min(READ_CHUNK_BYTES, before.st_size - offset),
                offset,
            )
            if not chunk:
                message = f"Attestation input changed while reading: {path}"
                raise ValueError(message)
            chunks.append(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
        if _stat_signature(before) != _stat_signature(after):
            message = f"Attestation input changed while reading: {path}"
            raise ValueError(message)
        return CapturedDocument(str(path), b"".join(chunks))
    finally:
        os.close(descriptor)


def capture_attestation_inputs(
    paths: Sequence[Path], policy_path: Path | None
) -> AttestationInputs:
    if len(paths) > MAX_ATTESTATIONS:
        message = "Supplied attestation count exceeds limit"
        raise ValueError(message)
    policy = capture_document(policy_path) if policy_path is not None else None
    return AttestationInputs(policy, tuple(capture_document(path) for path in paths))


def _base64(value: object) -> bytes:
    if not isinstance(value, str):
        message = "Expected base64 string"
        raise ValueError(message)  # noqa: TRY004 -- Malformed serialized value.
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        message = "Invalid base64 encoding"
        raise ValueError(message) from error
    if base64.b64encode(decoded).decode("ascii") != value:
        message = "Noncanonical base64 encoding"
        raise ValueError(message)
    return decoded


def load_trust_policy(raw: bytes) -> TrustPolicy:
    value = _document(raw)
    if set(value) != {"schema_version", "public_keys", "threshold", "predicate_types"}:
        message = "Invalid attestation trust policy fields"
        raise ValueError(message)
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        message = "Unsupported attestation trust policy schema"
        raise ValueError(message)
    keys = value["public_keys"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_KEYS:
        message = "Invalid trust key population"
        raise ValueError(message)
    decoded = tuple(_base64(key) for key in keys)
    predicates = value["predicate_types"]
    if not isinstance(predicates, list):
        message = "Invalid allowed predicate population"
        raise ValueError(message)  # noqa: TRY004 -- Malformed serialized value.
    threshold = value["threshold"]
    return TrustPolicy(decoded, threshold, tuple(predicates))


def _validate_policy(
    decoded: tuple[bytes, ...], threshold: int, predicates: tuple[str, ...]
) -> None:
    if not isinstance(decoded, tuple) or not 1 <= len(decoded) <= MAX_KEYS:
        message = "Invalid trust key population"
        raise ValueError(message)
    if any(
        not isinstance(key, bytes) or len(key) != ED25519_PUBLIC_BYTES for key in decoded
    ) or len(set(decoded)) != len(decoded):
        message = "Ed25519 keys must be unique 32-byte public keys"
        raise ValueError(message)
    if type(threshold) is not int or not 1 <= threshold <= len(decoded):
        message = "Invalid distinct-key signature threshold"
        raise ValueError(message)
    if not isinstance(predicates, tuple) or not 1 <= len(predicates) <= MAX_KEYS:
        message = "Invalid allowed predicate population"
        raise ValueError(message)
    if any(
        not isinstance(item, str) or not item or len(item) > MAX_TYPE_CHARS for item in predicates
    ):
        message = "Invalid allowed predicate type"
        raise ValueError(message)
    if len(set(predicates)) != len(predicates):
        message = "Duplicate allowed predicate type"
        raise ValueError(message)


def pae(payload_type: str, payload: bytes) -> bytes:
    encoded_type = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(encoded_type)).encode("ascii")
        + b" "
        + encoded_type
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _verified_payload(raw: bytes, policy: TrustPolicy) -> tuple[bytes, set[str]]:  # noqa: C901 -- Ordered authentication boundary.
    # Optional dependency: normal scans without supplied attestations do not import crypto.
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm  # noqa: PLC0415 -- Optional backend.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: PLC0415

    envelope = _document(raw)
    if (
        set(envelope) != {"payloadType", "payload", "signatures"}
        or envelope["payloadType"] != PAYLOAD_TYPE
    ):
        message = "Unsupported DSSE envelope or payload type"
        raise ValueError(message)
    payload = _base64(envelope["payload"])
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or not 1 <= len(signatures) <= MAX_SIGNATURES:
        message = "Invalid DSSE signature population"
        raise ValueError(message)
    signed_message = pae(PAYLOAD_TYPE, payload)
    verified = set()
    for signature in signatures:
        if (
            not isinstance(signature, dict)
            or set(signature) - {"sig", "keyid"}
            or "sig" not in signature
        ):
            message = "Invalid DSSE signature object"
            raise ValueError(message)
        if "keyid" in signature and not isinstance(signature["keyid"], str):
            message = "Invalid DSSE keyid hint"
            raise ValueError(message)
        if len(signature.get("keyid", "")) > MAX_KEYID_CHARS:
            message = "DSSE keyid hint exceeds limit"
            raise ValueError(message)
        value = _base64(signature["sig"])
        if len(value) != ED25519_SIGNATURE_BYTES:
            message = "Invalid Ed25519 signature length"
            raise ValueError(message)
        for key in policy.keys:
            try:
                Ed25519PublicKey.from_public_bytes(key).verify(value, signed_message)
            except InvalidSignature:
                continue
            except UnsupportedAlgorithm as error:
                message = "Ed25519 backend unavailable"
                raise ValueError(message) from error
            verified.add(hashlib.sha256(key).hexdigest())
    if len(verified) < policy.threshold:
        message = "Trusted distinct-key signature threshold not met"
        raise ValueError(message)
    return payload, verified


def _statement_subjects(payload: bytes, policy: TrustPolicy) -> tuple[dict, set[str]]:
    statement = _document(payload)
    if (
        set(statement) != {"_type", "subject", "predicateType", "predicate"}
        or statement["_type"] != STATEMENT_TYPE
    ):
        message = "Unsupported in-toto statement"
        raise ValueError(message)
    if statement["predicateType"] not in policy.predicate_types or not isinstance(
        statement["predicate"], dict
    ):
        message = "Statement predicate is not allowed by local policy"
        raise ValueError(message)
    subjects = statement["subject"]
    if not isinstance(subjects, list) or not 1 <= len(subjects) <= MAX_SUBJECTS:
        message = "Invalid statement subject population"
        raise ValueError(message)
    hashes = set()
    for subject in subjects:
        if (
            not isinstance(subject, dict)
            or set(subject) - {"name", "digest"}
            or not isinstance(subject.get("name", ""), str)
        ):
            message = "Invalid statement subject"
            raise ValueError(message)
        digest = subject.get("digest")
        if not isinstance(digest, dict):
            message = "Subject digest must be an object"
            raise ValueError(message)  # noqa: TRY004 -- Malformed serialized value.
        sha = digest.get("sha256")
        if (
            not isinstance(sha, str)
            or len(sha) != SHA256_HEX_CHARS
            or any(char not in "0123456789abcdef" for char in sha)
        ):
            message = "Subject requires exact lowercase SHA-256"
            raise ValueError(message)
        hashes.add(sha)
    return statement, hashes


def verify_attestation(raw: bytes, policy: TrustPolicy) -> dict:
    payload, verified = _verified_payload(raw, policy)
    statement, hashes = _statement_subjects(payload, policy)
    return {
        "signature_status": "verified",
        "evidence_strength": "verified_attestation",
        "attestation_sha256": hashlib.sha256(raw).hexdigest(),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "trust_policy_fingerprint": policy.semantic_sha256,
        "verified_keys": sorted(verified),
        "subject_sha256": sorted(hashes),
        "predicate_type": statement["predicateType"],
        "predicate_status": "authenticated_claim_not_independently_verified",
        "patch_status": "unknown",
    }


def inspect_captured_attestations(
    inputs: AttestationInputs, artifacts: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Join authenticated subjects only to exact scanned digests, never names."""
    if not inputs.bundles:
        return [], []
    if inputs.policy is None:
        message = "Supplied attestations require an explicit local trust policy"
        raise ValueError(message)
    policy = load_trust_policy(inputs.policy.raw)
    records, gaps = [], []
    by_hash: dict[str, list[str]] = {}
    for artifact in artifacts:
        by_hash.setdefault(artifact["sha256"], []).append(artifact["id"])
    for bundle in inputs.bundles:
        try:
            result = verify_attestation(bundle.raw, policy)
        except (ValueError, ImportError, OSError) as error:
            gaps.append({"path": bundle.label, "reason": f"Attestation unverified: {error}"})
            continue
        result["path"] = bundle.label
        result["attestation_input_sha256"] = bundle.sha256
        result["trust_policy_input_sha256"] = inputs.policy.sha256
        result["bound_artifacts"] = sorted(
            {
                identifier
                for digest in result["subject_sha256"]
                for identifier in by_hash.get(digest, [])
            }
        )
        result["subject_binding"] = (
            "exact_scanned_sha256" if result["bound_artifacts"] else "no_scanned_subject"
        )
        records.append(result)
    return records, gaps
