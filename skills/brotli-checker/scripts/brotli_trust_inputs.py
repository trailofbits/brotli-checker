# ruff: noqa: C901, EM101, EM102, PLR0913, TRY003, TRY004, TRY301
"""Immutable capture and artifact binding for optional trust evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from brotli_attestations import (
    MAX_ATTESTATIONS,
    PAYLOAD_TYPE,
    CapturedDocument,
    capture_document,
    parse_evidence_document,
    parse_statement_subjects,
)
from brotli_jsf import verify_jsf_document
from brotli_sigstore import verify_sigstore_bundle

if TYPE_CHECKING:
    import argparse
    from collections.abc import Sequence
    from pathlib import Path


@dataclass(frozen=True)
class TrustInputs:
    sigstore_bundles: tuple[CapturedDocument, ...]
    sigstore_trust_config: CapturedDocument | None
    sigstore_policy: CapturedDocument | None
    sigstore_verifier: Path | None
    jsf_documents: tuple[CapturedDocument, ...]
    jsf_policy: CapturedDocument | None

    def identity_documents(self) -> tuple[tuple[str, str, bytes], ...]:
        values = [
            *(("sigstore_bundle", item.label, item.raw) for item in self.sigstore_bundles),
            *(("jsf_document", item.label, item.raw) for item in self.jsf_documents),
        ]
        if self.sigstore_trust_config is not None:
            item = self.sigstore_trust_config
            values.append(("sigstore_trust_config", item.label, item.raw))
        if self.sigstore_policy is not None:
            item = self.sigstore_policy
            values.append(("sigstore_policy", item.label, item.raw))
        if self.jsf_policy is not None:
            item = self.jsf_policy
            values.append(("jsf_policy", item.label, item.raw))
        return tuple(values)


def _capture_many(paths: Sequence[Path], name: str) -> tuple[CapturedDocument, ...]:
    if len(paths) > MAX_ATTESTATIONS:
        raise ValueError(f"Supplied {name} count exceeds limit")
    documents = tuple(capture_document(path) for path in paths)
    labels = [item.label for item in documents]
    if len(labels) != len(set(labels)):
        raise ValueError(f"Duplicate supplied {name} path")
    return documents


def capture_trust_inputs(
    *,
    sigstore_bundles: Sequence[Path] = (),
    sigstore_trust_config: Path | None = None,
    sigstore_policy: Path | None = None,
    sigstore_verifier: Path | None = None,
    jsf_documents: Sequence[Path] = (),
    jsf_policy: Path | None = None,
) -> TrustInputs:
    bundles = _capture_many(sigstore_bundles, "Sigstore bundle")
    jsf = _capture_many(jsf_documents, "JSF document")
    if bundles and None in (sigstore_trust_config, sigstore_policy, sigstore_verifier):
        raise ValueError("Sigstore bundles require trust config, policy, and an isolated verifier")
    if not bundles and any(
        item is not None for item in (sigstore_trust_config, sigstore_policy, sigstore_verifier)
    ):
        raise ValueError("Sigstore trust inputs require at least one bundle")
    if jsf and jsf_policy is None:
        raise ValueError("JSF documents require an explicit JSF policy")
    if not jsf and jsf_policy is not None:
        raise ValueError("A JSF policy requires at least one JSF document")
    if sigstore_verifier is not None and not sigstore_verifier.expanduser().is_absolute():
        raise ValueError("Sigstore verifier path must be absolute")
    return TrustInputs(
        sigstore_bundles=bundles,
        sigstore_trust_config=(
            capture_document(sigstore_trust_config) if sigstore_trust_config is not None else None
        ),
        sigstore_policy=(
            capture_document(sigstore_policy) if sigstore_policy is not None else None
        ),
        sigstore_verifier=(
            sigstore_verifier.expanduser().resolve(strict=False)
            if sigstore_verifier is not None
            else None
        ),
        jsf_documents=jsf,
        jsf_policy=capture_document(jsf_policy) if jsf_policy is not None else None,
    )


def capture_trust_arguments(args: argparse.Namespace) -> TrustInputs:
    """Capture the trust-related CLI arguments once for every scanner entry point."""
    return capture_trust_inputs(
        sigstore_bundles=getattr(args, "sigstore_bundle", ()),
        sigstore_trust_config=getattr(args, "sigstore_trust_config", None),
        sigstore_policy=getattr(args, "sigstore_policy", None),
        sigstore_verifier=getattr(args, "sigstore_verifier", None),
        jsf_documents=getattr(args, "jsf", ()),
        jsf_policy=getattr(args, "jsf_policy", None),
    )


def _sha256_digest(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Sigstore bundle digest is not base64")
    try:
        digest = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("Sigstore bundle digest is invalid base64") from error
    if len(digest) != hashlib.sha256().digest_size:
        raise ValueError("Sigstore bundle digest is not SHA-256")
    return digest.hex()


def sigstore_claimed_subjects(raw: bytes) -> tuple[str, ...]:
    """Extract untrusted candidate digests only to select exact artifacts for verification."""
    document = parse_evidence_document(raw)
    message = document.get("messageSignature")
    if isinstance(message, dict):
        digest = message.get("messageDigest")
        if not isinstance(digest, dict) or digest.get("algorithm") != "SHA2_256":
            raise ValueError("Sigstore message bundle requires a SHA2_256 digest")
        return (_sha256_digest(digest.get("digest")),)
    envelope = document.get("dsseEnvelope")
    if not isinstance(envelope, dict) or envelope.get("payloadType") != PAYLOAD_TYPE:
        raise ValueError("Unsupported Sigstore bundle content")
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise ValueError("Invalid Sigstore DSSE payload")
    try:
        decoded = base64.b64decode(payload, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("Invalid Sigstore DSSE payload") from error
    statement = parse_evidence_document(decoded)
    predicate = statement.get("predicateType")
    if not isinstance(predicate, str):
        raise ValueError("Invalid Sigstore DSSE statement")
    _, hashes = parse_statement_subjects(decoded, (predicate,))
    return tuple(sorted(hashes))


def _artifact_index(artifacts: list[dict]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for artifact in artifacts:
        digest, identifier = artifact.get("sha256"), artifact.get("id")
        if isinstance(digest, str) and isinstance(identifier, str):
            result.setdefault(digest, []).append(identifier)
    return result


def inspect_trust_inputs(
    inputs: TrustInputs, artifacts: list[dict]
) -> tuple[list[dict], list[dict]]:
    by_hash = _artifact_index(artifacts)
    records, gaps = [], []
    if inputs.sigstore_bundles:
        assert inputs.sigstore_trust_config is not None  # noqa: S101
        assert inputs.sigstore_policy is not None  # noqa: S101
        assert inputs.sigstore_verifier is not None  # noqa: S101
        for bundle in inputs.sigstore_bundles:
            try:
                candidates = sigstore_claimed_subjects(bundle.raw)
                matches = [digest for digest in candidates if digest in by_hash]
                if not matches:
                    gaps.append(
                        {"path": bundle.label, "reason": "Sigstore bundle has no scanned subject"}
                    )
                    continue
                if len(matches) != 1:
                    raise ValueError("Sigstore bundle has multiple scanned subjects")
                result = verify_sigstore_bundle(
                    bundle.raw,
                    inputs.sigstore_trust_config.raw,
                    inputs.sigstore_policy.raw,
                    artifact_sha256=matches[0],
                    verifier_path=inputs.sigstore_verifier,
                )
            except (OSError, ValueError) as error:
                gaps.append({"path": bundle.label, "reason": f"Sigstore unverified: {error}"})
                continue
            result["path"] = bundle.label
            result["bundle_input_sha256"] = bundle.sha256
            result["bound_artifacts"] = sorted(by_hash[matches[0]])
            records.append(result)
    if inputs.jsf_documents:
        assert inputs.jsf_policy is not None  # noqa: S101
        for document in inputs.jsf_documents:
            try:
                result = verify_jsf_document(document.raw, inputs.jsf_policy.raw)
            except (ImportError, OSError, ValueError) as error:
                gaps.append({"path": document.label, "reason": f"JSF unverified: {error}"})
                continue
            result["path"] = document.label
            result["document_input_sha256"] = document.sha256
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
