"""Join explicitly supplied deployment observations without trusting target paths."""

from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING

from brotli_attestations import parse_evidence_document

if TYPE_CHECKING:
    from collections.abc import Sequence

    from brotli_attestations import CapturedDocument

MAX_RUNTIME_TRACES = 64
MAX_RUNTIME_EVENTS = 10000
MAX_TEXT_CHARS = 4096
MIN_PRINTABLE = 32
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _text(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_TEXT_CHARS
        or any(ord(char) < MIN_PRINTABLE for char in value)
    ):
        message = f"Runtime evidence has invalid {field}"
        raise ValueError(message)
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        message = "Runtime evidence requires lowercase SHA-256"
        raise ValueError(message)
    return value


def _fields(value: object, expected: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        message = "Runtime evidence object has missing or unsupported fields"
        raise ValueError(message)
    return value


def _instant(value: object) -> str:
    text = _text(value, "observed_at")
    try:
        instant = datetime.fromisoformat(text)
    except ValueError as error:
        message = "Runtime observation timestamp must be ISO 8601 with timezone"
        raise ValueError(message) from error
    if instant.tzinfo is None:
        message = "Runtime observation timestamp requires timezone"
        raise ValueError(message)
    return text


def _artifact(reference: object, namespace: str, index: dict) -> str:
    item = _fields(reference, {"logical_path", "sha256"})
    path = _text(item["logical_path"], "logical_path")
    digest = _digest(item["sha256"])
    candidates = index.get((namespace, path, digest), [])
    if len(candidates) != 1:
        message = "Runtime observation requires one exact namespace/path/hash artifact"
        raise ValueError(message)
    return candidates[0]


def _event(event: object, namespace: str, index: dict) -> dict:
    item = _fields(event, {"kind", "source", "target", "symbol", "observed_at"})
    if item["kind"] not in ("symbol_binding", "decoder_call"):
        message = "Runtime event must be a symbol binding or decoder call, not load/absence"
        raise ValueError(message)
    return {
        "kind": item["kind"],
        "source": _artifact(item["source"], namespace, index),
        "target": _artifact(item["target"], namespace, index),
        "symbol": _text(item["symbol"], "symbol"),
        "observed_at": _instant(item["observed_at"]),
        "status": "supplied_observation",
        "authentication": "not_independently_verified",
        "patch_status": "unknown",
        "attacker_control": "unknown",
    }


def bind_runtime_trace(raw: bytes, artifacts: Sequence[dict]) -> dict:
    """Validate scope/identity, not the truth or completeness of a collector's claims."""
    document = _fields(
        parse_evidence_document(raw),
        {"schema_version", "deployment", "collector", "events"},
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        message = "Unsupported runtime trace schema"
        raise ValueError(message)
    deployment = _fields(document["deployment"], {"id", "namespace", "configuration_sha256"})
    namespace = _text(deployment["namespace"], "namespace")
    if namespace.startswith(("unresolved:", "unresolved-image:")):
        message = "Runtime trace cannot bind an unresolved namespace"
        raise ValueError(message)
    scope = {
        "id": _text(deployment["id"], "deployment id"),
        "namespace": namespace,
        "configuration_sha256": _digest(deployment["configuration_sha256"]),
    }
    collector = _text(document["collector"], "collector")
    events = document["events"]
    if not isinstance(events, list) or not events or len(events) > MAX_RUNTIME_EVENTS:
        message = "Runtime event population is empty, invalid, or over limit"
        raise ValueError(message)
    index: dict[tuple, list[str]] = {}
    for artifact in artifacts:
        key = (artifact["namespace"], artifact["logical_path"], artifact["sha256"])
        index.setdefault(key, []).append(artifact["id"])
    return {
        "deployment": scope,
        "collector": collector,
        "events": [_event(event, namespace, index) for event in events],
        "scope_status": "artifact_identity_bound",
        "observation_status": "supplied_not_independently_verified",
        "absence_proven": False,
        "patch_status": "unknown",
    }


def inspect_runtime_traces(
    documents: Sequence[CapturedDocument], artifacts: Sequence[dict]
) -> tuple[list[dict], list[dict]]:
    results, gaps = [], []
    if len(documents) > MAX_RUNTIME_TRACES:
        message = "Supplied runtime trace count exceeds limit"
        raise ValueError(message)
    for document in documents:
        try:
            result = bind_runtime_trace(document.raw, artifacts)
        except ValueError as error:
            gaps.append({"path": document.label, "reason": str(error)})
        else:
            results.append({"label": document.label, "sha256": document.sha256, **result})
    return results, gaps
