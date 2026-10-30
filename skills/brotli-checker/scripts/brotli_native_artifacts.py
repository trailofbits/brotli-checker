"""Strict exact-artifact evidence from independently reviewed paired native builds."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

CATALOG = Path(__file__).resolve().parent.parent / "references/native-artifacts.json"
FINGERPRINTS = Path(__file__).resolve().parent.parent / "references/fingerprints.json"
MAX_CATALOG_BYTES = 8 * 1024 * 1024
MAX_ARTIFACTS = 1000
HEX = frozenset("0123456789abcdef")
PATCH_STATUSES = frozenset({"vulnerable_code_match", "fixed_code_match"})
PROVENANCE_FIELDS = frozenset(
    {
        "id",
        "format",
        "abi",
        "machine",
        "elf_class",
        "byteorder",
        "source",
        "source_sha256",
        "headers_sha256",
        "object_sha256",
        "compiler",
        "flags",
        "build_note",
        "source_state",
    }
)
ARTIFACT_FIELDS = frozenset(
    {
        "artifact_name",
        "sha256",
        "size",
        "patch_status",
        "method",
        "negative_control",
        "provenance",
        "build_run_url",
        "build_commit",
    }
)


def _hex(value: object, size: int, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != size
        or any(character not in HEX for character in value)
    ):
        message = f"Invalid native artifact identity: {field}"
        raise ValueError(message)
    return value


def _reviewed_sources() -> dict[str, str]:
    try:
        registry = json.loads(FINGERPRINTS.read_bytes())
        fingerprints = registry["fingerprints"]
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        message = "Invalid reviewed source fingerprint registry"
        raise ValueError(message) from error
    if not isinstance(fingerprints, list):
        message = "Invalid reviewed source fingerprint registry"
        raise ValueError(message)  # noqa: TRY004 -- One public malformed-catalog error type.
    reviewed: dict[str, str] = {}
    for item in fingerprints:
        if not isinstance(item, dict):
            message = "Invalid reviewed source fingerprint registry"
            raise ValueError(message)  # noqa: TRY004 -- One public malformed-catalog error type.
        if item.get("implementation", "google_brotli_c") != "google_brotli_c":
            continue
        digest = item.get("sha256")
        state = item.get("state")
        if (
            not isinstance(digest, str)
            or not isinstance(state, str)
            or state not in {"fixed", "vulnerable"}
        ):
            message = "Invalid reviewed source fingerprint registry"
            raise ValueError(message)
        prior = reviewed.setdefault(digest, state)
        if prior != state:
            message = "Conflicting reviewed source fingerprint state"
            raise ValueError(message)
    return reviewed


def _provenance(value: object, expected_state: str, reviewed: dict[str, str]) -> dict:
    if not isinstance(value, dict) or set(value) != PROVENANCE_FIELDS:
        message = "Invalid native artifact provenance fields"
        raise ValueError(message)
    source_state = value["source_state"]
    if not isinstance(source_state, str) or source_state != expected_state:
        message = "Native artifact provenance disagrees with patch status"
        raise ValueError(message)
    for field in ("source_sha256", "headers_sha256", "object_sha256"):
        _hex(value[field], 64, field)
    source_sha256 = value["source_sha256"]
    if reviewed.get(source_sha256) != expected_state:
        message = "Native artifact provenance is not a reviewed source state"
        raise ValueError(message)
    if (
        not isinstance(value["format"], str)
        or value["format"] not in {"pe", "mach_o"}
        or not isinstance(value["abi"], str)
        or value["abi"] not in {"windows", "darwin"}
        or type(value["machine"]) is not int
        or type(value["elf_class"]) is not int
        or value["elf_class"] not in (32, 64)
        or not isinstance(value["byteorder"], str)
        or value["byteorder"] not in {"little", "big"}
    ):
        message = "Invalid native artifact target provenance"
        raise ValueError(message)
    for field in ("id", "source", "compiler", "flags", "build_note"):
        if not isinstance(value[field], str) or not value[field]:
            message = f"Invalid native artifact provenance: {field}"
            raise ValueError(message)
    return value


def validate_native_artifacts(  # noqa: C901 -- One strict packaged evidence boundary.
    document: object,
) -> dict[str, dict]:
    if not isinstance(document, dict) or set(document) != {"schema_version", "artifacts"}:
        message = "Invalid native artifact catalog fields"
        raise ValueError(message)
    artifacts = document["artifacts"]
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        message = "Invalid native artifact catalog schema"
        raise ValueError(message)
    if not isinstance(artifacts, list):
        message = "Invalid native artifact catalog schema"
        raise ValueError(message)  # noqa: TRY004 -- One public malformed-catalog error type.
    if len(artifacts) > MAX_ARTIFACTS:
        message = "Native artifact catalog entry limit reached"
        raise ValueError(message)
    reviewed = _reviewed_sources()
    result = {}
    for value in artifacts:
        if not isinstance(value, dict) or set(value) != ARTIFACT_FIELDS:
            message = "Invalid native artifact fields"
            raise ValueError(message)
        digest = _hex(value["sha256"], 64, "sha256")
        _hex(value["build_commit"], 40, "build_commit")
        if digest in result:
            message = "Duplicate native artifact SHA-256"
            raise ValueError(message)
        if (
            type(value["size"]) is not int
            or value["size"] <= 0
            or not isinstance(value["patch_status"], str)
            or value["patch_status"] not in PATCH_STATUSES
            or value["method"] != "paired_native_build_exact_artifact"
            or value["negative_control"] != "opposite_source_state_rejected"
            or not isinstance(value["artifact_name"], str)
            or not value["artifact_name"]
            or not isinstance(value["build_run_url"], str)
            or re.fullmatch(
                r"https://github\.com/trailofbits/brotli-checker/actions/runs/[1-9][0-9]*",
                value["build_run_url"],
            )
            is None
        ):
            message = "Invalid native artifact assertion"
            raise ValueError(message)
        state = "fixed" if value["patch_status"] == "fixed_code_match" else "vulnerable"
        provenance = value["provenance"]
        if not isinstance(provenance, list) or not provenance:
            message = "Native artifact assertion requires provenance"
            raise ValueError(message)
        value["provenance"] = [_provenance(item, state, reviewed) for item in provenance]
        result[digest] = value
    return result


def load_native_artifacts(path: Path = CATALOG) -> dict[str, dict]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_CATALOG_BYTES + 1)
    if len(raw) > MAX_CATALOG_BYTES:
        message = "Native artifact catalog exceeds byte limit"
        raise ValueError(message)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        message = "Invalid native artifact catalog JSON"
        raise ValueError(message) from error
    return validate_native_artifacts(document)


@lru_cache(maxsize=1)
def packaged_native_artifacts() -> dict[str, dict]:
    return load_native_artifacts()


def native_artifact_match(digest: str, size: int) -> dict | None:
    value = packaged_native_artifacts().get(digest)
    return value if value is not None and value["size"] == size else None
