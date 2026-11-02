# ruff: noqa: C901, EM101, EM102, PLR2004, TRY003
"""Reviewed family-specific WebAssembly function-profile recognition."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from brotli_binary_data import sha256_data
from brotli_binary_layout import inspect_layout

if TYPE_CHECKING:
    from brotli_binary_data import Buffer

CATALOG = Path(__file__).resolve().parent.parent / "references/wasm-function-profiles.json"
MAX_CATALOG_BYTES = 4 * 1024 * 1024
MAX_PROFILE_HASHES = 10_000


@dataclass(frozen=True)
class WasmProfileAssessment:
    matches: tuple[dict[str, Any], ...]
    gaps: tuple[str, ...]
    patch_status: Literal[
        "unknown", "vulnerable_code_match", "fixed_code_match", "mixed_code_matches"
    ]
    limited: bool = False

    def as_dict(self) -> dict[str, Any]:
        return json.loads(json.dumps(asdict(self), sort_keys=True))


def _sha256(value: object, subject: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value.lower() != value
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"Invalid WebAssembly profile SHA-256: {subject}")
    return value


def load_wasm_profile_catalog(path: Path = CATALOG) -> tuple[dict[str, Any], ...]:
    if path.stat().st_size > MAX_CATALOG_BYTES:
        raise ValueError("WebAssembly profile catalog exceeds byte limit")
    with path.open("rb") as stream:
        raw = stream.read(MAX_CATALOG_BYTES + 1)
    if len(raw) > MAX_CATALOG_BYTES:
        raise ValueError("WebAssembly profile catalog exceeds byte limit")
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or set(value) != {"schema_version", "profiles"}
        or not isinstance(value["profiles"], list)
        or not value["profiles"]
    ):
        raise ValueError("Invalid WebAssembly profile catalog schema")
    identifiers = set()
    result = []
    for entry in value["profiles"]:
        required = {
            "id",
            "implementation_family",
            "source_version",
            "patch_status",
            "artifact_sha256",
            "noncustom_sha256",
            "artifact_size",
            "function_count",
            "verified_identity_count",
            "family_anchors",
            "required_profiles",
            "qualification",
            "qualification_status",
        }
        if (
            not isinstance(entry, dict)
            or set(entry) != required
            or not isinstance(entry["id"], str)
            or not entry["id"]
            or entry["id"] in identifiers
            or not isinstance(entry["implementation_family"], str)
            or not entry["implementation_family"]
            or not isinstance(entry["source_version"], str)
            or entry["patch_status"] not in ("vulnerable_code_match", "fixed_code_match")
            or type(entry["artifact_size"]) is not int
            or entry["artifact_size"] <= 0
            or type(entry["function_count"]) is not int
            or type(entry["verified_identity_count"]) is not int
            or not isinstance(entry["qualification"], dict)
            or entry["qualification_status"]
            not in ("pending_source_rebuild", "source_rebuild_verified")
        ):
            raise ValueError("Invalid WebAssembly profile catalog entry")
        _sha256(entry["artifact_sha256"], "artifact")
        _sha256(entry["noncustom_sha256"], "noncustom module")
        for field in ("family_anchors", "required_profiles"):
            population = entry[field]
            if (
                not isinstance(population, list)
                or not population
                or len(population) > MAX_PROFILE_HASHES
                or any(not isinstance(digest, str) for digest in population)
                or population != sorted(set(population))
            ):
                raise ValueError(f"Invalid WebAssembly profile population: {field}")
            for digest in population:
                _sha256(digest, field)
        identifiers.add(entry["id"])
        result.append(entry)
    return tuple(result)


def match_wasm_profiles(
    data: Buffer,
    catalog: tuple[dict[str, Any], ...] | None = None,
    *,
    layout: dict[str, Any] | None = None,
) -> WasmProfileAssessment:
    """Match one module against reviewed profiles without transferring native evidence."""
    layout = inspect_layout(data) if layout is None else layout
    if layout.get("kind") != "wasm":
        return WasmProfileAssessment((), ("Artifact is not WebAssembly",), "unknown")
    identities = [
        function.get("function_identity", {})
        for function in layout.get("functions", [])
        if isinstance(function, dict)
    ]
    observed = {
        identity["profile_sha256"]
        for identity in identities
        if identity.get("status") == "verified_identity"
        and isinstance(identity.get("profile_sha256"), str)
    }
    artifact_sha256 = sha256_data(data)
    matches = []
    qualified_states = set()
    for entry in catalog or load_wasm_profile_catalog():
        exact = entry["artifact_sha256"] == artifact_sha256 and entry["artifact_size"] == len(data)
        anchored = set(entry["family_anchors"]) <= observed
        complete = set(entry["required_profiles"]) <= observed
        semantic = entry["noncustom_sha256"] == layout.get("wasm_noncustom_sha256")
        recognized = anchored and complete
        if not exact and not semantic and not recognized:
            continue
        qualified = (exact or semantic) and entry[
            "qualification_status"
        ] == "source_rebuild_verified"
        patch_status = entry["patch_status"] if qualified else "unknown"
        if qualified:
            qualified_states.add(entry["patch_status"])
        matches.append(
            {
                "id": entry["id"],
                "implementation_family": entry["implementation_family"],
                "source_version": entry["source_version"],
                "patch_status": patch_status,
                "qualified_source_status": entry["patch_status"],
                "method": (
                    "exact_wasm_artifact_sha256"
                    if exact
                    else (
                        "validated_noncustom_wasm_sha256"
                        if semantic
                        else "reviewed_wasm_function_population"
                    )
                ),
                "artifact_sha256": artifact_sha256,
                "required_profiles": len(entry["required_profiles"]),
                "family_anchors": len(entry["family_anchors"]),
                "qualification": entry["qualification"],
                "qualification_status": entry["qualification_status"],
            }
        )
    if len(qualified_states) > 1:
        patch_status: Literal[
            "unknown", "vulnerable_code_match", "fixed_code_match", "mixed_code_matches"
        ] = "mixed_code_matches"
    elif qualified_states:
        patch_status = next(iter(qualified_states))
    else:
        patch_status = "unknown"
    if not matches:
        gaps = ("No reviewed family-specific WebAssembly profile matched",)
    elif not qualified_states:
        gaps = ("WebAssembly family matched, but full non-custom module identity is unqualified",)
    else:
        gaps = ()
    return WasmProfileAssessment(tuple(matches), gaps, patch_status)
