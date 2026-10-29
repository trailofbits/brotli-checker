"""Bounded structured CycloneDX and SPDX provenance parsing."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal

MAX_DOCUMENT_CHARS = 16 * 1024 * 1024
MAX_COMPONENTS = 50_000
MAX_RELATIONS = 100_000
MAX_HASHES_PER_COMPONENT = 16
MAX_EXTERNAL_REFS_PER_COMPONENT = 64
MAX_COMPLETENESS_DECLARATIONS = 10_000
MAX_COMPLETENESS_REFERENCES = 100_000
MAX_STRING_CHARS = 1024
SHA256_HEX_CHARS = 64
HEX = re.compile(r"[0-9A-Fa-f]+")
HASH_ALGORITHMS = {
    "MD5": (32, "MD5"),
    "SHA1": (40, "SHA-1"),
    "SHA-1": (40, "SHA-1"),
    "SHA256": (64, "SHA-256"),
    "SHA-256": (64, "SHA-256"),
    "SHA384": (96, "SHA-384"),
    "SHA-384": (96, "SHA-384"),
    "SHA512": (128, "SHA-512"),
    "SHA-512": (128, "SHA-512"),
    "BLAKE2B-256": (64, "BLAKE2B-256"),
    "BLAKE3": (64, "BLAKE3"),
}
STRONG_HASHES = frozenset({"SHA-256", "SHA-384", "SHA-512", "BLAKE2B-256", "BLAKE3"})
CYCLONEDX_AGGREGATES = frozenset(
    {
        "complete",
        "incomplete",
        "incomplete_first_party_only",
        "incomplete_first_party_proprietary_only",
        "incomplete_first_party_opensource_only",
        "incomplete_third_party_only",
        "incomplete_third_party_proprietary_only",
        "incomplete_third_party_opensource_only",
        "unknown",
        "not_specified",
    }
)


@dataclass(frozen=True)
class ProvenanceHash:
    algorithm: str
    value: str


@dataclass(frozen=True)
class ProvenanceComponent:
    identifier: str
    kind: str
    name: str
    version: str | None
    purl: str | None
    hashes: tuple[ProvenanceHash, ...]
    evidence_strength: Literal["name_only", "package_id", "artifact_hash_declared"]


@dataclass(frozen=True)
class ProvenanceRelation:
    source: str
    target: str
    kind: str


@dataclass(frozen=True)
class CompletenessDeclaration:
    aggregate: str
    assemblies: tuple[str, ...]
    dependencies: tuple[str, ...]


@dataclass(frozen=True)
class ProvenanceDocument:
    format: Literal["cyclonedx", "spdx"]
    spec_version: str
    components: tuple[ProvenanceComponent, ...]
    relations: tuple[ProvenanceRelation, ...]
    completeness: tuple[CompletenessDeclaration, ...]
    gaps: tuple[str, ...]
    limited: bool


@dataclass(frozen=True)
class ArtifactBinding:
    component_identifier: str
    evidence_strength: Literal["artifact_hash_bound", "unresolved"]
    sha256: str
    gap: str | None


def _string(value: object, field: str, gaps: list[str], *, required: bool = False) -> str | None:
    if not isinstance(value, str) or not value.strip():
        if required:
            gaps.append(f"Missing or invalid {field}")
        return None
    if len(value) > MAX_STRING_CHARS:
        gaps.append(f"{field} exceeds the {MAX_STRING_CHARS}-character limit")
        return None
    return value


def _hashes(value: object, field: str, gaps: list[str]) -> tuple[ProvenanceHash, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        gaps.append(f"Invalid {field} hash population")
        return ()
    hashes = []
    for index, entry in enumerate(value[: MAX_HASHES_PER_COMPONENT + 1]):
        if index == MAX_HASHES_PER_COMPONENT:
            gaps.append(f"{field} hash limit reached")
            break
        if not isinstance(entry, dict):
            gaps.append(f"Invalid {field} hash entry")
            continue
        algorithm = entry.get("alg", entry.get("algorithm"))
        content = entry.get("content", entry.get("checksumValue"))
        if not isinstance(algorithm, str) or algorithm.upper() not in HASH_ALGORITHMS:
            gaps.append(f"Unsupported {field} hash algorithm")
            continue
        size, normalized = HASH_ALGORITHMS[algorithm.upper()]
        if not isinstance(content, str) or len(content) != size or HEX.fullmatch(content) is None:
            gaps.append(f"Invalid {field} {normalized} value")
            continue
        hashes.append(ProvenanceHash(normalized, content.lower()))
    return tuple(sorted(set(hashes), key=lambda item: (item.algorithm, item.value)))


def _strength(
    hashes: tuple[ProvenanceHash, ...], purl: str | None
) -> Literal["name_only", "package_id", "artifact_hash_declared"]:
    if any(item.algorithm in STRONG_HASHES for item in hashes):
        return "artifact_hash_declared"
    return "package_id" if purl else "name_only"


def _append_component(
    component: ProvenanceComponent,
    components: list[ProvenanceComponent],
    identifiers: set[str],
    gaps: list[str],
) -> bool:
    if component.identifier in identifiers:
        gaps.append(f"Duplicate component identifier: {component.identifier}")
        return False
    if len(components) >= MAX_COMPONENTS:
        if "Component limit reached" not in gaps:
            gaps.append("Component limit reached")
        return False
    identifiers.add(component.identifier)
    components.append(component)
    return True


def _append_relation(
    relation: ProvenanceRelation,
    relations: list[ProvenanceRelation],
    known: set[str],
    gaps: list[str],
) -> bool:
    if relation.source not in known or relation.target not in known:
        gaps.append(f"Unresolved relationship endpoint: {relation.source} -> {relation.target}")
        return False
    if len(relations) >= MAX_RELATIONS:
        if "Relationship limit reached" not in gaps:
            gaps.append("Relationship limit reached")
        return False
    relations.append(relation)
    return True


def _cyclonedx_component(entry: object, index: int, gaps: list[str]) -> ProvenanceComponent | None:
    if not isinstance(entry, dict):
        gaps.append("Invalid CycloneDX component entry")
        return None
    name = _string(entry.get("name"), f"components[{index}].name", gaps, required=True)
    if name is None:
        return None
    purl = _string(entry.get("purl"), f"components[{index}].purl", gaps)
    identifier = _string(entry.get("bom-ref"), f"components[{index}].bom-ref", gaps)
    identifier = identifier or purl or f"component:{index}"
    version = _string(entry.get("version"), f"components[{index}].version", gaps)
    kind = _string(entry.get("type"), f"components[{index}].type", gaps) or "library"
    hashes = _hashes(entry.get("hashes"), f"components[{index}]", gaps)
    return ProvenanceComponent(
        identifier, kind, name, version, purl, hashes, _strength(hashes, purl)
    )


def _cyclonedx_entries(metadata: dict[str, Any], gaps: list[str]) -> list[object]:
    population = metadata.get("components", [])
    if not isinstance(population, list):
        gaps.append("Invalid CycloneDX components population")
        population = []
    root = metadata.get("metadata")
    root_component = root.get("component") if isinstance(root, dict) else None
    pending = list(reversed(([root_component] if root_component is not None else []) + population))
    entries = []
    while pending and len(entries) < MAX_COMPONENTS + 1:
        entry = pending.pop()
        entries.append(entry)
        if isinstance(entry, dict) and "components" in entry:
            nested = entry["components"]
            if isinstance(nested, list):
                pending.extend(reversed(nested))
            else:
                gaps.append("Invalid nested CycloneDX components population")
    if pending:
        gaps.append("Component limit reached")
    return entries


def _cyclonedx(  # noqa: C901, PLR0912, PLR0915 -- One bounded format/gap state.
    metadata: dict[str, Any], gaps: list[str]
) -> ProvenanceDocument:
    version = _string(metadata.get("specVersion"), "CycloneDX specVersion", gaps, required=True)
    components: list[ProvenanceComponent] = []
    identifiers: set[str] = set()
    entries = _cyclonedx_entries(metadata, gaps)
    for index, entry in enumerate(entries):
        component = _cyclonedx_component(entry, index, gaps)
        if component is not None:
            _append_component(component, components, identifiers, gaps)
        if len(components) >= MAX_COMPONENTS:
            if index + 1 < len(entries) and "Component limit reached" not in gaps:
                gaps.append("Component limit reached")
            break
    relations: list[ProvenanceRelation] = []
    relation_candidates = 0
    relations_exhausted = False
    dependencies = metadata.get("dependencies", [])
    if not isinstance(dependencies, list):
        gaps.append("Invalid CycloneDX dependencies population")
        dependencies = []
    for entry in dependencies:
        if not isinstance(entry, dict) or not isinstance(entry.get("ref"), str):
            gaps.append("Invalid CycloneDX dependency entry")
            continue
        targets = entry.get("dependsOn", [])
        if not isinstance(targets, list):
            gaps.append("Invalid CycloneDX dependsOn population")
            continue
        for target in targets:
            if relation_candidates >= MAX_RELATIONS:
                if "Relationship limit reached" not in gaps:
                    gaps.append("Relationship limit reached")
                relations_exhausted = True
                break
            relation_candidates += 1
            if isinstance(target, str):
                _append_relation(
                    ProvenanceRelation(entry["ref"], target, "depends_on"),
                    relations,
                    identifiers,
                    gaps,
                )
            else:
                gaps.append("Invalid CycloneDX dependency target")
        if relations_exhausted:
            break
    completeness = []
    compositions = metadata.get("compositions", [])
    if not isinstance(compositions, list):
        gaps.append("Invalid CycloneDX compositions population")
        compositions = []
    for index, entry in enumerate(compositions):
        if index >= MAX_COMPLETENESS_DECLARATIONS:
            gaps.append("Completeness declaration limit reached")
            break
        if not isinstance(entry, dict) or entry.get("aggregate") not in CYCLONEDX_AGGREGATES:
            gaps.append("Invalid CycloneDX completeness declaration")
            continue
        assemblies = entry.get("assemblies", [])
        declared_dependencies = entry.get("dependencies", [])
        if not isinstance(assemblies, list) or not all(
            isinstance(item, str) for item in assemblies
        ):
            gaps.append("Invalid CycloneDX completeness assemblies")
            continue
        if not isinstance(declared_dependencies, list) or not all(
            isinstance(item, str) for item in declared_dependencies
        ):
            gaps.append("Invalid CycloneDX completeness dependencies")
            continue
        if len(assemblies) + len(declared_dependencies) > MAX_COMPLETENESS_REFERENCES:
            gaps.append("Completeness reference limit reached")
            break
        completeness.append(
            CompletenessDeclaration(
                entry["aggregate"], tuple(assemblies), tuple(declared_dependencies)
            )
        )
        gaps.extend(
            f"Unresolved completeness reference: {reference}"
            for reference in (*assemblies, *declared_dependencies)
            if reference not in identifiers
        )
    if "signature" in metadata:
        gaps.append("CycloneDX signature is declared but not cryptographically verified")
    limited = any("limit reached" in gap for gap in gaps)
    return ProvenanceDocument(
        "cyclonedx",
        version or "unknown",
        tuple(components),
        tuple(sorted(set(relations), key=lambda item: (item.source, item.kind, item.target))),
        tuple(completeness),
        tuple(gaps),
        limited,
    )


def _spdx_purl(entry: dict[str, Any], field: str, gaps: list[str]) -> str | None:
    refs = entry.get("externalRefs", [])
    if not isinstance(refs, list):
        gaps.append(f"Invalid {field} externalRefs population")
        return None
    purls = []
    for index, ref in enumerate(refs):
        if index >= MAX_EXTERNAL_REFS_PER_COMPONENT:
            gaps.append(f"{field} externalRef limit reached")
            break
        if not isinstance(ref, dict):
            gaps.append(f"Invalid {field} externalRef")
            continue
        ref_type = ref.get("referenceType")
        locator = ref.get("referenceLocator")
        if isinstance(ref_type, str) and ref_type.lower() == "purl" and isinstance(locator, str):
            purls.append(locator)
    if len(set(purls)) > 1:
        gaps.append(f"Conflicting {field} purl references")
        return None
    return _string(purls[0], f"{field}.purl", gaps) if purls else None


def _spdx_component(
    entry: object, field: str, kind: str, gaps: list[str]
) -> ProvenanceComponent | None:
    if not isinstance(entry, dict):
        gaps.append(f"Invalid SPDX {field} entry")
        return None
    identifier = _string(entry.get("SPDXID"), f"{field}.SPDXID", gaps, required=True)
    name = _string(entry.get("name", entry.get("fileName")), f"{field}.name", gaps, required=True)
    if identifier is None or name is None:
        return None
    version = _string(entry.get("versionInfo"), f"{field}.versionInfo", gaps)
    purl = _spdx_purl(entry, field, gaps)
    hashes = _hashes(entry.get("checksums"), field, gaps)
    return ProvenanceComponent(
        identifier, kind, name, version, purl, hashes, _strength(hashes, purl)
    )


def _spdx(  # noqa: C901, PLR0912, PLR0915 -- One bounded format/gap state.
    metadata: dict[str, Any], gaps: list[str]
) -> ProvenanceDocument:
    version = _string(metadata.get("spdxVersion"), "SPDX spdxVersion", gaps, required=True)
    components: list[ProvenanceComponent] = []
    identifiers: set[str] = set()
    for population_name, kind in (("packages", "package"), ("files", "file")):
        population = metadata.get(population_name, [])
        if not isinstance(population, list):
            gaps.append(f"Invalid SPDX {population_name} population")
            continue
        for index, entry in enumerate(population):
            if len(components) >= MAX_COMPONENTS:
                if "Component limit reached" not in gaps:
                    gaps.append("Component limit reached")
                break
            component = _spdx_component(entry, f"{population_name}[{index}]", kind, gaps)
            if component is not None:
                _append_component(component, components, identifiers, gaps)
    document_id = (
        _string(metadata.get("SPDXID"), "SPDX document SPDXID", gaps) or "SPDXRef-DOCUMENT"
    )
    known = {*identifiers, document_id}
    relations: list[ProvenanceRelation] = []
    relation_candidates = 0
    described = metadata.get("documentDescribes", [])
    if not isinstance(described, list):
        gaps.append("Invalid SPDX documentDescribes population")
        described = []
    for target in described:
        if relation_candidates >= MAX_RELATIONS:
            if "Relationship limit reached" not in gaps:
                gaps.append("Relationship limit reached")
            break
        relation_candidates += 1
        if isinstance(target, str):
            _append_relation(
                ProvenanceRelation(document_id, target, "describes"), relations, known, gaps
            )
        else:
            gaps.append("Invalid SPDX documentDescribes target")
    population = metadata.get("relationships", [])
    if not isinstance(population, list):
        gaps.append("Invalid SPDX relationships population")
        population = []
    for entry in population:
        if relation_candidates >= MAX_RELATIONS:
            if "Relationship limit reached" not in gaps:
                gaps.append("Relationship limit reached")
            break
        relation_candidates += 1
        if not isinstance(entry, dict):
            gaps.append("Invalid SPDX relationship entry")
            continue
        source = entry.get("spdxElementId")
        target = entry.get("relatedSpdxElement")
        kind = entry.get("relationshipType")
        if not all(isinstance(item, str) and item for item in (source, target, kind)):
            gaps.append("Invalid SPDX relationship entry")
            continue
        _append_relation(ProvenanceRelation(source, target, kind.lower()), relations, known, gaps)
    limited = any("limit reached" in gap for gap in gaps)
    return ProvenanceDocument(
        "spdx",
        version or "unknown",
        tuple(components),
        tuple(sorted(set(relations), key=lambda item: (item.source, item.kind, item.target))),
        (),
        tuple(gaps),
        limited,
    )


def parse_provenance_json(text: str, name: str = "provenance.json") -> ProvenanceDocument:
    """Parse one supplied JSON SBOM without resolving packages or external references."""
    if len(text) > MAX_DOCUMENT_CHARS:
        msg = f"{name} exceeds the {MAX_DOCUMENT_CHARS}-character provenance limit"
        raise ValueError(msg)
    try:
        metadata = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as error:
        msg = f"Invalid structured provenance JSON: {name}"
        raise ValueError(msg) from error
    if not isinstance(metadata, dict):
        msg = f"Structured provenance root must be an object: {name}"
        raise ValueError(msg)  # noqa: TRY004 -- Malformed document is a value error.
    gaps: list[str] = []
    if metadata.get("bomFormat") == "CycloneDX":
        return _cyclonedx(metadata, gaps)
    if isinstance(metadata.get("spdxVersion"), str):
        return _spdx(metadata, gaps)
    msg = f"Unsupported structured provenance format: {name}"
    raise ValueError(msg)


def bind_component_hash(component: ProvenanceComponent, artifact_sha256: str) -> ArtifactBinding:
    """Upgrade one declaration only after an exact supplied artifact SHA-256 match."""
    if (
        len(artifact_sha256) != SHA256_HEX_CHARS
        or HEX.fullmatch(artifact_sha256) is None
        or artifact_sha256.lower() != artifact_sha256
    ):
        msg = "Artifact SHA-256 must be 64 lowercase hexadecimal characters"
        raise ValueError(msg)
    declared = {item.value for item in component.hashes if item.algorithm == "SHA-256"}
    if not declared:
        return ArtifactBinding(
            component.identifier,
            "unresolved",
            artifact_sha256,
            "Component has no declared SHA-256 to bind to the artifact",
        )
    if artifact_sha256 not in declared:
        return ArtifactBinding(
            component.identifier,
            "unresolved",
            artifact_sha256,
            "Artifact SHA-256 does not match the component declaration",
        )
    return ArtifactBinding(component.identifier, "artifact_hash_bound", artifact_sha256, None)
