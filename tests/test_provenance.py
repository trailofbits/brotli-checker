import json
from dataclasses import FrozenInstanceError

import brotli_provenance as subject
import pytest


def test_cyclonedx_components_hashes_relationships_and_completeness():
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {
                "bom-ref": "app",
                "type": "application",
                "name": "service",
                "version": "1.0",
            }
        },
        "components": [
            {
                "bom-ref": "brotli",
                "type": "library",
                "name": "brotli",
                "version": "1.2.1",
                "purl": "pkg:generic/brotli@1.2.1",
                "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
            }
        ],
        "dependencies": [{"ref": "app", "dependsOn": ["brotli"]}],
        "compositions": [
            {"aggregate": "complete", "assemblies": ["app"], "dependencies": ["brotli"]}
        ],
    }

    result = subject.parse_provenance_json(json.dumps(document), "bom.json")

    assert result.format == "cyclonedx"
    assert result.spec_version == "1.6"
    assert [component.identifier for component in result.components] == ["app", "brotli"]
    brotli = result.components[1]
    assert brotli.evidence_strength == "artifact_hash_declared"
    assert brotli.hashes == (subject.ProvenanceHash("SHA-256", "a" * 64),)
    assert subject.bind_component_hash(brotli, "a" * 64).evidence_strength == (
        "artifact_hash_bound"
    )
    assert result.relations == (subject.ProvenanceRelation("app", "brotli", "depends_on"),)
    assert result.completeness == (
        subject.CompletenessDeclaration("complete", ("app",), ("brotli",)),
    )
    assert result.gaps == ()
    assert result.limited is False


def test_spdx_packages_files_external_ids_and_relationships():
    document = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "name": "brotli",
                "versionInfo": "1.2.1",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:generic/brotli@1.2.1",
                    }
                ],
                "checksums": [{"algorithm": "SHA1", "checksumValue": "b" * 40}],
            }
        ],
        "files": [
            {
                "SPDXID": "SPDXRef-File",
                "fileName": "libbrotlidec.so",
                "checksums": [{"algorithm": "SHA256", "checksumValue": "c" * 64}],
            }
        ],
        "documentDescribes": ["SPDXRef-Package"],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-Package",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": "SPDXRef-File",
            }
        ],
    }

    result = subject.parse_provenance_json(json.dumps(document), "spdx.json")

    assert result.format == "spdx"
    assert [component.evidence_strength for component in result.components] == [
        "package_id",
        "artifact_hash_declared",
    ]
    assert set(result.relations) == {
        subject.ProvenanceRelation("SPDXRef-DOCUMENT", "SPDXRef-Package", "describes"),
        subject.ProvenanceRelation("SPDXRef-Package", "SPDXRef-File", "contains"),
    }
    assert result.completeness == ()
    assert result.gaps == ()


def test_duplicate_unresolved_and_unsupported_provenance_is_explicit():
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"bom-ref": "same", "name": "first"},
            {
                "bom-ref": "same",
                "name": "second",
                "hashes": [{"alg": "CRC32", "content": "12345678"}],
            },
        ],
        "dependencies": [{"ref": "same", "dependsOn": ["missing"]}],
    }

    result = subject.parse_provenance_json(json.dumps(document))

    assert len(result.components) == 1
    assert any("Duplicate component identifier" in gap for gap in result.gaps)
    assert any("Unsupported" in gap for gap in result.gaps)
    assert any("Unresolved relationship endpoint" in gap for gap in result.gaps)
    assert result.relations == ()


def test_nested_components_and_unverified_signature_are_preserved_conservatively():
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "signature": {"algorithm": "RS256", "value": "unverified"},
        "components": [
            {
                "bom-ref": "parent",
                "name": "parent",
                "components": [{"bom-ref": "child", "name": "brotli"}],
            }
        ],
    }

    result = subject.parse_provenance_json(json.dumps(document))

    assert [item.identifier for item in result.components] == ["parent", "child"]
    assert any("not cryptographically verified" in gap for gap in result.gaps)


def test_hash_binding_requires_exact_supplied_artifact_identity():
    component = subject.ProvenanceComponent(
        "brotli",
        "library",
        "brotli",
        "1.2.1",
        None,
        (subject.ProvenanceHash("SHA-256", "a" * 64),),
        "artifact_hash_declared",
    )

    mismatch = subject.bind_component_hash(component, "b" * 64)

    assert mismatch.evidence_strength == "unresolved"
    assert mismatch.gap is not None
    assert "does not match" in mismatch.gap
    with pytest.raises(ValueError, match="lowercase hexadecimal"):
        subject.bind_component_hash(component, "A" * 64)


def test_provenance_limits_are_bounded_and_reported(monkeypatch):
    monkeypatch.setattr(subject, "MAX_COMPONENTS", 1)
    monkeypatch.setattr(subject, "MAX_RELATIONS", 0)
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"bom-ref": "one", "name": "one"},
            {"bom-ref": "two", "name": "two"},
        ],
        "dependencies": [{"ref": "one", "dependsOn": ["one"]}],
    }

    result = subject.parse_provenance_json(json.dumps(document))

    assert len(result.components) == 1
    assert result.relations == ()
    assert result.limited is True
    assert "Component limit reached" in result.gaps
    assert "Relationship limit reached" in result.gaps


def test_provenance_input_and_result_are_strict_and_immutable(monkeypatch):
    with pytest.raises(ValueError, match="Unsupported structured provenance"):
        subject.parse_provenance_json("{}")
    monkeypatch.setattr(subject, "MAX_DOCUMENT_CHARS", 2)
    with pytest.raises(ValueError, match="provenance limit"):
        subject.parse_provenance_json("{} ")
    monkeypatch.setattr(subject, "MAX_DOCUMENT_CHARS", 16 * 1024 * 1024)

    result = subject.parse_provenance_json(
        '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}'
    )
    with pytest.raises(FrozenInstanceError):
        result.spec_version = "changed"  # ty: ignore[invalid-assignment]


def test_recursive_json_is_rejected(monkeypatch):
    def recursive(_text):
        raise RecursionError

    monkeypatch.setattr(subject.json, "loads", recursive)
    with pytest.raises(ValueError, match="Invalid structured provenance JSON"):
        subject.parse_provenance_json("{}")
