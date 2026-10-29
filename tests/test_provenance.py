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


@pytest.mark.parametrize(
    ("value", "field"),
    [
        (
            subject.ProvenanceComponent("id", "library", "name", None, None, (), "name_only"),
            "name",
        ),
        (subject.ProvenanceRelation("a", "b", "contains"), "kind"),
        (subject.CompletenessDeclaration("complete", (), ()), "aggregate"),
        (subject.ArtifactBinding("id", "unresolved", "a" * 64, "gap"), "gap"),
    ],
)
def test_provenance_evidence_nodes_are_immutable(value, field):
    with pytest.raises(FrozenInstanceError):
        setattr(value, field, "changed")


def test_cyclonedx_string_hash_and_component_limits_are_exact(monkeypatch):
    monkeypatch.setattr(subject, "MAX_STRING_CHARS", 4)
    accepted = subject.parse_provenance_json(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"bom-ref": "id", "name": "four"}],
            }
        )
    )
    rejected = subject.parse_provenance_json(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"bom-ref": "id", "name": "five!"}],
            }
        )
    )
    assert accepted.components[0].name == "four"
    assert not any("character limit" in gap for gap in accepted.gaps)
    assert rejected.components == ()
    assert any("character limit" in gap for gap in rejected.gaps)

    monkeypatch.setattr(subject, "MAX_STRING_CHARS", 1024)
    monkeypatch.setattr(subject, "MAX_HASHES_PER_COMPONENT", 1)
    one_hash = {"alg": "SHA-256", "content": "a" * 64}
    hash_limited = subject.parse_provenance_json(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {"bom-ref": "one", "name": "one", "hashes": [one_hash]},
                    {
                        "bom-ref": "two",
                        "name": "two",
                        "hashes": [one_hash, {"alg": "SHA-1", "content": "b" * 40}],
                    },
                    {
                        "bom-ref": "bad-length",
                        "name": "bad-length",
                        "hashes": [{"alg": "SHA-256", "content": "c" * 63}],
                    },
                    {
                        "bom-ref": "bad-hex",
                        "name": "bad-hex",
                        "hashes": [{"alg": "SHA-256", "content": "g" * 64}],
                    },
                ],
            }
        )
    )
    assert hash_limited.components[0].hashes == (subject.ProvenanceHash("SHA-256", "a" * 64),)
    assert hash_limited.components[1].hashes == (subject.ProvenanceHash("SHA-256", "a" * 64),)
    assert hash_limited.components[2].hashes == hash_limited.components[3].hashes == ()
    assert sum("hash limit reached" in gap for gap in hash_limited.gaps) == 1
    assert sum("Invalid" in gap and "SHA-256" in gap for gap in hash_limited.gaps) == 2

    monkeypatch.setattr(subject, "MAX_COMPONENTS", 1)
    exact = subject.parse_provenance_json(
        '{"bomFormat":"CycloneDX","specVersion":"1.6",'
        '"components":[{"bom-ref":"one","name":"one"}]}'
    )
    over = subject.parse_provenance_json(
        '{"bomFormat":"CycloneDX","specVersion":"1.6",'
        '"components":[{"bom-ref":"one","name":"one"},{"bom-ref":"two","name":"two"}]}'
    )
    assert len(exact.components) == 1
    assert "Component limit reached" not in exact.gaps
    assert len(over.components) == 1
    assert "Component limit reached" in over.gaps


def test_cyclonedx_relationship_and_completeness_boundaries(monkeypatch):
    malformed = subject.parse_provenance_json(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"purl": "pkg:generic/one", "name": "one"},
                    {"bom-ref": "two", "name": "two"},
                    {"bom-ref": "missing-name"},
                ],
                "dependencies": [42, {"ref": 42}, {"ref": "two", "dependsOn": [42]}],
                "compositions": [
                    42,
                    {"aggregate": "invalid"},
                    {"aggregate": "complete", "assemblies": "one"},
                    {"aggregate": "complete", "assemblies": [42]},
                    {"aggregate": "complete", "dependencies": "two"},
                    {"aggregate": "complete", "dependencies": [42]},
                ],
            }
        )
    )
    assert malformed.spec_version == "unknown"
    assert malformed.components[0].identifier == "pkg:generic/one"
    assert malformed.components[0].kind == "library"
    assert malformed.relations == ()
    assert malformed.completeness == ()
    assert any("specVersion" in gap for gap in malformed.gaps)
    assert any("components[2].name" in gap for gap in malformed.gaps)
    assert sum("Invalid CycloneDX dependency entry" in gap for gap in malformed.gaps) == 2
    assert any("dependency target" in gap for gap in malformed.gaps)
    assert sum("completeness declaration" in gap for gap in malformed.gaps) == 2
    assert sum("completeness assemblies" in gap for gap in malformed.gaps) == 2
    assert sum("completeness dependencies" in gap for gap in malformed.gaps) == 2

    monkeypatch.setattr(subject, "MAX_RELATIONS", 1)
    related = subject.parse_provenance_json(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {"bom-ref": "one", "name": "one"},
                    {"bom-ref": "two", "name": "two"},
                    {"bom-ref": "three", "name": "three"},
                ],
                "dependencies": [
                    {"ref": "one", "dependsOn": ["two"]},
                    {"ref": "two", "dependsOn": ["three"]},
                ],
            }
        )
    )
    assert related.relations == (subject.ProvenanceRelation("one", "two", "depends_on"),)
    assert "Relationship limit reached" in related.gaps

    monkeypatch.setattr(subject, "MAX_COMPLETENESS_DECLARATIONS", 1)
    monkeypatch.setattr(subject, "MAX_COMPLETENESS_REFERENCES", 1)
    complete = subject.parse_provenance_json(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"bom-ref": "one", "name": "one"}],
                "compositions": [
                    {"aggregate": "complete", "assemblies": ["one"], "dependencies": ["one"]},
                    {"aggregate": "complete"},
                ],
            }
        )
    )
    assert complete.completeness == ()
    assert "Completeness reference limit reached" in complete.gaps

    exact = subject.parse_provenance_json(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"bom-ref": "one", "name": "one"}],
                "compositions": [
                    {"aggregate": "complete", "assemblies": ["one"]},
                    {"aggregate": "unknown"},
                ],
            }
        )
    )
    assert exact.completeness == (subject.CompletenessDeclaration("complete", ("one",), ()),)
    assert "Completeness reference limit reached" not in exact.gaps
    assert "Completeness declaration limit reached" in exact.gaps


def test_spdx_fallbacks_malformed_fields_and_exact_limits(monkeypatch):
    malformed = subject.parse_provenance_json(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {"name": "missing-id"},
                    {"SPDXID": "SPDXRef-MissingName"},
                    {
                        "SPDXID": "SPDXRef-BadType",
                        "name": "bad-type",
                        "externalRefs": [
                            {"referenceType": 1, "referenceLocator": "pkg:generic/bad"}
                        ],
                    },
                    {
                        "SPDXID": "SPDXRef-BadLocator",
                        "name": "bad-locator",
                        "externalRefs": [{"referenceType": "purl", "referenceLocator": 1}],
                    },
                    {
                        "SPDXID": "SPDXRef-Conflict",
                        "name": "conflict",
                        "externalRefs": [
                            {"referenceType": "purl", "referenceLocator": "pkg:generic/a"},
                            {"referenceType": "purl", "referenceLocator": "pkg:generic/b"},
                        ],
                    },
                ],
                "documentDescribes": ["SPDXRef-BadType"],
                "relationships": [
                    {
                        "spdxElementId": 1,
                        "relationshipType": "CONTAINS",
                        "relatedSpdxElement": "SPDXRef-BadType",
                    }
                ],
            }
        )
    )
    assert [item.identifier for item in malformed.components] == [
        "SPDXRef-BadType",
        "SPDXRef-BadLocator",
        "SPDXRef-Conflict",
    ]
    assert malformed.components[0].purl is None
    assert malformed.components[1].purl is None
    assert malformed.components[2].purl is None
    assert malformed.relations == (
        subject.ProvenanceRelation("SPDXRef-DOCUMENT", "SPDXRef-BadType", "describes"),
    )
    assert any("Conflicting" in gap for gap in malformed.gaps)
    assert any("packages[0].SPDXID" in gap for gap in malformed.gaps)
    assert any("packages[1].name" in gap for gap in malformed.gaps)
    assert any("Invalid SPDX relationship" in gap for gap in malformed.gaps)

    monkeypatch.setattr(subject, "MAX_EXTERNAL_REFS_PER_COMPONENT", 1)
    limited_ref = subject.parse_provenance_json(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-One",
                        "name": "one",
                        "externalRefs": [
                            {"referenceType": "purl", "referenceLocator": "pkg:generic/one"},
                            {"referenceType": "purl", "referenceLocator": "pkg:generic/two"},
                        ],
                    }
                ],
            }
        )
    )
    assert limited_ref.components[0].purl == "pkg:generic/one"
    assert any("externalRef limit reached" in gap for gap in limited_ref.gaps)

    monkeypatch.setattr(subject, "MAX_COMPONENTS", 1)
    limited_components = subject.parse_provenance_json(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {"SPDXID": "SPDXRef-One", "name": "one"},
                    {"SPDXID": "SPDXRef-Two", "name": "two"},
                ],
            }
        )
    )
    assert [item.identifier for item in limited_components.components] == ["SPDXRef-One"]
    assert "Component limit reached" in limited_components.gaps

    gaps = []
    missing_version = subject._spdx({}, gaps)  # noqa: SLF001 - format parser fallback contract
    assert missing_version.spec_version == "unknown"
    assert gaps == ["Missing or invalid SPDX spdxVersion"]


def test_relation_helpers_enforce_population_caps_before_append(monkeypatch):
    monkeypatch.setattr(subject, "MAX_RELATIONS", 1)
    relation = subject.ProvenanceRelation("one", "two", "depends_on")
    relations = [relation]
    gaps = []
    assert (
        subject._append_relation(  # noqa: SLF001 - defensive parser budget boundary
            relation, relations, {"one", "two"}, gaps
        )
        is False
    )
    assert relations == [relation]
    assert gaps == ["Relationship limit reached"]

    monkeypatch.setattr(subject, "MAX_COMPONENTS", 1)
    entries = subject._cyclonedx_entries(  # noqa: SLF001 - bounded traversal contract
        {
            "components": [
                {"bom-ref": "one", "name": "one"},
                {"bom-ref": "two", "name": "two"},
                {"bom-ref": "three", "name": "three"},
            ]
        },
        gaps := [],
    )
    assert len(entries) == 2
    assert gaps == ["Component limit reached"]


def test_document_and_binding_exact_boundaries(monkeypatch):
    monkeypatch.setattr(subject, "MAX_DOCUMENT_CHARS", 2)
    with pytest.raises(ValueError, match="Unsupported structured provenance"):
        subject.parse_provenance_json("{}")

    component = subject.ProvenanceComponent(
        "brotli", "library", "brotli", None, None, (), "name_only"
    )
    binding = subject.bind_component_hash(component, "a" * 64)
    assert binding.evidence_strength == "unresolved"
    assert binding.gap == "Component has no declared SHA-256 to bind to the artifact"
