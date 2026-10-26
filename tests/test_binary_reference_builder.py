import copy
import gzip
import hashlib
import runpy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUILDER = runpy.run_path(str(ROOT / "scripts/build_binary_references.py"))
load_references = BUILDER["load_references"]
main = BUILDER["main"]
scoped_reference_id = BUILDER["scoped_reference_id"]
unique_references = BUILDER["unique_references"]
write_validated_catalog = BUILDER["write_validated_catalog"]


def reference(identifier: str = "fixture") -> dict:
    code = bytes(range(256))
    return {
        "id": identifier,
        "state": "fixed",
        "machine": 183,
        "source_sha256": hashlib.sha256(b"source").hexdigest(),
        "object_sha256": hashlib.sha256(b"object").hexdigest(),
        "source": "test fixture",
        "compiler": "test compiler",
        "flags": "-O2",
        "code": code.hex(),
        "mask": (b"\xff" * len(code)).hex(),
    }


def test_identical_generated_references_are_deduplicated():
    entry = reference()
    assert unique_references([entry, copy.deepcopy(entry)]) == [entry]


def test_conflicting_generated_reference_ids_are_rejected():
    first = reference()
    second = {**first, "object_sha256": hashlib.sha256(b"different").hexdigest()}
    with pytest.raises(ValueError, match="Conflicting generated code reference id"):
        unique_references([first, second])


def test_subset_reference_id_is_scope_qualified_without_changing_legacy_ids():
    entry = reference("source-profile")
    entry.update(elf_class=64, byteorder="little")
    assert scoped_reference_id(entry) == "183:64:little:source-profile"
    entry["code_scope"] = "patch_bearing_sections_v1"
    assert scoped_reference_id(entry) == (
        "183:64:little:source-profile:scope=patch_bearing_sections_v1"
    )


def test_repeated_trees_and_profiles_produce_one_valid_reference(tmp_path, monkeypatch):
    entry = reference()

    def build(trees, compiler, flags):
        del compiler, flags
        return {"schema_version": 1, "references": [copy.deepcopy(entry) for _ in trees]}

    output = tmp_path / "references.json"
    monkeypatch.setitem(main.__globals__, "build_references", build)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "build_binary_references.py",
            "tree",
            "tree",
            "--cflags=-O2",
            "--cflags=-O2",
            "--build-note=trusted fixture headers",
            "--output",
            str(output),
        ],
    )
    assert main() == 0
    assert [item.metadata["id"] for item in load_references(output)] == [entry["id"]]
    assert load_references(output)[0].metadata["build_note"] == "trusted fixture headers"


def test_conflicting_profile_preserves_existing_output(tmp_path, monkeypatch):
    first = reference()
    second = {**first, "object_sha256": hashlib.sha256(b"different").hexdigest()}
    outputs = iter(([first], [second]))

    def build(trees, compiler, flags):
        del trees, compiler, flags
        return {"schema_version": 1, "references": next(outputs)}

    output = tmp_path / "references.json"
    output.write_text("existing catalog\n")
    monkeypatch.setitem(main.__globals__, "build_references", build)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "build_binary_references.py",
            "tree",
            "--cflags=-O2",
            "--cflags=-O3",
            "--output",
            str(output),
        ],
    )
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
    assert output.read_text() == "existing catalog\n"


def test_consumer_validation_precedes_output_replacement(tmp_path):
    output = tmp_path / "references.json"
    output.write_text("existing catalog\n")
    invalid = reference()
    invalid["mask"] = (b"\0" * 256).hex()
    with pytest.raises(ValueError, match="masks too much"):
        write_validated_catalog(
            output,
            {"schema_version": 1, "references": [invalid]},
        )
    assert output.read_text() == "existing catalog\n"
    assert list(tmp_path.glob(".references.json.*.tmp")) == []


def test_merge_preserves_sections_and_writes_deterministic_gzip(tmp_path, monkeypatch):
    entry = {**reference(), "additional_sections": [{"code": "c3", "mask": "ff"}]}
    first, output = tmp_path / "first.json", tmp_path / "merged.json.gz"
    write_validated_catalog(first, {"schema_version": 1, "references": [entry]})
    monkeypatch.setattr(
        sys,
        "argv",
        ["builder", "--merge", str(first), "--merge", str(first), "--output", str(output)],
    )
    assert main() == 0
    assert [ref.to_json() for ref in load_references(output)] == [entry]
    compressed = output.read_bytes()
    assert compressed[:10] == bytes.fromhex("1f8b08000000000002ff")
    assert gzip.decompress(compressed).endswith(b"\n")
    assert main() == 0
    assert output.read_bytes() == compressed
