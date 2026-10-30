import hashlib
import json
import runpy

import brotli_binary_inventory as binary_inventory
import brotli_inventory as inventory
import brotli_native_artifacts as subject
import pytest

IMPORTER = runpy.run_path("scripts/import_native_artifacts.py")


def provenance(state="fixed"):
    source = (
        "8d7beeafed5ff9f3f00f6e528e92ad6a36059b3549356bed5a9ca3ee16938438"
        if state == "fixed"
        else "f7749b1296128c0add4eaa454b9d82ee1c7b0451c1c9ed47d96733e6de6f2d7b"
    )
    return {
        "id": "profile",
        "format": "pe",
        "abi": "windows",
        "machine": 62,
        "elf_class": 64,
        "byteorder": "little",
        "source": "https://example.test/decode.c",
        "source_sha256": source,
        "headers_sha256": "a" * 64,
        "object_sha256": "b" * 64,
        "compiler": "fixture compiler",
        "flags": "/O2 /Gy",
        "build_note": "reviewed paired fixture",
        "source_state": state,
    }


def assertion(data=b"known binary", state="fixed"):
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "patch_status": f"{state}_code_match",
        "method": "paired_native_build_exact_artifact",
        "negative_control": "opposite_source_state_rejected",
        "provenance": [provenance(state)],
    }


def catalog(value):
    return {
        "schema_version": 1,
        "artifacts": [
            {
                **value,
                "artifact_name": "brotlidec.dll",
                "build_run_url": "https://github.com/trailofbits/brotli-checker/actions/runs/1",
                "build_commit": "c" * 40,
            }
        ],
    }


def matched(*_args):
    return catalog(assertion())["artifacts"][0]


def test_packaged_catalog_has_six_reviewed_exact_native_artifacts():
    actual = subject.load_native_artifacts()
    assert len(actual) == 6
    assert {item["patch_status"] for item in actual.values()} == {
        "fixed_code_match",
        "vulnerable_code_match",
    }
    assert {item["provenance"][0]["format"] for item in actual.values()} == {"pe", "mach_o"}
    assert all(item["method"] == "paired_native_build_exact_artifact" for item in actual.values())


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda row: row.update(size=0), "assertion"),
        (lambda row: row.update(method="flirt"), "assertion"),
        (lambda row: row.update(patch_status=[]), "assertion"),
        (lambda row: row["provenance"][0].update(source_state="vulnerable"), "disagrees"),
        (lambda row: row["provenance"][0].update(format=[]), "target"),
        (lambda row: row["provenance"][0].update(source_sha256="d" * 64), "reviewed"),
        (lambda row: row.update(build_commit="A" * 40), "identity"),
        (
            lambda row: row.update(
                build_run_url=("https://github.com/trailofbits/brotli-checker/actions/runs/1/x")
            ),
            "assertion",
        ),
    ],
    ids=("empty", "method", "status-type", "state", "format-type", "source", "commit", "run"),
)
def test_catalog_rejects_unqualified_or_inconsistent_assertions(tmp_path, change, message):
    document = catalog(assertion())
    change(document["artifacts"][0])
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match=message):
        subject.load_native_artifacts(path)


def test_catalog_rejects_boolean_schema_version(tmp_path):
    document = catalog(assertion())
    document["schema_version"] = True
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="schema"):
        subject.load_native_artifacts(path)


def test_exact_artifact_match_requires_digest_and_size(monkeypatch):
    evidence = catalog(assertion())["artifacts"][0]
    monkeypatch.setattr(
        subject, "packaged_native_artifacts", lambda: {evidence["sha256"]: evidence}
    )
    assert subject.native_artifact_match(evidence["sha256"], evidence["size"]) == evidence
    assert subject.native_artifact_match(evidence["sha256"], evidence["size"] + 1) is None
    assert subject.native_artifact_match("0" * 64, evidence["size"]) is None


def test_cli_reports_invalid_packaged_catalog(tmp_path, monkeypatch, capsys):
    def invalid_catalog():
        message = "invalid native artifact fixture"
        raise ValueError(message)

    monkeypatch.setattr(inventory, "packaged_native_artifacts", invalid_catalog)
    assert inventory.main([str(tmp_path)]) == 2
    assert "invalid native artifact fixture" in capsys.readouterr().err

    monkeypatch.setattr(binary_inventory, "packaged_native_artifacts", invalid_catalog)
    with pytest.raises(SystemExit) as error:
        binary_inventory.main([str(tmp_path)])
    assert error.value.code == 2
    assert "invalid native artifact fixture" in capsys.readouterr().err


def test_assessment_promotes_only_exact_whole_artifact(monkeypatch):
    evidence = catalog(assertion())["artifacts"][0]
    monkeypatch.setattr(inventory, "native_artifact_match", matched)
    result = inventory.assess_binary(b"known binary", [], digest=evidence["sha256"])
    assert result["kind"] == "exact_native_artifact_match"
    assert result["patch_status"] == "fixed_code_match"
    assert result["native_artifact"] == evidence
    assert result["detection_status"] == "decoder_code_identified"
    assert result["linkage"] == "embedded_code"


def test_both_inventory_paths_preserve_exact_native_provenance(monkeypatch):
    evidence = catalog(assertion())["artifacts"][0]
    monkeypatch.setattr(inventory, "native_artifact_match", matched)
    monkeypatch.setattr(binary_inventory, "assess_binary", inventory.assess_binary)
    main = inventory.Inventory({"fingerprints": []}, None, None, 10, 0, code_references=[])
    main.inspect(b"known binary", "brotlidec.dll", 0)
    assert main.findings[0]["patch_status"] == "fixed_code_match"
    assert main.findings[0]["evidence"]["native_artifact"] == evidence
    binary = binary_inventory.BinaryInventory(
        {}, [], max_file_bytes=None, max_total_bytes=None, max_files=10, archive_depth=0
    )
    binary.inspect(b"known binary", "brotlidec.dll", 0)
    assert binary.findings[0]["kind"] == "exact_native_artifact_match"
    assert binary.findings[0]["patch_status"] == "fixed_code_match"
    assert binary.findings[0]["native_artifact"] == evidence


def test_importer_rejects_unreviewed_source_state_before_writing(tmp_path, monkeypatch):
    data = b"known binary"
    artifact = tmp_path / "brotlidec.dll"
    artifact.write_bytes(data)
    row = assertion(data)
    row["provenance"][0]["source_sha256"] = "d" * 64
    pair = tmp_path / "pair.json"
    pair.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "affected_match_count": 1,
                "fixed_match_count": 1,
                "opposite_state_controls": "rejected",
                "exact_artifact_assertions": [row, assertion(b"other", "vulnerable")],
            }
        )
    )
    output = tmp_path / "catalog.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "import_native_artifacts.py",
            "--pair",
            str(pair),
            "--artifact",
            str(artifact),
            "--build-run-url",
            "https://github.com/trailofbits/brotli-checker/actions/runs/1",
            "--build-commit",
            "c" * 40,
            "--output",
            str(output),
        ],
    )
    with pytest.raises(SystemExit):
        IMPORTER["main"]()
    assert not output.exists()


def test_importer_writes_only_a_valid_exact_artifact_catalog(tmp_path, monkeypatch):
    vulnerable = tmp_path / "vulnerable.dll"
    fixed = tmp_path / "fixed.dll"
    vulnerable.write_bytes(b"vulnerable native fixture")
    fixed.write_bytes(b"fixed native fixture")
    pair = tmp_path / "pair.json"
    pair.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "affected_match_count": 1,
                "fixed_match_count": 1,
                "opposite_state_controls": "rejected",
                "exact_artifact_assertions": [
                    assertion(vulnerable.read_bytes(), "vulnerable"),
                    assertion(fixed.read_bytes(), "fixed"),
                ],
            }
        )
    )
    output = tmp_path / "catalog.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "import_native_artifacts.py",
            "--pair",
            str(pair),
            "--artifact",
            str(vulnerable),
            "--artifact",
            str(fixed),
            "--build-run-url",
            "https://github.com/trailofbits/brotli-checker/actions/runs/1",
            "--build-commit",
            "c" * 40,
            "--output",
            str(output),
        ],
    )
    assert IMPORTER["main"]() == 0
    actual = subject.load_native_artifacts(output)
    assert len(actual) == 2
    assert {item["artifact_name"] for item in actual.values()} == {
        "fixed.dll",
        "vulnerable.dll",
    }
