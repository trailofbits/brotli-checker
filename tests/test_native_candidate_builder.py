import hashlib
import json
import runpy
from pathlib import Path

import pytest
from brotli_binary_signatures import CODE_LENGTH_TABLES, command_table
from test_binary_signatures import mach_data, mach_fat, pe_data

ROOT = Path(__file__).resolve().parents[1]
BUILDER = runpy.run_path(str(ROOT / "scripts/record_native_candidate.py"))
candidate_manifest = BUILDER["candidate_manifest"]


def source_tree(tmp_path, monkeypatch, *, reviewed=True):
    tree = tmp_path / ("brotli" if reviewed else "unknown-brotli")
    source = tree / "c/dec/decode.c"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"reviewed decoder" if reviewed else b"unknown decoder")
    (tree / "c/include/brotli").mkdir(parents=True, exist_ok=True)
    (tree / "c/include/brotli/decode.h").write_bytes(b"header")
    registry = tmp_path / "skills/brotli-checker/references/fingerprints.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(
        json.dumps(
            {
                "fingerprints": [
                    {
                        "sha256": hashlib.sha256(b"reviewed decoder").hexdigest(),
                        "state": "vulnerable",
                        "sources": [{"url": "https://example.invalid/decode.c"}],
                    }
                ]
            }
        )
    )
    monkeypatch.setitem(candidate_manifest.__globals__, "ROOT", tmp_path)
    return tree


def decoder_tables():
    return command_table("<") + b"\0".join(CODE_LENGTH_TABLES.values())


@pytest.mark.parametrize(
    "binary",
    [
        pytest.param(pe_data(decoder_tables()), id="pe"),
        pytest.param(
            mach_fat(mach_data(decoder_tables()), mach_data(decoder_tables())),
            id="mach-universal",
        ),
    ],
)
def test_native_candidate_records_provenance_without_patch_promotion(tmp_path, monkeypatch, binary):
    tree = source_tree(tmp_path, monkeypatch)
    object_path = tmp_path / "decode.obj"
    object_path.write_bytes(b"object")

    result = candidate_manifest(binary, tree, "native compiler", "-O2", (object_path,))

    assert result["source_state_provenance"] == "vulnerable"
    assert result["target_patch_status"] == "unknown"
    assert result["compiler"] == "native compiler"
    assert result["objects"][0]["sha256"] == hashlib.sha256(b"object").hexdigest()
    expected = sorted({"command_lut_le", *CODE_LENGTH_TABLES})
    assert all(row["signature_ids"] == expected for row in result["decoder_tables"])


def test_native_candidate_rejects_unreviewed_source_and_non_native_target(tmp_path, monkeypatch):
    unknown = source_tree(tmp_path, monkeypatch, reviewed=False)
    with pytest.raises(ValueError, match="not uniquely reviewed"):
        candidate_manifest(pe_data(decoder_tables()), unknown, "compiler", "-O2")
    reviewed = source_tree(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="unsupported linked format"):
        candidate_manifest(b"\x7fELF" + bytes(128), reviewed, "compiler", "-O2")
