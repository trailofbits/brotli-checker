import contextlib
import hashlib
import io
import json
import runpy
import struct
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/brotli-checker/scripts"
sys.path.insert(0, str(SCRIPTS))
import brotli_binary_match as matcher  # noqa: E402
from test_binary_inventory import run_scan  # noqa: E402


def reference(state="fixed", machine=183, salt=b"fixed"):
    code = b"".join(hashlib.sha256(salt + bytes([i])).digest() for i in range(16))
    return {
        "id": state + salt.hex(),
        "state": state,
        "machine": machine,
        "source_sha256": "a" * 64,
        "object_sha256": "b" * 64,
        "source": "test fixture, not a Brotli signature",
        "compiler": "fixture",
        "flags": "fixture",
        "code": code.hex(),
        "mask": (b"\xff" * len(code)).hex(),
    }


def elf(payload, machine=183, *, flags=5, kind=2, prefix=b"", elf_class=64, byteorder="little"):  # noqa: PLR0913 -- Independent ELF fixture controls.
    order = "<" if byteorder == "little" else ">"
    header_struct = struct.Struct(
        order + ("16sHHIQQQIHHHHHH" if elf_class == 64 else "16sHHIIIIIHHHHHH")
    )
    program_struct = struct.Struct(order + ("IIQQQQQQ" if elf_class == 64 else "IIIIIIII"))
    header = header_struct.pack(
        b"\x7fELF"
        + bytes((2 if elf_class == 64 else 1, 1 if byteorder == "little" else 2, 1))
        + bytes(9),
        kind,
        machine,
        1,
        0,
        header_struct.size,
        0,
        0,
        header_struct.size,
        program_struct.size,
        1,
        0,
        0,
        0,
    )
    contents = prefix + payload
    fields = (
        1,
        flags,
        len(header) + program_struct.size,
        0x401000,
        0x401000,
        len(contents),
        len(contents),
        1,
    )
    if elf_class == 32:
        fields = (fields[0], *fields[2:6], fields[6], fields[1], fields[7])
    program = program_struct.pack(*fields)
    return header + program + contents


def write_catalog(tmp_path, entries):
    path = tmp_path / "references.json"
    path.write_text(json.dumps({"schema_version": 1, "references": entries}))
    return path


@pytest.mark.parametrize("state", ["fixed", "vulnerable"])
@pytest.mark.parametrize("machine", [62, 183])
@pytest.mark.parametrize("kind", [2, 3])
def test_stripped_embedded_code_and_shifted_layout(tmp_path, state, machine, kind):
    entry = reference(state, machine)
    path = tmp_path / "service"
    path.write_bytes(
        elf(bytes.fromhex(entry["code"]), machine, kind=kind, prefix=b"other code" * 37)
    )
    catalog = write_catalog(tmp_path, [entry])
    result = run_scan(path, "--code-references", catalog)
    finding = json.loads(result.stdout)["findings"][0]
    assert result.returncode == 1
    assert finding["patch_status"] == state + "_code_match"
    assert finding["indicators"] == []
    assert finding["linkage"] == "embedded_code"
    assert finding["code_matches"][0]["file_offset"] == 120 + 370
    assert finding["code_matches"][0]["source_sha256"] == entry["source_sha256"]


def test_only_relocation_bits_are_ignored():
    entry = reference()
    mask = bytearray.fromhex(entry["mask"])
    mask[128:132] = matcher.relocation_mask(183, 283)
    entry["mask"] = mask.hex()
    ref = matcher.CodeReference.from_json(entry)
    code = bytearray(ref.code)
    code[128] ^= 0xFF
    assert matcher.match_code(elf(code), [ref]).matches
    code[131] ^= 0x80  # Change opcode, not the relocated branch displacement.
    assert not matcher.match_code(elf(code), [ref]).matches


@pytest.mark.parametrize(
    "variant", ["data", "overlay", "wrong_arch", "truncated_code", "modified", "import"]
)
def test_negative_code_evidence(variant):
    entry = reference()
    ref = matcher.CodeReference.from_json(entry)
    code = ref.code
    data = {
        "data": elf(code, flags=4),
        "overlay": elf(b"unrelated instructions") + code,
        "wrong_arch": elf(code, machine=62),
        "truncated_code": elf(code[:-1]),
        "modified": elf(code[:-1] + bytes([code[-1] ^ 1])),
        "import": elf(b"BrotliDecoderDecompress\0"),
    }[variant]
    assessment = matcher.match_code(data, [ref])
    assert not assessment.matches
    assert assessment.reason


def test_mixed_copies_are_not_fixed(tmp_path):
    entries = [reference(), reference("vulnerable", salt=b"old")]
    data = elf(b"padding".join(bytes.fromhex(e["code"]) for e in entries))
    path = tmp_path / "app"
    path.write_bytes(data)
    result = run_scan(path, "--code-references", write_catalog(tmp_path, entries))
    finding = json.loads(result.stdout)["findings"][0]
    assert finding["patch_status"] == "mixed_code_matches"
    assert len(finding["code_matches"]) == 2


@pytest.mark.parametrize(
    "data",
    [b"", b"\x7fELF", elf(b"x", machine=3), elf(b"x", kind=1), elf(b"x")[:80], elf(b"x")[:-1]],
)
def test_bad_or_unsupported_elf_is_unknown(data):
    assessment = matcher.match_code(data, [])
    assert not assessment.matches
    assert assessment.reason


def test_invalid_program_tables():
    for offset, value in ((54, 0), (56, 0xFFFF), (56, 0)):
        data = bytearray(elf(b"code"))
        struct.pack_into("<H", data, offset, value)
        with pytest.raises(ValueError, match="program header"):
            matcher.executable_ranges(bytes(data))
    data = bytearray(elf(b"code"))
    struct.pack_into("<Q", data, 64 + 40, 1)
    with pytest.raises(ValueError, match="memory size"):
        matcher.executable_ranges(bytes(data))


@pytest.mark.parametrize(
    "change",
    [
        {"id": ""},
        {"state": "maybe"},
        {"machine": 0},
        {"machine": []},
        {"source_sha256": "x" * 64},
        {"code": "no hex"},
        {"code": None},
        {"mask": "ff"},
        {"mask": "00" * 512},
        {"mask": "fe" * 512},
        {"flags": None},
    ],
)
def test_invalid_reference(change):
    with pytest.raises(ValueError, match="reference"):
        matcher.CodeReference.from_json({**reference(), **change})
    with pytest.raises(ValueError, match="reference"):
        matcher.CodeReference.from_json([])


@pytest.mark.parametrize(
    "catalog",
    [
        [],
        {},
        {"schema_version": 1, "references": []},
        {"schema_version": 2, "references": [reference()]},
    ],
)
def test_invalid_catalog_structure(tmp_path, catalog):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog))
    result = run_scan(tmp_path / "app", "--code-references", path)
    assert result.returncode == 2
    assert "references" in result.stderr


def test_duplicate_and_oversized_catalog(tmp_path):
    path = write_catalog(tmp_path, [reference(), reference()])
    with pytest.raises(ValueError, match="Duplicate"):
        matcher.load_references(path)
    with (
        patch.object(matcher, "MAX_REFERENCE_BYTES", 1),
        pytest.raises(ValueError, match="exceeds"),
    ):
        matcher.load_references(path)


def test_match_budgets_are_explicit():
    ref = matcher.CodeReference.from_json(reference())
    with patch.object(matcher, "MAX_MATCHES", 1):
        assessment = matcher.match_code(elf(ref.code * 2), [ref])
        assert len(assessment.matches) == 1
        assert assessment.limited
    with patch.object(matcher, "MAX_CANDIDATES", 1):
        assessment = matcher.match_code(elf((ref.code[:-1] + b"x") * 3), [ref])
        assert not assessment.matches
        assert assessment.limited


def relocatable(machine=183, relocation_kind=283):
    code = bytes.fromhex(reference()["code"])
    relocation = matcher.RELOCATION.pack(128, relocation_kind, 0)
    sections = [
        (0,) * 10,
        (0, 1, 6, 0, 64, len(code), 0, 0, 4, 0),
        (0, 4, 0, 0, 64 + len(code), 24, 0, 1, 8, 24),
    ]
    header = matcher.ELF_HEADER.pack(
        b"\x7fELF\x02\x01\x01" + bytes(9),
        1,
        machine,
        1,
        0,
        0,
        64 + len(code) + 24,
        0,
        64,
        0,
        0,
        64,
        len(sections),
        0,
    )
    return header + code + relocation + b"".join(matcher.SECTION_HEADER.pack(*s) for s in sections)


@pytest.mark.parametrize(
    ("machine", "kind"), [(62, 1), (62, 2), (62, 4), (183, 283), (183, 275), (183, 277)]
)
def test_reference_generation_preserves_nonrelocation_bits(machine, kind):
    obj = relocatable(machine, kind)
    generated = matcher.reference_from_object(bytes(obj), reference())
    mask = bytes.fromhex(generated["mask"])
    expected = matcher.relocation_mask(machine, kind)
    assert mask[:128] == b"\xff" * 128
    assert mask[128 : 128 + len(expected)] == expected
    assert mask[128 + len(expected) :] == b"\xff" * (512 - 128 - len(expected))
    assert generated["object_sha256"] == hashlib.sha256(obj).hexdigest()


def test_unsupported_object_relocations_and_layouts():
    with pytest.raises(ValueError, match="Unsupported executable relocation"):
        matcher.reference_from_object(relocatable(relocation_kind=999), reference())
    with pytest.raises(ValueError, match="relocatable"):
        matcher.reference_from_object(elf(b"code"), reference())
    obj = bytearray(relocatable())
    section_offset = matcher.elf_header(bytes(obj))[6]
    struct.pack_into("<Q", obj, section_offset + 64 + 8, 0)
    with pytest.raises(ValueError, match="one complete executable section"):
        matcher.reference_from_object(bytes(obj), reference())
    obj = bytearray(relocatable())
    struct.pack_into("<I", obj, section_offset + 128 + 4, 9)
    with pytest.raises(ValueError, match="RELA"):
        matcher.reference_from_object(bytes(obj), reference())
    obj = bytearray(relocatable())
    struct.pack_into("<Q", obj, section_offset + 128 + 32, 23)
    with pytest.raises(ValueError, match="Malformed relocation"):
        matcher.reference_from_object(bytes(obj), reference())


def test_packaged_references_are_reviewed_and_discriminating():
    refs = matcher.load_references(matcher.REFERENCES)
    source_registry = json.loads((matcher.REFERENCES.parent / "fingerprints.json").read_text())
    source_states = {e["sha256"]: e["state"] for e in source_registry["fingerprints"]}
    assert {r.metadata["state"] for r in refs} == {"fixed", "vulnerable"}
    for ref in refs:
        assert source_states[ref.metadata["source_sha256"]] == ref.metadata["state"]
        payload = ref.code + b"".join(part.code for part in ref.additional_sections)
        matches = matcher.match_code(
            elf(
                payload,
                ref.metadata["machine"],
                elf_class=ref.metadata.get("elf_class", 64),
                byteorder=ref.metadata.get("byteorder", "little"),
            ),
            refs,
        ).matches
        assert matches
        assert {m["state"] for m in matches} == {ref.metadata["state"]}


def test_reference_builder_rejects_unreviewed_source(tmp_path):
    tree = tmp_path / "source"
    (tree / "c/dec").mkdir(parents=True)
    (tree / "c/dec/decode.c").write_text("unreviewed")
    builder = SCRIPTS.parents[2] / "scripts/build_binary_references.py"
    stderr = io.StringIO()
    with (
        patch.object(sys, "argv", [str(builder), str(tree), "--output", str(tmp_path / "out")]),
        patch("shutil.which", return_value="cc"),
        patch("subprocess.check_output", return_value="test compiler\n"),
        contextlib.redirect_stderr(stderr),
        pytest.raises(SystemExit) as result,
    ):
        runpy.run_path(str(builder), run_name="__main__")
    assert result.value.code == 2
    assert "Unreviewed decoder source" in stderr.getvalue()
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    ("states", "expected_code", "expected_status"),
    [
        (["fixed"], 3, "fixed_code_match"),
        (["vulnerable"], 1, "vulnerable_code_match"),
        (["fixed", "vulnerable"], 1, "mixed_code_matches"),
        ([], 3, "unknown"),
    ],
)
def test_normal_scanner_uses_code_matches(tmp_path, states, expected_code, expected_status):
    import brotli_inventory as scanner  # noqa: PLC0415 -- Exercise both public CLIs.

    entries = [reference(state, salt=state.encode()) for state in ("fixed", "vulnerable")]
    code = b"".join(bytes.fromhex(e["code"]) for e in entries if e["state"] in states)
    app = tmp_path / "app"
    app.write_bytes(elf(code or b"unknown instructions"))
    catalog = write_catalog(tmp_path, entries)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        status = scanner.main(
            [str(app), "--code-references", str(catalog), "--no-flirt", "--no-xrefs", "--json"]
        )
    report = json.loads(output.getvalue())
    assert status == expected_code
    finding = report["findings"][0]
    assert finding["patch_status"] == expected_status
    assert finding["reachability"] == "unknown"
    assert finding["exploitability"] == "not_assessed"
    text = scanner.render_text(report)
    assert "Brotli check:" in text
    if states:
        assert "decoder code matched" in text
        assert finding["evidence"]["code_matches"]
    if "vulnerable" in states:
        assert report["user_summary"]["status"] == "needs_attention"
    else:
        assert report["result"] == "review_required"


def test_normal_scanner_packaged_references_and_archive(tmp_path):
    import zipfile  # noqa: PLC0415

    import brotli_inventory as scanner  # noqa: PLC0415

    ref = matcher.load_references(matcher.REFERENCES)[0]
    data = elf(ref.code, ref.metadata["machine"])
    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("bin/service", data)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        scanner.main([str(archive), "--json"])
    report = json.loads(output.getvalue())
    assert report["findings"][0]["patch_status"] == ref.metadata["state"] + "_code_match"
    assert report["findings"][0]["path"].endswith("!bin/service")


def test_code_budget_is_a_scan_gap(tmp_path):
    entry = reference()
    artifact = tmp_path / "service"
    artifact.write_bytes(elf(bytes.fromhex(entry["code"])))
    catalog = write_catalog(tmp_path, [entry])
    with patch.object(matcher, "MAX_MATCHES", 1):
        result = run_scan(artifact, "--code-references", catalog)
    assert result.returncode == 3
    assert json.loads(result.stdout)["coverage"]["gap_count"] == 1


def test_elf_prefixed_zip_still_traverses_members(tmp_path):
    import zipfile  # noqa: PLC0415

    import brotli_inventory as scanner  # noqa: PLC0415

    entry = reference()
    path = tmp_path / "selfextract.zip"
    path.write_bytes(elf(b"unmatched outer executable"))
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("bin/inner", elf(bytes.fromhex(entry["code"])))
    catalog = write_catalog(tmp_path, [entry])
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert (
            scanner.main(
                [str(path), "--code-references", str(catalog), "--no-flirt", "--no-xrefs", "--json"]
            )
            == 3
        )
    report = json.loads(output.getvalue())
    assert report["findings"][-1]["patch_status"] == "fixed_code_match"
    assert report["findings"][-1]["path"].endswith("!bin/inner")
    assert report["coverage"]["gap_count"] == 0
