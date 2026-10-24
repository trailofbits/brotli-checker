import gzip
import struct
from pathlib import Path

import brotli_binary_match as matcher
import brotli_binary_triage as triage
import brotli_inventory as scanner
import pytest
from test_binary_match import elf, reference, write_catalog


@pytest.mark.parametrize("identity", matcher.TARGETS, ids=lambda key: matcher.TARGETS[key][0])
@pytest.mark.parametrize("state", ["fixed", "vulnerable"])
def test_architecture_matching_and_disassembly_scope(identity, state, tmp_path):
    machine, bits, byteorder = identity
    entry = {**reference(state, machine), "elf_class": bits, "byteorder": byteorder}
    data = elf(bytes.fromhex(entry["code"]), machine, elf_class=bits, byteorder=byteorder)
    assert matcher.target_identity(matcher.elf_header(data)) == identity
    refs = [matcher.CodeReference.from_json(entry)]
    assert scanner.assess_binary(data, refs)["patch_status"] == state + "_code_match"
    report = {"tool": {"fragments": []}}
    command = triage.fragment_command(
        report, data, tmp_path, Path("/trusted/objdump"), 0x401000, 0x401200
    )
    assert f"--architecture={matcher.TARGETS[identity][1]}" in command
    assert f"--endian={byteorder}" in command
    assert Path(command[-1]).read_bytes() == bytes.fromhex(entry["code"])


@pytest.mark.parametrize(
    ("machine", "bits", "byteorder"), [(8, 32, "big"), (8, 64, "big"), (243, 32, "little")]
)
def test_reference_identity_includes_byte_order_and_word_size(machine, bits, byteorder):
    ref = matcher.CodeReference.from_json(
        {**reference(machine=machine), "elf_class": 64, "byteorder": "little"}
    )
    result = matcher.match_code(elf(ref.code, machine, elf_class=bits, byteorder=byteorder), [ref])
    assert result.patch_status == "unknown"
    assert result.limited
    assert "No compiled references" in result.reason


@pytest.mark.parametrize(
    ("machine", "kind", "mask"),
    [
        (3, 43, "00000000"),
        (40, 10, "c000f800"),
        (40, 43, "fff0f000"),
        (8, 4, "fc000000"),
        (8, 37, "00000000"),
        (21, 64, "0003"),
        (22, 19, "00000000"),
        (243, 19, "000fffff00000fff"),
        (258, 71, "fe00001f"),
        (258, 72, "ffc003ff"),
    ],
)
def test_known_abi_relocation_fields(machine, kind, mask):
    assert matcher.relocation_mask(machine, kind, "big").hex() == mask
    assert matcher.relocation_mask(machine, kind, "little").hex() == bytes.fromhex(mask)[::-1].hex()
    with pytest.raises(ValueError, match="Unsupported executable relocation"):
        matcher.relocation_mask(machine, 9999)


def test_split_decoder_requires_every_executable_section():
    entry = {
        **reference(),
        "additional_sections": [{"code": b"cold error helper".hex(), "mask": "ff" * 17}],
    }
    ref = matcher.CodeReference.from_json(entry)
    assert ref.to_json() == entry
    for suffix, status in [
        (b"", "unknown"),
        (b"cold error helper", "fixed_code_match"),
        (b"cold error helpeX", "unknown"),
    ]:
        assert matcher.match_code(elf(ref.code + suffix), [ref]).patch_status == status


def test_gzip_catalog_limits_apply_after_decompression(tmp_path, monkeypatch):
    path = write_catalog(tmp_path, [reference()])
    raw = path.read_bytes()
    path.write_bytes(gzip.compress(raw))
    monkeypatch.setattr(matcher, "MAX_REFERENCE_BYTES", len(raw))
    assert matcher.load_references(path)[0].metadata["state"] == "fixed"
    monkeypatch.setattr(matcher, "MAX_REFERENCE_BYTES", len(raw) - 1)
    with pytest.raises(ValueError, match="uncompressed byte limit"):
        matcher.load_references(path)
    path.write_bytes(gzip.compress(raw)[:-4])
    monkeypatch.setattr(matcher, "MAX_REFERENCE_BYTES", len(raw) + 1)
    with pytest.raises(ValueError, match="compressed catalog"):
        matcher.load_references(path)


@pytest.mark.parametrize(
    "change",
    [
        {"elf_class": []},
        {"elf_class": 64.0},
        {"byteorder": []},
        {"additional_sections": [None]},
        {"additional_sections": [{"state": "fixed"}]},
    ],
)
def test_malformed_reference_architecture_and_sections_are_rejected(change):
    with pytest.raises(ValueError, match="Invalid"):
        matcher.CodeReference.from_json({**reference(), **change})


def object_with_relocation(identity, kind, code, offset=128, *, rela=True):
    machine, bits, byteorder = identity
    order = "<" if byteorder == "little" else ">"
    small = bits == 32
    header = struct.Struct(order + ("16sHHIIIIIHHHHHH" if small else "16sHHIQQQIHHHHHH"))
    section = struct.Struct(order + ("IIIIIIIIII" if small else "IIQQQQIIQQ"))
    relocation = struct.Struct(order + (("II" if small else "QQ") + ("i" if small else "q") * rela))
    info = kind
    if machine == 8 and not small:
        info = int.from_bytes(bytes(7) + bytes([kind]), byteorder)
    relocation_bytes = relocation.pack(offset, info, *([0] if rela else []))
    section_offset = header.size + len(code) + relocation.size
    sections = [
        (0,) * 10,
        (0, 1, 6, 0, header.size, len(code), 0, 0, 4, 0),
        (
            0,
            4 if rela else 9,
            0,
            0,
            header.size + len(code),
            relocation.size,
            0,
            1,
            4,
            relocation.size,
        ),
    ]
    ident = b"\x7fELF" + bytes((1 if small else 2, 1 if byteorder == "little" else 2, 1)) + bytes(9)
    return (
        header.pack(
            ident, 1, machine, 1, 0, 0, section_offset, 0, header.size, 0, 0, section.size, 3, 0
        )
        + code
        + relocation_bytes
        + b"".join(section.pack(*row) for row in sections)
    )


@pytest.mark.parametrize("identity", matcher.TARGETS)
@pytest.mark.parametrize("rela", [False, True])
def test_elf_tables_and_object_relocations_across_layouts(identity, rela):
    machine, bits, byteorder = identity
    order, small = "<" if byteorder == "little" else ">", bits == 32
    kind = {3: 2, 8: 2, 21: 1, 22: 4, 40: 2, 62: 2, 183: 283, 243: 23, 258: 1}[machine]
    code = bytes.fromhex(reference()["code"])
    data = object_with_relocation(identity, kind, code, rela=rela)
    generated = matcher.reference_from_object(data, reference())
    field = {183: "fc000000", 243: "00000fff"}.get(machine, "00000000")
    expected = bytes.fromhex(field)
    if byteorder == "little":
        expected = expected[::-1]
    assert bytes.fromhex(generated["mask"]) == b"\xff" * 128 + expected + b"\xff" * 380
    assert generated["code"] == code.hex()
    assert (generated["machine"], generated["elf_class"], generated["byteorder"]) == identity
    symbol = struct.pack(
        order + ("IIIBBH" if small else "IBBHQQ"),
        *((7, 0x1234, 17, 18, 0, 1) if small else (7, 18, 0, 1, 0x1234, 17)),
    )
    assert list(
        matcher.symbol_rows(symbol, matcher.elf_header(data), (0, 0, 0, 0, 0, len(symbol)))
    ) == [(7, 18, 0, 1, 0x1234, 17)]


@pytest.mark.parametrize(
    ("identity", "kind", "instruction", "field_offset", "expected"),
    [
        ((3, 32, "little"), 43, "8b0500000000", 2, "000000000000"),
        ((3, 32, "little"), 43, "030500000000", 2, "000000000000"),
        ((3, 32, "little"), 43, "ff1500000000", 2, "000000000000"),
        ((62, 64, "little"), 42, "488b0500000000", 3, "00000000000000"),
        ((62, 64, "little"), 41, "ff1500000000", 2, "000000000000"),
        ((22, 64, "big"), 26, "c41800000000", 2, "fbf700000000"),
        ((40, 32, "little"), 28, "000000eb", 0, "0000000e"),
        ((21, 64, "little"), 64, "000062e8", 0, "0000e003"),
        ((21, 64, "big"), 64, "e8620000", 2, "03e00000"),
        ((21, 64, "little"), 48, "00006238", 0, "0000e0ff"),
        ((21, 64, "big"), 50, "3c620000", 2, "00000000"),
        ((21, 64, "little"), 252, "00004c3c", 0, "0000e0ff"),
        ((21, 64, "big"), 10, "4800000160000000", 0, "fc00000300000000"),
        ((21, 64, "big"), 10, "4800000112345678", 0, "fc000003ffffffff"),
    ],
)
def test_linker_rewrite_fields_keep_surrounding_code(
    identity, kind, instruction, field_offset, expected
):
    code = bytearray.fromhex(reference()["code"])
    instruction = bytes.fromhex(instruction)
    code[128 : 128 + len(instruction)] = instruction
    obj = object_with_relocation(identity, kind, bytes(code), 128 + field_offset)
    mask = bytes.fromhex(matcher.reference_from_object(obj, reference())["mask"])
    assert mask == b"\xff" * 128 + bytes.fromhex(expected) + b"\xff" * (384 - len(instruction))


@pytest.mark.parametrize("byteorder", ["little", "big"])
@pytest.mark.parametrize(
    ("suffix", "answer"),
    [("00051807", 5), ("00061807", 6), ("01051807", None), ("00071807", None), ("000518ff", None)],
)
def test_mips64_compound_relocation_known_answers(byteorder, suffix, answer):
    info = int.from_bytes(bytes(4) + bytes.fromhex(suffix), byteorder)
    if answer is None:
        with pytest.raises(ValueError, match="compound MIPS64"):
            matcher.mips64_relocation(info, byteorder)
    else:
        assert matcher.mips64_relocation(info, byteorder) == answer


def test_thumb_mode_is_explicit_and_arm_only(tmp_path):
    data = elf(b"code" * 64, 40, elf_class=32)
    command = triage.fragment_command(
        {"tool": {"fragments": []}},
        data,
        tmp_path,
        Path("/trusted/objdump"),
        0x401000,
        0x401010,
        thumb=True,
    )
    assert "--disassembler-options=force-thumb" in command
    with pytest.raises(triage.TriageError, match="ARM ELF"):
        triage.fragment_command(
            {"tool": {"fragments": []}},
            elf(b"code" * 64),
            tmp_path,
            Path("/trusted/objdump"),
            0x401000,
            0x401010,
            thumb=True,
        )


@pytest.mark.parametrize(("machine", "kind"), [(243, 51), (258, 100)])
def test_size_changing_relaxation_relocations_require_no_relax(machine, kind):
    with pytest.raises(ValueError, match="Unsupported executable relocation"):
        matcher.relocation_mask(machine, kind)


def test_missing_split_section_stops_duplicate_primary_search(monkeypatch):
    ref = matcher.CodeReference.from_json(
        {**reference(), "additional_sections": [{"code": "aabbcc", "mask": "ffffff"}]}
    )
    monkeypatch.setattr(matcher, "MAX_CANDIDATES", 2)
    result = matcher.match_code(elf(ref.code * 3), [ref])
    assert result.patch_status == "unknown"
    assert not result.limited
