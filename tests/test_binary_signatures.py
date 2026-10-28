import contextlib
import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
from pathlib import Path

import brotli_binary_match as matcher
import brotli_binary_signatures as signatures
import brotli_inventory as scanner
import pytest
from brotli_binary_data import file_data
from test_binary_inventory import run_scan
from test_binary_match import elf, reference


def pe_data(payload, *, resource=b""):
    section_count = 1 + bool(resource)
    header_bytes = 0x200
    data_offset = header_bytes
    resource_offset = data_offset + len(payload)
    image = bytearray(resource_offset + len(resource))
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x8664, section_count, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", image, 0x98, 0x20B)
    struct.pack_into("<I", image, 0x98 + 108, 16)
    if resource:
        struct.pack_into("<II", image, 0x98 + 112 + 2 * 8, 0x2000, len(resource))
    section = 0x98 + 0xF0
    image[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", image, section + 8, len(payload), 0x1000, len(payload), data_offset)
    struct.pack_into("<I", image, section + 36, 0x40000040)
    if resource:
        section += 40
        image[section : section + 8] = b".rsrc\0\0\0"
        struct.pack_into(
            "<IIII", image, section + 8, len(resource), 0x2000, len(resource), resource_offset
        )
        struct.pack_into("<I", image, section + 36, 0x40000040)
    image[data_offset : data_offset + len(payload)] = payload
    image[resource_offset:] = resource
    return bytes(image)


def mach_data(payload, *, cpu=0x0100000C, initprot=1):
    data_offset = 0x100
    image = bytearray(data_offset + len(payload))
    command = struct.pack(
        "<II16sQQQQIIII",
        0x19,
        72,
        b"__DATA" + bytes(10),
        0x100000,
        len(payload),
        data_offset,
        len(payload),
        7,
        initprot,
        0,
        0,
    )
    struct.pack_into("<8I", image, 0, 0xFEEDFACF, cpu, 0, 6, 1, len(command), 0, 0)
    image[32 : 32 + len(command)] = command
    image[data_offset:] = payload
    return bytes(image)


def mach_fat(*slices):
    image = bytearray(0x100 + sum(map(len, slices)))
    image[:8] = b"\xca\xfe\xba\xbe" + struct.pack(">I", len(slices))
    offset = 0x100
    for index, child in enumerate(slices):
        struct.pack_into(">IIIII", image, 8 + index * 20, 0x0100000C, 0, offset, len(child), 0)
        image[offset : offset + len(child)] = child
        offset += len(child)
    return bytes(image)


def uleb(value):
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def wasm_data(payload, *, custom=b""):
    sections = []
    if custom:
        sections.append(b"\0" + uleb(len(custom)) + custom)
    segment = b"\x01\x01" + uleb(len(payload)) + payload
    sections.append(b"\x0b" + uleb(len(segment)) + segment)
    return b"\0asm\x01\0\0\0" + b"".join(sections)


@pytest.mark.parametrize(
    ("order", "digest"),
    [
        ("<", "fdbc5d5f207a43d34b26441e29b7024f4f3d00be66502d8a73233bcbe9f6c1b4"),
        (">", "68734cc6cd5855efe1e04a05b45b754871f1a3f127510c34bb57b6bacc81afa6"),
    ],
)
def test_command_table_matches_independently_serialized_upstream_initializer(order, digest):
    # Digests computed from all 704 literal rows in v1.2.1 prefix_inc.h, not this generator.
    assert hashlib.sha256(signatures.command_table(order)).hexdigest() == digest


@pytest.mark.parametrize("name", ["command_lut_le", "command_lut_be"])
def test_full_decoder_table_without_any_names_identifies_data_not_patch(name):
    data = elf(signatures.SIGNATURES[name])
    result = scanner.assess_binary(data, [])
    assert result["kind"] == "decoder_data_signature"
    assert result["detection_status"] == "decoder_tables_detected"
    assert result["patch_status"] == "unknown"
    assert result["recognition"]["scope"] == "elf_load_segments"
    assert result["recognition"]["matches"][0]["size_bytes"] == 5632
    assert result["code_matches"] == []


def test_all_three_code_length_tables_required_independent_of_order():
    tables = list(signatures.CODE_LENGTH_TABLES.values())
    for missing in range(3):
        payload = b"padding".join(table for i, table in enumerate(tables) if i != missing)
        assert not signatures.recognize_decoder_data(elf(payload))["matches"]
    result = signatures.recognize_decoder_data(elf(b"padding".join(reversed(tables))))
    assert {row["id"] for row in result["matches"]} == signatures.CODE_LENGTH_TABLES.keys()
    assert all(row["virtual_addresses"] for row in result["matches"])


def test_truncated_altered_and_appended_tables_do_not_match_loaded_data():
    table = signatures.SIGNATURES["command_lut_le"]
    for payload in (table[:64], table[:-1], table[:-1] + bytes([table[-1] ^ 1])):
        assert not signatures.recognize_decoder_data(elf(payload))["matches"]
    assert not signatures.recognize_decoder_data(elf(b"instructions") + table)["matches"]


@pytest.mark.parametrize(
    "artifact",
    [
        pe_data(signatures.SIGNATURES["command_lut_le"]),
        mach_data(signatures.SIGNATURES["command_lut_le"]),
        wasm_data(signatures.SIGNATURES["command_lut_le"]),
    ],
)
def test_non_elf_tables_require_validated_loader_data_ranges(artifact):
    result = signatures.recognize_decoder_data(artifact)
    assert result["matches"]
    assert result["scope"] == "loader_data_ranges"
    assert not result["limited"]


def test_pe_resource_and_certificate_lookalikes_are_not_decoder_data():
    table = signatures.SIGNATURES["command_lut_le"]
    resource = signatures.recognize_decoder_data(pe_data(b"ordinary data", resource=table))
    assert not resource["matches"]
    certificate = pe_data(b"ordinary data") + table
    assert not signatures.recognize_decoder_data(certificate)["matches"]


def test_mach_code_and_wasm_custom_lookalikes_are_not_decoder_data():
    table = signatures.SIGNATURES["command_lut_le"]
    assert not signatures.recognize_decoder_data(mach_data(table, initprot=5))["matches"]
    custom = uleb(4) + b"fake" + table
    assert not signatures.recognize_decoder_data(wasm_data(b"ordinary", custom=custom))["matches"]


def test_mach_universal_reports_each_matching_slice_without_cross_slice_state():
    table = signatures.SIGNATURES["command_lut_le"]
    result = signatures.recognize_decoder_data(mach_fat(mach_data(table), mach_data(table)))
    assert result["format"] == "mach_o_universal"
    assert [row["slice_index"] for row in result["matches"]] == [0, 1]
    assert result["matches"][0]["file_offset"] != result["matches"][1]["file_offset"]


def test_malformed_known_binary_is_incomplete_without_raw_byte_match():
    table = signatures.SIGNATURES["command_lut_le"]
    for magic in signatures.OTHER_BINARY_MAGICS:
        result = signatures.recognize_decoder_data(magic + table)
        assert not result["matches"]
        assert result["limited"]
        assert result["layout_gaps"]


def test_text_and_invalid_elf_do_not_gain_strong_recognition():
    table = signatures.SIGNATURES["command_lut_le"]
    assert not signatures.recognize_decoder_data(b"plain data" + table)["matches"]
    result = signatures.recognize_decoder_data(b"\x7fELF" + table)
    assert result["limited"]
    assert not result["matches"]


def test_chunk_boundary_and_sparse_access_preserve_offsets(tmp_path, monkeypatch):
    monkeypatch.setattr(signatures, "CHUNK_BYTES", 128)
    table = signatures.SIGNATURES["command_lut_be"]
    artifact = wasm_data(b"x" * (128 * 100 - 64) + table)
    path = tmp_path / "component.wasm"
    path.write_bytes(artifact)
    with path.open("rb") as stream, file_data(stream) as data:
        result = signatures.recognize_decoder_data(data)
    row = result["matches"][0]
    assert row["id"] == "command_lut_be"
    assert artifact[row["file_offset"] : row["file_offset"] + len(table)] == table
    assert row["format"] == "wasm"


def test_load_segment_beyond_six_gibibytes_skips_sparse_padding(tmp_path, monkeypatch):
    table = signatures.SIGNATURES["command_lut_le"]
    template = elf(table)
    header = matcher.elf_header(template)
    segment = next(matcher.program_headers(template, header))
    contents = bytearray(template)
    offset = 6 * 1024**3
    struct.pack_into("<Q", contents, header[5] + 8, offset)
    path = tmp_path / "large.elf"
    with path.open("wb") as stream:
        stream.write(contents[: segment[2]])
        stream.seek(offset)
        stream.write(table)
    original = os.pread
    reads = []

    def measured(fd, size, position):
        reads.append(size)
        assert sum(reads) < 32 * 1024, "Recognition must skip sparse padding"
        return original(fd, size, position)

    monkeypatch.setattr(os, "pread", measured)
    with path.open("rb") as stream, file_data(stream) as data:
        result = signatures.recognize_decoder_data(data)
    row = result["matches"][0]
    assert row["file_offset"] == offset
    assert row["virtual_addresses"] == [segment[3]]
    assert sum(reads) < 32 * 1024


def test_candidate_limit_reports_incomplete_and_retains_completed_evidence(monkeypatch):
    monkeypatch.setattr(signatures, "MAX_CANDIDATES", 4)
    table = signatures.SIGNATURES["command_lut_le"]
    payload = table + (signatures.SIGNATURES["command_lut_be"][:64] + b"x") * 8
    result = signatures.recognize_decoder_data(wasm_data(payload))
    assert result["limited"]
    assert result["matches"][0]["id"] == "command_lut_le"


def test_overlapping_ranges_are_scanned_once_without_stitching_tables(tmp_path, monkeypatch):
    path = tmp_path / "overlap"
    path.write_bytes(b"x" * 65536)
    original = os.pread
    reads = []

    def measured(fd, size, position):
        reads.append(size)
        assert sum(reads) <= 65536, "Overlapping ranges must not amplify reads"
        return original(fd, size, position)

    monkeypatch.setattr(os, "pread", measured)
    with path.open("rb") as stream, file_data(stream) as data:
        assert signatures.scan_tables(data, [(i, 65536 - i) for i in range(256)]) == ({}, False)
    assert sum(reads) <= 65536
    table = signatures.SIGNATURES["command_lut_le"]
    # Union reading is safe, but neither original mapping contains this full table.
    assert signatures.scan_tables(table, [(0, 100), (100, len(table) - 100)]) == ({}, False)
    # An overlapping original mapping that contains it is sufficient.
    assert signatures.scan_tables(table, [(0, 100), (0, len(table))])[0]


def test_independent_code_and_signature_limits_both_reach_coverage_gaps(monkeypatch):
    monkeypatch.setattr(signatures, "MAX_CANDIDATES", 1)
    table = signatures.SIGNATURES["command_lut_le"]
    data = elf(table + signatures.SIGNATURES["command_lut_be"][:64] + b"x")
    result = scanner.assess_binary(data, [])
    assert result["recognition"]["limited"]
    assert any("No compiled references" in gap for gap in result["gaps"])
    assert any("signature candidate limit" in gap for gap in result["gaps"])


def test_both_clis_preserve_recognition_without_claiming_fixed_version(tmp_path):
    path = tmp_path / "renamed.wasm"
    path.write_bytes(wasm_data(signatures.SIGNATURES["command_lut_le"]))
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = scanner.main([str(path), "--brotli-version", "1.2.1", "--no-flirt", "--json"])
    report = json.loads(output.getvalue())
    assert code == 3
    assert report["user_summary"]["status"] == "decoder_detected_patch_unresolved"
    item = report["findings"][0]
    assert item["kind"] == "decoder_data_signature"
    assert item["patch_status"] == "unknown"
    binary = json.loads(run_scan(path).stdout)["findings"][0]
    assert binary["recognition"] == item["evidence"]["recognition"]
    assert binary["detection_status"] == "decoder_tables_detected"


def test_table_signatures_never_override_exact_affected_or_fixed_code():
    from brotli_binary_match import CodeReference  # noqa: PLC0415 -- Explicit independent layer.

    for state in ("fixed", "vulnerable"):
        entry = reference()
        entry["state"] = state
        ref = CodeReference.from_json(entry)
        result = scanner.assess_binary(
            elf(ref.code + signatures.SIGNATURES["command_lut_le"]), [ref]
        )
        assert result["patch_status"] == state + "_code_match"
        assert result["detection_status"] == "decoder_code_identified"
        assert result["recognition"]["matches"]


@pytest.mark.skipif(not os.environ.get("BROTLI_TEST_SOURCES"), reason="Optional trusted LTO builds")
@pytest.mark.parametrize("release", ["1.0.9", "1.2.1"])
def test_real_lto_build_recognition_without_compiler_code_references(tmp_path, release):
    compiler = shutil.which("cc")
    strip = shutil.which("strip")
    if compiler is None or strip is None:
        pytest.skip("Requires trusted C compiler and strip")
    tree = Path(os.environ["BROTLI_TEST_SOURCES"]).resolve() / f"brotli-{release}"
    source = tmp_path / "main.c"
    source.write_text(
        "#include <brotli/decode.h>\n"
        "int main(void) { const unsigned char input[] = {0x3b}; "
        "unsigned char output[32]; size_t size = sizeof(output); "
        "return BrotliDecoderDecompress(sizeof(input), input, &size, output); }\n"
    )
    target = tmp_path / "app"
    sources = sorted((tree / "c/common").glob("*.c")) + sorted((tree / "c/dec").glob("*.c"))
    subprocess.run(  # noqa: S603 -- Explicit opt-in compilation of trusted fixture sources.
        [
            compiler,
            "-O2",
            "-flto",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wl,--gc-sections",
            "-I",
            str(tree / "c/include"),
            str(source),
            *map(str, sources),
            "-o",
            str(target),
        ],
        check=True,
        capture_output=True,
    )
    for stripped in (False, True):
        if stripped:
            subprocess.run([strip, str(target)], check=True, capture_output=True)  # noqa: S603
        result = scanner.assess_binary(target.read_bytes(), [])
        assert result["detection_status"] == "decoder_tables_detected"
        assert result["patch_status"] == "unknown"
        assert len(result["recognition"]["matches"]) >= 3
