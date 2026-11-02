import importlib
import json
import struct
import sys
from pathlib import Path

import brotli_debug_companions as debug
import pytest
from test_debug_companions import universal_mach_fixture

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
exporter = importlib.import_module("export_mach_debug_symbols")


DWARF = """
0x00000001: DW_TAG_compile_unit
0x00000002:   DW_TAG_subprogram
                DW_AT_name ("DecodeLiteralBlockSwitch")
                DW_AT_decl_file ("/private/build/c/dec/decode.c")
                DW_AT_decl_line (42)
                DW_AT_low_pc (0x0000000000100010)
                DW_AT_high_pc (0x0000000000100020)
0x00000003:   DW_TAG_variable
0x00000004:   DW_TAG_subprogram
                DW_AT_name ("missing_line")
                DW_AT_low_pc (0x0000000000100030)
                DW_AT_high_pc (0x0000000000100040)
"""

DWARF_UNRESOLVED_HIGH_PC = """
0x00000002: DW_TAG_subprogram
                DW_AT_name ("DecodeLiteralBlockSwitch")
                DW_AT_decl_file ("decode.c")
                DW_AT_decl_line (42)
                DW_AT_low_pc (0x0000000000000100)
                DW_AT_high_pc (0x0000000000000010)
"""


def test_dwarfdump_parser_retains_only_complete_bounded_subprograms():
    assert exporter.parse_subprograms(DWARF) == [
        {
            "name": "DecodeLiteralBlockSwitch",
            "address": 0x100010,
            "size": 0x10,
            "source_file": "decode.c",
            "source_line": 42,
        }
    ]
    with pytest.raises(ValueError, match="population exceeds"):
        exporter.parse_subprograms(DWARF, maximum=0)
    assert exporter.parse_subprograms(DWARF_UNRESOLVED_HIGH_PC) == []


def test_exporter_packet_self_verifies_against_selected_universal_slice(tmp_path):
    artifact, _, _, _ = universal_mach_fixture()
    tool = tmp_path / "llvm-dwarfdump"
    tool.write_bytes(b"trusted fixture tool")
    functions = exporter.parse_subprograms(DWARF)

    packet = exporter.packet(artifact, artifact, "aarch64", tool, "version 17", functions)
    raw = (json.dumps(packet, sort_keys=True) + "\n").encode()
    verified = debug.verify_mach_debug_export(artifact, artifact, raw)

    assert verified.status == "verified"
    assert verified.function_hints[0].file_offset == 0x310
    assert packet["slice"]["machine"] == "aarch64"


def test_stable_sparse_buffer_preserves_bytes_startswith_contract(tmp_path):
    artifact, _, _, _ = universal_mach_fixture()
    path = tmp_path / "universal.dylib"
    path.write_bytes(artifact)

    with exporter.stable_data(path) as data:
        cases = (
            ((), 0, None),
            ((b"not-magic", b"\xca\xfe\xba\xbe"), 0, 4),
            ((artifact[-4:],), -4, None),
            ((artifact[-3:-1],), -3, -1),
            ((b"",), -1, -1),
            ((b"",), len(artifact), len(artifact) - 1),
            ((b"",), len(artifact) + 1, None),
        )
        for prefix, start, end in cases:
            expected = (
                artifact.startswith(prefix, start)
                if end is None
                else artifact.startswith(prefix, start, end)
            )
            assert data.startswith(prefix, start, end) is expected
        assert debug.inspect_layout(data)["kind"] == "mach_o_universal"


def test_exporter_uses_bounded_runner_text_contract(monkeypatch):
    monkeypatch.setattr(
        exporter,
        "run_bounded",
        lambda *_: {"reason": None, "returncode": 0, "output": "llvm-dwarfdump version 17"},
    )
    assert exporter.run_tool(["tool", "--version"], 1, 100) == "llvm-dwarfdump version 17"

    monkeypatch.setattr(
        exporter,
        "run_bounded",
        lambda *_: {"reason": None, "returncode": 0, "output": b"wrong contract"},
    )
    with pytest.raises(ValueError, match="non-text"):
        exporter.run_tool(["tool", "--version"], 1, 100)


def test_dsym_identity_does_not_require_executable_segment_layout(tmp_path):
    artifact, first_size, _, _ = universal_mach_fixture()
    companion = bytearray(artifact)
    base = 0x100
    command_count = int.from_bytes(companion[base + 16 : base + 20], "little")
    cursor = base + 32
    for _ in range(command_count):
        command, size = struct.unpack_from("<II", companion, cursor)
        if command == 2:
            struct.pack_into("<I", companion, cursor + 8, len(companion) + 1)
            break
        cursor += size
    corrupted = bytes(companion)
    assert debug.inspect_layout(corrupted)["gaps"]

    tool = tmp_path / "llvm-dwarfdump"
    tool.write_bytes(b"trusted fixture tool")
    document = exporter.packet(
        artifact,
        corrupted,
        "aarch64",
        tool,
        "version 17",
        exporter.parse_subprograms(DWARF),
    )
    verified = debug.verify_mach_debug_export(
        artifact, corrupted, (json.dumps(document, sort_keys=True) + "\n").encode()
    )

    assert verified.status == "verified"
    assert document["slice"]["dsym_size"] == first_size
