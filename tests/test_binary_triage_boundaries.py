import argparse
import sys
import time
from pathlib import Path

import brotli_binary_match as matcher
import brotli_binary_triage as triage
import pytest
from test_binary_metadata import CODE_ADDRESS, elf_with_symbols
from test_binary_triage import elf, run_main


def symbol_elf(symbols=None, **options):
    return elf_with_symbols(
        b"\x90" * 32,
        matcher.EM_X86_64,
        [{"name": "ProcessCommands"}] if symbols is None else symbols,
        **options,
    )


def replace_header(data, index, value):
    result = bytearray(data)
    fields = list(matcher.ELF_HEADER.unpack_from(result))
    fields[index] = value
    matcher.ELF_HEADER.pack_into(result, 0, *fields)
    return bytes(result)


def replace_section(data, index, field, value):
    result = bytearray(data)
    header = matcher.elf_header(bytes(result))
    offset = header[6] + index * matcher.SECTION_HEADER.size
    fields = list(matcher.SECTION_HEADER.unpack_from(result, offset))
    fields[field] = value
    matcher.SECTION_HEADER.pack_into(result, offset, *fields)
    return bytes(result)


@pytest.mark.parametrize(("offset", "size"), [(0, 0), (0, 4), (4, 0), (1, 3)])
def test_checked_range_allows_empty_and_exact_file_boundaries(offset, size):
    assert triage.checked_range(b"abcd", offset, size) == (offset, offset + size)


@pytest.mark.parametrize(("offset", "size"), [(-1, 1), (0, -1), (5, 0), (1, 4), (4, 1)])
def test_checked_range_rejects_individually_invalid_bounds(offset, size):
    with pytest.raises(ValueError, match="ELF range outside file"):
        triage.checked_range(b"abcd", offset, size)


def test_cli_numeric_types_allow_zero_offset_and_base_prefixes():
    assert triage.nonnegative("0") == 0
    assert triage.nonnegative("0x10") == 16
    assert triage.positive("1") == 1
    assert triage.positive("0x10") == 16


def test_trusted_objdump_uses_explicit_path_and_path_lookup(tmp_path, monkeypatch):
    tool = tmp_path / "objdump"
    tool.write_text("tool")
    tool.chmod(0o700)
    monkeypatch.setattr(triage.shutil, "which", lambda _: str(tool))
    assert triage.trusted_objdump(None) == tool.resolve()
    monkeypatch.setattr(triage.shutil, "which", lambda _: None)
    assert triage.trusted_objdump(str(tool)) == tool.resolve()
    with pytest.raises(triage.TriageError, match="was not found"):
        triage.trusted_objdump(None)


@pytest.mark.parametrize("kind", ["missing", "directory", "not_executable", "relative"])
def test_trusted_objdump_rejects_unusable_paths(tmp_path, kind):
    tool = tmp_path / "objdump"
    if kind == "directory":
        tool.mkdir()
    elif kind == "not_executable":
        tool.write_text("tool")
        tool.chmod(0o600)
    value = "objdump" if kind == "relative" else str(tool)
    with pytest.raises(triage.TriageError):
        triage.trusted_objdump(value)


def test_read_target_accepts_exact_file_limit_and_rejects_directory(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"data")
    for limit in (None, 4, 5):
        with triage.read_target(target, limit) as data:
            assert data[:] == b"data"
    with (
        pytest.raises(triage.TriageError, match="nonregular"),
        triage.read_target(tmp_path, None),
    ):
        pytest.fail("Directories cannot be read as targets")


def test_process_start_failure_is_bounded_evidence(tmp_path):
    result = triage.run_bounded([str(tmp_path / "missing")], 1, 10)
    assert result["returncode"] is None
    assert result["output"] == ""
    assert result["limited"] is True
    assert result["reason"].startswith("Cannot start objdump:")
    assert 0 <= result["elapsed_seconds"] < 1


def test_process_exact_output_limit_remains_complete():
    result = triage.run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.write('abcd')"], 2, 4
    )
    assert result["returncode"] == 0
    assert result["output"] == "abcd"
    assert result["limited"] is False
    assert result["reason"] is None
    assert 0 <= result["elapsed_seconds"] < 2


def test_process_timeout_terminates_descendants(tmp_path):
    gate = tmp_path / "gate"
    marker = tmp_path / "survived"
    child = (
        "import pathlib,sys,time\n"
        "gate=pathlib.Path(sys.argv[1]); marker=pathlib.Path(sys.argv[2])\n"
        "while not gate.exists():\n    time.sleep(.01)\n"
        "marker.write_text('survived')\n"
    )
    parent = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}, *sys.argv[1:]]); "
        "print('child started', flush=True); time.sleep(10)"
    )
    result = triage.run_bounded(
        [sys.executable, "-c", parent, str(gate), str(marker)],
        timeout_seconds=1,
        max_output_bytes=1024,
    )
    assert result["limited"] is True
    assert result["reason"] == "objdump timeout reached"
    assert result["output"] == "child started\n"
    gate.write_text("continue")
    time.sleep(0.25)
    assert not marker.exists()


def test_successful_process_cannot_leave_descendants(tmp_path):
    gate = tmp_path / "gate"
    marker = tmp_path / "survived"
    child = (
        "import pathlib,sys,time\n"
        "gate=pathlib.Path(sys.argv[1]); marker=pathlib.Path(sys.argv[2])\n"
        "while not gate.exists():\n    time.sleep(.01)\n"
        "marker.write_text('survived')\n"
    )
    parent = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}, *sys.argv[1:]], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
        "print('child started', flush=True)"
    )
    result = triage.run_bounded(
        [sys.executable, "-c", parent, str(gate), str(marker)],
        timeout_seconds=2,
        max_output_bytes=1024,
    )
    assert result["returncode"] == 0
    assert result["limited"] is False
    assert result["output"] == "child started\n"
    gate.write_text("continue")
    time.sleep(0.25)
    assert not marker.exists()


@pytest.mark.parametrize(("offset", "length", "address"), [(120, 4, 0x401000), (123, 1, 0x401003)])
def test_file_offset_range_accepts_segment_endpoints(offset, length, address):
    assert triage.file_offset_address(elf(b"abcd"), offset, length) == address


@pytest.mark.parametrize(("offset", "length"), [(119, 1), (120, 5), (123, 2), (124, 1)])
def test_file_offset_range_rejects_segment_crossing(offset, length):
    with pytest.raises(triage.TriageError, match="executable PT_LOAD"):
        triage.file_offset_address(elf(b"abcd"), offset, length)


@pytest.mark.parametrize(("start", "size", "expected"), [(0x401000, 4, 120), (0x401003, 1, 123)])
def test_function_mapping_accepts_segment_endpoints(start, size, expected):
    data = elf(b"abcd")
    assert triage.function_offset(data, matcher.elf_header(data), start, size) == expected


@pytest.mark.parametrize(("start", "size"), [(0x400FFF, 1), (0x401000, 5), (0x401004, 1)])
def test_function_mapping_rejects_non_file_backed_ranges(start, size):
    data = elf(b"abcd")
    assert triage.function_offset(data, matcher.elf_header(data), start, size) is None


def test_executable_mapping_rejects_non_load_segments():
    data = bytearray(elf(b"abcd"))
    program = list(matcher.PROGRAM_HEADER.unpack_from(data, matcher.ELF_HEADER.size))
    program[0] = 2
    matcher.PROGRAM_HEADER.pack_into(data, matcher.ELF_HEADER.size, *program)
    assert triage.function_offset(bytes(data), matcher.elf_header(bytes(data)), 0x401000, 4) is None


def test_symbol_scan_reports_unsupported_section_entry_size():
    data = replace_header(symbol_elf(), 11, matcher.SECTION_HEADER.size - 1)
    assert triage.relevant_symbols(data, float("inf")) == ([], "Unsupported ELF section table")


@pytest.mark.parametrize(("field", "value"), [(9, 1), (5, 1), (6, 4)])
def test_symbol_scan_reports_malformed_symbol_tables(field, value):
    data = replace_section(symbol_elf(), 3, field, value)
    assert triage.relevant_symbols(data, float("inf")) == ([], "Malformed ELF symbol table")


def test_symbol_scan_requires_string_table():
    data = symbol_elf(string_type=1)
    assert triage.relevant_symbols(data, float("inf")) == (
        [],
        "ELF symbols do not reference a string table",
    )


def test_symbol_scan_symbol_budget_accepts_exact_count(monkeypatch):
    monkeypatch.setattr(triage, "MAX_SYMBOLS", 2)
    symbols, reason = triage.relevant_symbols(symbol_elf(), float("inf"))
    assert [item["name"] for item in symbols] == ["ProcessCommands"]
    assert reason is None
    monkeypatch.setattr(triage, "MAX_SYMBOLS", 1)
    assert triage.relevant_symbols(symbol_elf(), float("inf")) == ([], "ELF symbol limit reached")


def test_symbol_scan_table_budget_preserves_collected_evidence(monkeypatch):
    monkeypatch.setattr(triage, "MAX_SYMBOL_TABLES", 1)
    symbols, reason = triage.relevant_symbols(symbol_elf(), float("inf"))
    assert [item["name"] for item in symbols] == ["ProcessCommands"]
    assert reason is None
    symbols, reason = triage.relevant_symbols(symbol_elf(symbol_table_copies=2), float("inf"))
    assert [item["name"] for item in symbols] == ["ProcessCommands"]
    assert reason == "ELF symbol-table limit reached"


def test_symbol_scan_honors_exact_deadline(monkeypatch):
    monkeypatch.setattr(triage.time, "monotonic", lambda: 10.0)
    assert triage.relevant_symbols(symbol_elf(), 10.0) == ([], "ELF symbol scan timeout reached")


@pytest.mark.parametrize(
    "symbol",
    [
        {"name": "unrelated"},
        {"name": "ProcessCommands", "info": 0x11},
        {"name": "ProcessCommands", "name_offset": 0xFFFF},
        {"name": "ProcessCommands", "index": 4},
        {"name": "ProcessCommands", "address": CODE_ADDRESS - 1, "size": 1},
        {"name": "ProcessCommands", "address": CODE_ADDRESS + 31, "size": 2},
    ],
)
def test_symbol_scan_ignores_irrelevant_or_out_of_bounds_entries(symbol):
    assert triage.relevant_symbols(symbol_elf([symbol]), float("inf")) == ([], None)


def test_symbol_scan_accepts_owner_end_and_imports():
    symbols, reason = triage.relevant_symbols(
        symbol_elf(
            [
                {"name": "ProcessCommands", "address": CODE_ADDRESS + 31, "size": 1},
                {"name": "BrotliDecoderDecompressStream", "index": 0, "address": 0, "size": 0},
            ]
        ),
        float("inf"),
    )
    assert reason is None
    assert [(item["name"], item["defined"]) for item in symbols] == [
        ("ProcessCommands", True),
        ("BrotliDecoderDecompressStream", False),
    ]


def test_symbol_scan_distinguishes_exact_candidate_limit_and_overflow():
    data = symbol_elf([{"name": "ProcessCommands"}, {"name": "SafeDecodeLiteralBlockSwitch"}])
    symbols, reason = triage.relevant_symbols(data, float("inf"), candidate_limit=2)
    assert len(symbols) == 2
    assert reason is None
    symbols, reason = triage.relevant_symbols(data, float("inf"), candidate_limit=1)
    assert [item["name"] for item in symbols] == ["ProcessCommands"]
    assert reason == "Relevant ELF symbol candidate limit reached"


@pytest.mark.parametrize(("seconds", "output_left"), [(0, 1), (-1, 1), (1, 0), (1, -1)])
def test_command_budget_exhaustion_skips_process(monkeypatch, seconds, output_left):
    monkeypatch.setattr(triage.time, "monotonic", lambda: 10.0)
    report = triage.base_report(Path("target"), triage.build_parser().parse_args(["target"]))
    used = triage.command_evidence(report, ["missing"], {}, 10.0 + seconds, output_left)
    assert used == 0
    assert report["tool"]["commands"] == []
    assert report["evidence"]["disassembly"] == []
    assert report["collection"]["reasons"] == ["Global objdump time/output budget exhausted"]


@pytest.mark.parametrize(
    ("limited", "returncode", "reason", "expected"),
    [(True, 0, "output capped", "output capped"), (False, 2, None, "objdump exited 2")],
)
def test_command_errors_preserve_disassembly_and_mark_incomplete(
    monkeypatch, limited, returncode, reason, expected
):
    monkeypatch.setattr(triage.time, "monotonic", lambda: 10.0)

    def run(command, timeout, output_left):
        assert command == ["objdump", "code.bin"]
        assert timeout == 1
        assert output_left == 4
        return {"limited": limited, "returncode": returncode, "reason": reason, "output": "é"}

    monkeypatch.setattr(triage, "run_bounded", run)
    report = triage.base_report(Path("target"), triage.build_parser().parse_args(["target"]))
    assert triage.command_evidence(report, ["objdump", "code.bin"], {"mode": "symbol"}, 11, 4) == 2
    assert report["collection"]["reasons"] == [expected]
    assert report["evidence"]["disassembly"] == [
        {
            "scope": {"mode": "symbol"},
            "returncode": returncode,
            "limited": limited,
            "reason": reason,
            "text": "é",
        }
    ]


def test_explicit_range_accepts_exact_maximum_and_rejects_empty_range():
    args = argparse.Namespace(start_address=0x401000, stop_address=0x401004, max_range_bytes=4)
    assert triage.explicit_range(elf(b"abcd"), args, "address_range") == (0x401000, 0x401004)
    args.stop_address = args.start_address
    with pytest.raises(triage.TriageError, match="nonempty"):
        triage.explicit_range(elf(b"abcd"), args, "address_range")


def named_section_elf():
    data = symbol_elf([{"name": ".text"}])
    data = replace_header(data, 13, 2)
    return replace_section(data, 1, 0, 1)


def test_section_constraint_accepts_exact_executable_section_endpoints():
    triage.require_section(named_section_elf(), ".text", CODE_ADDRESS, CODE_ADDRESS + 32)


@pytest.mark.parametrize(
    ("start", "stop", "name"),
    [
        (CODE_ADDRESS - 1, CODE_ADDRESS + 1, ".text"),
        (CODE_ADDRESS, CODE_ADDRESS + 33, ".text"),
        (CODE_ADDRESS, CODE_ADDRESS, ".text"),
        (CODE_ADDRESS, CODE_ADDRESS + 1, ".tex"),
        (CODE_ADDRESS, CODE_ADDRESS + 1, ".text.extra"),
    ],
)
def test_section_constraint_rejects_partial_names_and_outside_ranges(start, stop, name):
    with pytest.raises(triage.TriageError, match="Requested section"):
        triage.require_section(named_section_elf(), name, start, stop)


@pytest.mark.parametrize(("field", "value"), [(1, 3), (2, 2), (0, 7)])
def test_section_constraint_rejects_non_code_and_invalid_name_offsets(field, value):
    data = replace_section(named_section_elf(), 1, field, value)
    with pytest.raises(triage.TriageError, match="Requested section"):
        triage.require_section(data, ".text", CODE_ADDRESS, CODE_ADDRESS + 1)


@pytest.mark.parametrize(("field", "value"), [(11, 1), (13, 0), (13, 4)])
def test_section_constraint_rejects_unavailable_section_names(field, value):
    data = replace_header(named_section_elf(), field, value)
    with pytest.raises(triage.TriageError, match="Requested section"):
        triage.require_section(data, ".text", CODE_ADDRESS, CODE_ADDRESS + 1)


@pytest.mark.parametrize(("machine", "architecture"), [(183, "aarch64"), (62, "i386:x86-64")])
def test_fragment_command_matches_target_architecture(tmp_path, machine, architecture):
    report = triage.base_report(Path("target"), triage.build_parser().parse_args(["target"]))
    command = triage.fragment_command(
        report, elf(b"abcd", machine), tmp_path, Path("objdump"), 0x401000, 0x401004
    )
    assert f"--architecture={architecture}" in command
    assert Path(command[-1]).read_bytes() == b"abcd"
    assert report["tool"]["fragments"][0]["file_offset"] == 120


@pytest.mark.parametrize("size", [0, 1, 32])
def test_symbol_disassembly_handles_zero_minimum_and_exact_range_limit(tmp_path, monkeypatch, size):
    target = tmp_path / "service"
    target.write_bytes(symbol_elf())
    symbol = {
        "name": "ProcessCommands",
        "base_name": "ProcessCommands",
        "address": CODE_ADDRESS,
        "size_bytes": size,
        "section": "section[1]",
        "defined": True,
    }
    code, report = run_main(
        monkeypatch, target, "--max-range-bytes", "32", symbols=[symbol], outputs=("asm",)
    )
    assert code == 3  # Missing block-switch functions keep symbol triage incomplete.
    if size:
        assert len(report["evidence"]["disassembly"]) == 1
        assert report["tool"]["fragments"][0]["size_bytes"] == size
    else:
        assert report["evidence"]["disassembly"] == []
        assert any("no bounded size" in reason for reason in report["collection"]["reasons"])
