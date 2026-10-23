import argparse
import contextlib
import hashlib
import io
import json
import struct
import sys
import tracemalloc
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/brotli-checker/scripts"
sys.path.insert(0, str(SCRIPTS))
import brotli_binary_match as matcher  # noqa: E402
import brotli_binary_triage as triage  # noqa: E402
from test_binary_metadata import elf_with_symbols  # noqa: E402


def elf(payload=b"instructions", machine=183):
    header = matcher.ELF_HEADER.pack(
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3,
        machine,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    program = matcher.PROGRAM_HEADER.pack(
        1, 5, 120, 0x401000, 0x401000, len(payload), len(payload), 1
    )
    return header + program + payload


def run_main(monkeypatch, target, *arguments, outputs=(), symbols=None):
    responses = iter(outputs)

    def fake_run(command, timeout_seconds, max_output_bytes):
        del command, timeout_seconds, max_output_bytes
        output = next(responses)
        return {
            "returncode": 0,
            "output": output,
            "limited": False,
            "reason": None,
            "elapsed_seconds": 0.01,
        }

    monkeypatch.setattr(triage, "run_bounded", fake_run)
    selected = SYMBOL_FIXTURES if symbols is None else symbols
    monkeypatch.setattr(triage, "relevant_symbols", lambda *_: (selected, None))
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = triage.main([str(target), "--objdump", "/bin/true", *map(str, arguments)])
    return code, json.loads(output.getvalue())


SYMBOL_FIXTURES = [
    {
        "name": "SafeDecodeLiteralBlockSwitch",
        "base_name": "SafeDecodeLiteralBlockSwitch",
        "address": 0x401040,
        "size_bytes": 0x20,
        "section": "section[1]",
        "defined": True,
    },
    {
        "name": "SafeDecodeCommandBlockSwitch",
        "base_name": "SafeDecodeCommandBlockSwitch",
        "address": 0x401080,
        "size_bytes": 0x20,
        "section": "section[1]",
        "defined": True,
    },
    {
        "name": "ProcessCommandsInternal.constprop.0",
        "base_name": "ProcessCommandsInternal.constprop.0",
        "address": 0x401100,
        "size_bytes": 0x40,
        "section": "section[1]",
        "defined": True,
    },
    {
        "name": "SafeDecodeDistanceBlockSwitch",
        "base_name": "SafeDecodeDistanceBlockSwitch",
        "address": 0x4010C0,
        "size_bytes": 0x20,
        "section": "section[1]",
        "defined": True,
    },
    {
        "name": "BrotliDecoderDecompressStream",
        "base_name": "BrotliDecoderDecompressStream",
        "address": 0x401300,
        "size_bytes": 0x100,
        "section": "section[1]",
        "defined": True,
    },
    {
        "name": "ProcessCommands",
        "base_name": "ProcessCommands",
        "address": 0,
        "size_bytes": 0,
        "section": "*UND*",
        "defined": False,
    },
]


def test_symbol_triage_selects_patch_functions_and_preserves_unknown(tmp_path, monkeypatch):
    target = tmp_path / "service"
    data = elf(b"x" * 0x400)
    target.write_bytes(data)
    before = target.read_bytes()
    code, report = run_main(
        monkeypatch,
        target,
        outputs=(
            "literal disassembly",
            "command disassembly",
            "distance disassembly",
            "process disassembly",
            "stream disassembly",
        ),
    )
    assert code == 0
    assert report["collection"] == {
        "status": "evidence_collected",
        "incomplete": False,
        "reasons": [],
    }
    assert report["classification"]["patch_status"] == "unknown"
    assert report["target"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert [item["base_name"] for item in report["evidence"]["symbols"]] == [
        "SafeDecodeLiteralBlockSwitch",
        "SafeDecodeCommandBlockSwitch",
        "SafeDecodeDistanceBlockSwitch",
        "ProcessCommandsInternal.constprop.0",
        "BrotliDecoderDecompressStream",
        "ProcessCommands",
    ]
    assert len(report["evidence"]["disassembly"]) == 5
    fragments = report["tool"]["fragments"]
    assert report["tool"]["input_mode"] == "code_fragments"
    assert len(fragments) == 5
    for fragment, command in zip(fragments, report["tool"]["commands"], strict=True):
        begin = fragment["file_offset"]
        assert (
            fragment["sha256"]
            == hashlib.sha256(data[begin : begin + fragment["size_bytes"]]).hexdigest()
        )
        assert fragment["size_bytes"] <= report["limits"]["max_range_bytes"]
        assert fragment["ephemeral"] is True
        assert command[-1] == fragment["path"]
        assert "--target=binary" in command
        assert not Path(fragment["path"]).exists()
    assert target.read_bytes() == before


def test_stripped_or_import_only_binary_requests_explicit_range(tmp_path, monkeypatch):
    target = tmp_path / "service"
    target.write_bytes(elf())
    fallback = next(
        symbol for symbol in SYMBOL_FIXTURES if symbol["base_name"] == triage.PUBLIC_FALLBACK
    )
    imported = [{**fallback, "address": 0, "section": "*UND*", "defined": False}]
    code, report = run_main(monkeypatch, target, symbols=imported)
    assert code == 3
    assert report["collection"]["incomplete"]
    assert "No defined patch-bearing symbols" in " ".join(report["collection"]["reasons"])
    assert "--file-offset" in report["collection"]["next_request"]
    assert report["evidence"]["symbols"][0]["defined"] is False


def test_file_offset_range_is_translated_to_executable_address(tmp_path, monkeypatch):
    target = tmp_path / "service"
    target.write_bytes(elf(b"abcdefgh"))
    code, report = run_main(
        monkeypatch,
        target,
        "--file-offset",
        "122",
        "--length",
        "4",
        outputs=("bounded range disassembly",),
    )
    assert code == 0
    assert report["scope"] == {
        "mode": "file_offset_range",
        "start_address": 0x401002,
        "stop_address": 0x401006,
        "file_offset": 122,
        "length": 4,
    }
    command = report["tool"]["commands"][0]
    assert "--adjust-vma=0x401002" in command
    assert command[-1] == report["tool"]["fragments"][0]["path"]
    assert report["tool"]["fragments"][0]["size_bytes"] == 4


def test_large_regular_file_uses_only_small_code_fragments(tmp_path, monkeypatch):
    target = tmp_path / "large-browser"
    target.write_bytes(elf(b"x" * 0x400))
    size = 129 * 1024 * 1024
    with target.open("r+b") as stream:
        stream.truncate(size)
    tracemalloc.start()
    try:
        code, report = run_main(monkeypatch, target, outputs=("asm",) * 5)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert code == 0
    assert report["target"]["size_bytes"] == size
    assert report["limits"]["max_file_bytes"] is None
    assert sum(f["size_bytes"] for f in report["tool"]["fragments"]) < 1024
    assert peak < 16 * 1024 * 1024


def test_input_mutation_marks_collected_packet_incomplete(tmp_path, monkeypatch):
    target = tmp_path / "service"
    target.write_bytes(elf(b"x" * 0x400))
    monkeypatch.setattr(triage, "relevant_symbols", lambda *_: (SYMBOL_FIXTURES, None))

    def change_during_disassembly(*_):
        with target.open("r+b") as stream:
            stream.seek(-1, 2)
            stream.write(b"y")
        return {"returncode": 0, "output": "asm", "limited": False, "reason": None}

    monkeypatch.setattr(triage, "run_bounded", change_during_disassembly)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = triage.main([str(target), "--objdump", "/bin/true"])
    report = json.loads(output.getvalue())
    assert code == 3
    assert report["collection"]["incomplete"]
    assert "chang" in " ".join(report["collection"]["reasons"]).lower()


def test_address_range_and_section_are_exact_and_bounded(tmp_path, monkeypatch):
    target = tmp_path / "service"
    data = bytearray(elf_with_symbols(b"instructions", 183, [{"name": ".text"}]))
    # Reuse the fixture's string table for section names.
    struct.pack_into("<H", data, 62, 2)
    section_table = matcher.elf_header(bytes(data))[6]
    struct.pack_into("<I", data, section_table + matcher.SECTION_HEADER.size, 1)
    target.write_bytes(data)
    code, report = run_main(
        monkeypatch,
        target,
        "--start-address",
        "0x400100",
        "--stop-address",
        "0x400108",
        "--section",
        ".text",
        outputs=("address disassembly",),
    )
    assert code == 0
    assert report["scope"]["section"] == ".text"
    assert "--adjust-vma=0x400100" in report["tool"]["commands"][0]

    code, report = run_main(
        monkeypatch,
        target,
        "--start-address",
        "0x400100",
        "--stop-address",
        "0x400200",
        "--max-range-bytes",
        "8",
        outputs=(),
    )
    assert code == 3
    assert report["target"]["sha256"]
    assert "max-range-bytes" in report["collection"]["reasons"][0]


def test_symlinks_and_oversized_files_are_not_given_to_objdump(tmp_path, monkeypatch):
    target = tmp_path / "service"
    target.write_bytes(elf())
    link = tmp_path / "link"
    link.symlink_to(target)

    def forbidden(*args, **kwargs):
        del args, kwargs
        pytest.fail("objdump must not run")

    monkeypatch.setattr(triage, "run_bounded", forbidden)
    for path, extra in ((link, ()), (target, ("--max-file-bytes", "1"))):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            assert triage.main([str(path), "--objdump", "/bin/true", *extra]) == 3
        report = json.loads(output.getvalue())
        assert report["collection"]["incomplete"]
        assert report["tool"]["commands"] == []


def test_unsupported_elf_is_hashed_and_explicitly_incomplete(tmp_path, monkeypatch):
    target = tmp_path / "service"
    data = b"not an ELF"
    target.write_bytes(data)
    monkeypatch.setattr(triage, "run_bounded", pytest.fail)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert triage.main([str(target), "--objdump", "/bin/true"]) == 3
    report = json.loads(output.getvalue())
    assert report["target"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert "Unsupported or malformed ELF" in report["collection"]["reasons"][0]


def test_symbol_priority_orders_defined_patch_evidence_before_fallback():
    parsed = sorted(SYMBOL_FIXTURES, key=triage.symbol_priority)
    assert [item["section"] for item in parsed] == [
        "section[1]",
        "section[1]",
        "section[1]",
        "section[1]",
        "section[1]",
        "*UND*",
    ]
    assert parsed[0]["address"] == 0x401040
    assert parsed[-1]["defined"] is False


def test_sectionless_elf_requests_an_explicit_range():
    symbols, reason = triage.relevant_symbols(elf(), float("inf"))
    assert symbols == []
    assert reason == "No ELF section table; symbol-based triage is unavailable"


def test_elf_symbol_selection_bounds_candidates_and_prefers_definitions():
    data = elf_with_symbols(
        b"\x90" * 64,
        matcher.EM_X86_64,
        [
            {
                "name": "SafeDecodeLiteralBlockSwitch",
                "index": 0,
                "address": 0,
                "size": 0,
            },
            {"name": "SafeDecodeCommandBlockSwitch"},
            {"name": "ProcessCommands"},
            {"name": "BrotliDecoderDecompressStream"},
        ],
    )
    symbols, reason = triage.relevant_symbols(data, float("inf"), candidate_limit=2)
    assert [symbol["name"] for symbol in symbols] == [
        "SafeDecodeCommandBlockSwitch",
        "ProcessCommands",
    ]
    assert all(symbol["defined"] for symbol in symbols)
    assert reason == "Relevant ELF symbol candidate limit reached"


def test_elf_symbol_definition_requires_executable_owner_and_load_mapping():
    data = elf_with_symbols(
        b"\x90" * 64,
        matcher.EM_X86_64,
        [{"name": "SafeDecodeCommandBlockSwitch"}],
        owner_flags=2,
    )
    symbols, reason = triage.relevant_symbols(data, float("inf"))
    assert symbols == []
    assert reason is None


def test_symbol_disassembly_respects_range_limit(tmp_path, monkeypatch):
    target = tmp_path / "service"
    target.write_bytes(elf(b"x" * 0x400))
    oversized = [{**SYMBOL_FIXTURES[0], "size_bytes": 65}]
    code, report = run_main(
        monkeypatch,
        target,
        "--max-range-bytes",
        "64",
        symbols=oversized,
    )
    assert code == 3
    assert report["tool"]["commands"] == []
    assert any("no bounded size" in reason for reason in report["collection"]["reasons"])


def test_public_fallback_only_is_orientation_not_complete_patch_scope(tmp_path, monkeypatch):
    target = tmp_path / "service"
    target.write_bytes(elf(b"x" * 0x400))
    fallback = [
        symbol for symbol in SYMBOL_FIXTURES if symbol["base_name"] == triage.PUBLIC_FALLBACK
    ]
    code, report = run_main(
        monkeypatch,
        target,
        symbols=fallback,
        outputs=("stream orientation",),
    )
    assert code == 3
    assert len(report["evidence"]["disassembly"]) == 1
    reasons = " ".join(report["collection"]["reasons"])
    assert "Missing defined block-switch classes" in reasons
    assert "No defined ProcessCommands" in reasons


def test_defined_symbols_are_selected_before_imports_at_cap(tmp_path, monkeypatch):
    target = tmp_path / "service"
    target.write_bytes(elf(b"x" * 0x400))
    imported = {**SYMBOL_FIXTURES[0], "address": 0, "section": "*UND*", "defined": False}
    code, report = run_main(
        monkeypatch,
        target,
        "--max-symbols",
        "1",
        symbols=[imported, SYMBOL_FIXTURES[1]],
        outputs=("defined command block",),
    )
    assert code == 3
    assert report["evidence"]["symbols"][0]["defined"] is True
    assert report["evidence"]["symbols"][0]["name"] == "SafeDecodeCommandBlockSwitch"


def test_explicit_address_range_must_be_file_backed_executable(tmp_path, monkeypatch):
    target = tmp_path / "service"
    target.write_bytes(elf())
    code, report = run_main(
        monkeypatch,
        target,
        "--start-address",
        "0x500000",
        "--stop-address",
        "0x500008",
    )
    assert code == 3
    assert report["tool"]["commands"] == []
    assert "file-backed executable PT_LOAD" in report["collection"]["reasons"][0]


def test_run_bounded_caps_output_and_time():
    output = triage.run_bounded(
        [sys.executable, "-c", "print('x' * 10000)"], timeout_seconds=2, max_output_bytes=32
    )
    assert output["limited"]
    assert output["reason"] == "objdump output limit reached"
    assert len(output["output"].encode()) == 32

    timed = triage.run_bounded(
        [sys.executable, "-c", "import time; time.sleep(1)"],
        timeout_seconds=0.01,
        max_output_bytes=32,
    )
    assert timed["limited"]
    assert timed["reason"] == "objdump timeout reached"


def test_file_offset_must_be_in_one_executable_segment():
    with pytest.raises(triage.TriageError, match="executable PT_LOAD"):
        triage.file_offset_address(elf(b"abcd"), 0, 4)


@pytest.mark.parametrize(
    "arguments",
    [
        ("--start-address", "1"),
        ("--file-offset", "1"),
        ("--section", ".text"),
        (
            "--start-address",
            "1",
            "--stop-address",
            "2",
            "--file-offset",
            "120",
            "--length",
            "1",
        ),
    ],
)
def test_invalid_scope_arguments_are_cli_errors(tmp_path, arguments):
    target = tmp_path / "service"
    target.write_bytes(elf())
    with pytest.raises(SystemExit) as error:
        triage.main([str(target), *arguments])
    assert error.value.code == 2


def test_nonnegative_and_positive_types_reject_invalid_values():
    with pytest.raises(argparse.ArgumentTypeError):
        triage.nonnegative("-1")
    with pytest.raises(argparse.ArgumentTypeError):
        triage.positive("0")


def test_output_file_receives_json(tmp_path, monkeypatch):
    target = tmp_path / "service"
    target.write_bytes(elf())
    report_path = tmp_path / "triage.json"
    monkeypatch.setattr(triage, "relevant_symbols", lambda *_: ([], None))
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert (
            triage.main(
                [
                    str(target),
                    "--objdump",
                    "/bin/true",
                    "--output",
                    str(report_path),
                ]
            )
            == 3
        )
    assert output.getvalue() == ""
    assert json.loads(report_path.read_text())["target"]["sha256"]


def test_output_cannot_alias_target(tmp_path):
    target = tmp_path / "service"
    original = elf()
    target.write_bytes(original)
    with pytest.raises(SystemExit) as error:
        triage.main(
            [
                str(target),
                "--objdump",
                "/bin/true",
                "--output",
                str(target),
            ]
        )
    assert error.value.code == 2
    assert target.read_bytes() == original
