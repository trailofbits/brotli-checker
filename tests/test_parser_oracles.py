import hashlib
import json
import struct
import sys
from pathlib import Path

import brotli_parser_oracles as subject
import pytest


def elf_with_executable_nonload_segment() -> bytes:
    header = struct.Struct("<16sHHIQQQIHHHHHH")
    program = struct.Struct("<IIQQQQQQ")
    data_offset = header.size + 2 * program.size
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    return b"".join(
        (
            header.pack(
                ident,
                3,
                183,
                1,
                0x401000,
                header.size,
                0,
                0,
                header.size,
                program.size,
                2,
                0,
                0,
                0,
            ),
            program.pack(1, 5, data_offset, 0x401000, 0x401000, 4, 4, 4),
            program.pack(4, 1, data_offset + 4, 0x402000, 0x402000, 16, 16, 4),
            b"\x1f\x20\x03\xd5",
            bytes(16),
        )
    )


def test_lief_agrees_with_scanner_on_host_elf_when_available():
    pytest.importorskip("lief")
    target = Path(sys.executable).resolve()
    with target.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            pytest.skip("This oracle field comparison requires an ELF host executable")
    scanner = subject.scanner_observation(target)
    lief = subject.lief_observation(target)
    assert scanner["status"] == lief["status"] == "parsed"
    assert scanner["kind"] == lief["kind"] == "elf"
    assert scanner["machine"] == lief["machine"]
    assert scanner["executable_ranges"] == lief["executable_ranges"]
    assert subject.compare_observations(scanner, lief) == []


def test_lief_executable_ranges_exclude_nonload_pf_x_segments(tmp_path):
    pytest.importorskip("lief")
    target = tmp_path / "executable-note.elf"
    target.write_bytes(elf_with_executable_nonload_segment())
    scanner = subject.scanner_observation(target)
    lief = subject.lief_observation(target)
    assert scanner["status"] == lief["status"] == "parsed"
    assert scanner["executable_ranges"] == [[176, 4]]
    assert lief["executable_ranges"] == scanner["executable_ranges"]
    assert subject.compare_observations(scanner, lief) == []


def test_acceptance_and_field_disagreements_are_explicit_not_verdicts():
    scanner = {
        "parser": "brotli-checker",
        "status": "parsed",
        "kind": "elf",
        "bits": 64,
    }
    rejected = {"parser": "lief", "status": "rejected"}
    different = {"parser": "llvm", "status": "parsed", "kind": "elf", "bits": 32}
    differences = subject.compare_observations(scanner, rejected, different)
    assert differences == [
        {
            "kind": "acceptance_disagreement",
            "oracle": "lief",
            "scanner_status": "parsed",
            "oracle_status": "rejected",
        },
        {
            "kind": "field_disagreement",
            "oracle": "llvm",
            "field": "bits",
            "scanner_value": 64,
            "oracle_value": 32,
        },
    ]


def test_unsupported_and_unavailable_oracles_are_inconclusive():
    scanner = {"parser": "brotli-checker", "status": "unsupported"}
    parsed = {"parser": "lief", "status": "parsed", "kind": "coff"}
    unavailable = {"parser": "llvm-readobj", "status": "unavailable"}
    assert subject.compare_observations(scanner, parsed, unavailable) == [
        {"kind": "scanner_coverage_gap", "oracle": "lief"},
        {"kind": "oracle_inconclusive", "oracle": "llvm-readobj", "status": "unavailable"},
    ]


def test_llvm_packet_is_bounded_and_requires_json(monkeypatch):
    monkeypatch.setattr(subject, "_trusted_tool", lambda path: path)
    monkeypatch.setattr(subject, "_hash_path", lambda _: "a" * 64)
    valid_output = json.dumps(
        [
            {
                "FileSummary": {"Format": "elf64-aarch64"},
                "ElfHeader": {
                    "Ident": {
                        "Class": {"Name": "64-bit", "Value": 2},
                        "DataEncoding": {"Name": "LittleEndian", "Value": 1},
                    },
                    "Machine": {"Name": "EM_AARCH64", "Value": 183},
                },
                "ProgramHeaders": [
                    {
                        "ProgramHeader": {
                            "Type": {"Name": "PT_LOAD", "Value": 1},
                            "Flags": {"Value": 5, "Flags": []},
                            "Offset": 0,
                            "FileSize": 9,
                        }
                    }
                ],
            }
        ]
    )

    def result(command, *_args, output=valid_output, limited=False):
        if command[1:] == ["--version"]:
            return {
                "returncode": 0,
                "output": "LLVM version 22.1.8\n",
                "limited": False,
                "reason": None,
            }
        return {
            "returncode": 0,
            "output": output,
            "limited": limited,
            "reason": "timeout" if limited else None,
        }

    monkeypatch.setattr(subject, "run_bounded", result)
    parsed = subject.llvm_observation(Path("fixture"), Path("/llvm-readobj"))
    assert parsed["status"] == "parsed"
    assert parsed["tool_version"] == "LLVM version 22.1.8"
    assert parsed["bits"] == 64
    assert parsed["byteorder"] == "little"
    assert parsed["machine"] == 183
    assert parsed["executable_ranges"] == [[0, 9]]
    monkeypatch.setattr(
        subject, "run_bounded", lambda command, *args: result(command, *args, output="not json")
    )
    assert subject.llvm_observation(Path("fixture"), Path("/llvm"))["status"] == "error"
    monkeypatch.setattr(
        subject,
        "run_bounded",
        lambda command, *args: result(command, *args, output="", limited=True),
    )
    assert subject.llvm_observation(Path("fixture"), Path("/llvm"))["reason"] == "timeout"


def test_stable_snapshot_hashes_exact_bytes_and_rejects_symlinks(tmp_path):
    source = tmp_path / "fixture"
    source.write_bytes(b"fixture bytes")
    snapshot_dir = tmp_path / "snapshots"
    snapshot_dir.mkdir()
    with subject.stable_snapshot(source, snapshot_dir) as (snapshot, sha256, size):
        assert snapshot.read_bytes() == b"fixture bytes"
        assert sha256 == hashlib.sha256(b"fixture bytes").hexdigest()
        assert size == len(b"fixture bytes")
    link = tmp_path / "link"
    link.symlink_to(source)
    with (
        pytest.raises(ValueError, match="non-symlink"),
        subject.stable_snapshot(link, snapshot_dir),
    ):
        pass


def test_inspect_fixture_keeps_oracle_evidence_out_of_scanner_verdict(monkeypatch):
    monkeypatch.setattr(
        subject, "scanner_observation", lambda _: {"parser": "s", "status": "parsed"}
    )
    monkeypatch.setattr(
        subject, "lief_observation", lambda _: {"parser": "l", "status": "rejected"}
    )
    monkeypatch.setattr(
        subject,
        "llvm_observation",
        lambda *_: {"parser": "llvm", "status": "unavailable"},
    )
    result = subject.inspect_fixture(Path("fixture"), "a" * 64, 1, None)
    assert result["status"] == "disagreement"
    assert result["verdict_effect"] == "none_development_evidence_only"


def test_malformed_input_is_retained_as_rejection(tmp_path):
    fixture = tmp_path / "malformed"
    fixture.write_bytes(b"\x7fELF")
    result = subject.scanner_observation(fixture)
    assert result["status"] == "rejected"
    assert "ELF" in result["reason"]

    retained = Path(__file__).parent / "fixtures/parser/malformed-pe.bin"
    retained_result = subject.scanner_observation(retained)
    assert retained_result["status"] == "rejected"
    assert retained_result["kind"] == "pe"
