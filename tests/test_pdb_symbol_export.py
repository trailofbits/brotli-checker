import hashlib
import json
import sys

import brotli_debug_companions as debug
import export_pdb_symbols as exporter
import pytest
from test_binary_layout import pe_fixture
from test_debug_companions import pdb


def packet(pe, companion, *, functions=None):
    identity = debug.debug_identity(companion).identity
    assert identity is not None
    return {
        "schema_version": 1,
        "format": "llvm-pdbutil-symbols-v1",
        "pe_sha256": hashlib.sha256(pe).hexdigest(),
        "pdb_sha256": hashlib.sha256(companion).hexdigest(),
        "pdb_identity": {"guid": identity.pdb_guid, "age": identity.pdb_age},
        "generator": {"name": "llvm-pdbutil", "version": "LLVM 21", "sha256": "a" * 64},
        "functions": functions
        if functions is not None
        else [{"name": "DecodeCommands", "rva": 0x1000, "size": 16}],
    }


def test_symbol_packet_binds_pe_pdb_tool_and_executable_function():
    pe = pe_fixture()
    companion = pdb(bytes(range(16)), 3)
    result = debug.verify_pdb_symbol_export(
        pe, companion, json.dumps(packet(pe, companion)).encode()
    )
    assert result.status == "verified"
    assert result.patch_status == "unknown"
    assert result.gaps == ()
    assert result.function_hints == (debug.FunctionHint("DecodeCommands", 0x1000, 16, 0x400),)
    assert result.as_dict()["patch_status"] == "unknown"
    assert debug.pdb_symbol_export_targets(json.dumps(packet(pe, companion)).encode()) == (
        hashlib.sha256(pe).hexdigest(),
        hashlib.sha256(companion).hexdigest(),
    )


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (lambda value: value.update(pe_sha256="b" * 64), "PE hash"),
        (lambda value: value.update(pdb_sha256="b" * 64), "PDB hash"),
        (lambda value: value["pdb_identity"].update(age=4), "GUID/age"),
        (lambda value: value["generator"].update(name="unknown"), "llvm-pdbutil"),
        (lambda value: value.update(schema_version=True), "schema"),
        (lambda value: value["functions"][0].update(rva=0x2000), "executable PE"),
        (lambda value: value["functions"][0].update(size=0), "function"),
        (lambda value: value["functions"].append(dict(value["functions"][0])), "duplicate"),
    ],
    ids=("pe-hash", "pdb-hash", "identity", "tool", "schema-bool", "data", "zero", "duplicate"),
)
def test_symbol_packet_malformed_or_unbound_evidence_stays_unresolved(mutation, reason):
    pe = pe_fixture()
    companion = pdb(bytes(range(16)), 3)
    value = packet(pe, companion)
    mutation(value)
    result = debug.verify_pdb_symbol_export(pe, companion, json.dumps(value).encode())
    assert result.status == "unresolved"
    assert result.function_hints == ()
    assert reason in result.gaps[0].reason
    assert result.patch_status == "unknown"


def test_symbol_packet_enforces_byte_and_function_limits():
    pe = pe_fixture()
    companion = pdb(bytes(range(16)), 3)
    raw = json.dumps(packet(pe, companion)).encode()
    limited = debug.verify_pdb_symbol_export(
        pe, companion, raw, debug.DebugLimits(max_identity_bytes=len(raw) - 1)
    )
    excessive = debug.verify_pdb_symbol_export(
        pe, companion, raw, debug.DebugLimits(max_function_hints=0 + 1)
    )
    assert limited.limited is True
    assert limited.gaps[0].code == "pdb_symbol_export_limit"
    assert excessive.status == "verified"
    two = packet(
        pe,
        companion,
        functions=[
            {"name": "one", "rva": 0x1000, "size": 1},
            {"name": "two", "rva": 0x1001, "size": 1},
        ],
    )
    result = debug.verify_pdb_symbol_export(
        pe,
        companion,
        json.dumps(two).encode(),
        debug.DebugLimits(max_function_hints=1),
    )
    assert result.status == "unresolved"
    assert "excessive" in result.gaps[0].reason

    duplicate = raw.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1')
    result = debug.verify_pdb_symbol_export(pe, companion, duplicate)
    assert result.status == "unresolved"
    assert "Duplicate" in result.gaps[0].reason


def test_llvm_dump_parser_uses_hex_section_offsets_and_executable_sections():
    sections = exporter.pe_sections(pe_fixture())
    output = """
 | 10 | S_GPROC32 [size = 60] `DecodeOne`
 | parent = 0, end = 70, addr = 0001:0010, code size = 16
 | 80 | S_LPROC32_ID [size = 52] `DecodeTwo`
 | parent = 0, end = 132, addr = 0001:0020, code size = 8
"""
    assert exporter.parse_symbols(output, sections) == [
        {"name": "DecodeOne", "rva": 0x1010, "size": 16},
        {"name": "DecodeTwo", "rva": 0x1020, "size": 8},
    ]
    with pytest.raises(ValueError, match="executable"):
        exporter.parse_symbols(
            " | 10 | S_GPROC32 [size = 60] `Data`\n | addr = 0002:0000, code size = 1",
            sections,
        )


def test_explicit_generator_records_exact_commands_and_self_verifies(tmp_path, monkeypatch):
    pe_path, pdb_path = tmp_path / "app.exe", tmp_path / "fixture.pdb"
    output = tmp_path / "symbols.json"
    pe_path.write_bytes(pe_fixture())
    pdb_path.write_bytes(pdb(bytes(range(16)), 3))
    commands = []

    def fake_output(command, _timeout, _limit):
        commands.append(command)
        if "--version" in command:
            return "LLVM PDB Utilities version 21.0.0\n"
        return (
            " | 10 | S_GPROC32 [size = 60] `DecodeCommands`\n"
            " | parent = 0, end = 70, addr = 0001:0000, code size = 16\n"
        )

    monkeypatch.setattr(exporter, "tool_output", fake_output)
    assert (
        exporter.main(
            [
                str(pe_path),
                str(pdb_path),
                "--llvm-pdbutil",
                sys.executable,
                "--output",
                str(output),
            ]
        )
        == 0
    )
    stored = json.loads(output.read_text())
    assert stored["functions"] == [{"name": "DecodeCommands", "rva": 0x1000, "size": 16}]
    resolved_tool = str(exporter.trusted_tool(sys.executable))
    assert commands[0] == [resolved_tool, "--version"]
    assert commands[1][:3] == [resolved_tool, "dump", "--symbols"]
    assert commands[1][3].endswith("/companion.pdb")
    assert commands[1][3] != str(pdb_path)
    verified = debug.verify_pdb_symbol_export(
        pe_path.read_bytes(), pdb_path.read_bytes(), output.read_bytes()
    )
    assert verified.status == "verified"
    with pytest.raises(SystemExit) as error:
        exporter.main(
            [
                str(pe_path),
                str(pdb_path),
                "--llvm-pdbutil",
                sys.executable,
                "--output",
                str(output),
            ]
        )
    assert error.value.code == 2


def test_stable_mapped_input_uses_open_handle_identity_and_detects_mutation(tmp_path, monkeypatch):
    path = tmp_path / "input.bin"
    path.write_bytes(b"original")
    actual = exporter.path_identity_no_follow(path)
    monkeypatch.setattr(
        exporter, "path_identity_no_follow", lambda _path: (actual[0], actual[1] + 1)
    )
    with (
        pytest.raises(ValueError, match=r"identity changed.*path=.*handle="),
        exporter.stable_data(path),
    ):
        pass

    monkeypatch.setattr(exporter, "path_identity_no_follow", lambda _path: actual)

    def mutate_open_input():
        with exporter.stable_data(path) as data:
            assert data[:] == b"original"
            path.write_bytes(b"modified!")

    with pytest.raises(ValueError, match="changed while exporting"):
        mutate_open_input()


def test_portable_mapped_inputs_share_chunked_hashing_without_pread(tmp_path, monkeypatch):
    artifact = tmp_path / "mapped.bin"
    content = b"sparse-readable-mapping"
    artifact.write_bytes(content)

    def forbidden(*_args):
        pytest.fail("portable PDB inputs must not require os.pread")

    monkeypatch.setattr(exporter.os, "pread", forbidden, raising=False)
    with exporter.stable_data(artifact) as data:
        assert data.startswith(b"sparse")
        assert data.find(b"mapping") == content.index(b"mapping")
        assert exporter.sha256_buffer(data) == hashlib.sha256(content).hexdigest()
        assert data.read(6) == b"sparse"
        assert data.seek(0) == 0
        assert data.read() == content
