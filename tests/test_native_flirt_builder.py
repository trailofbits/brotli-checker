import hashlib
import runpy
import struct
from pathlib import Path

import brotli_flirt as runtime
import brotli_inventory as inventory
import pytest
from test_flirt import FakeBackend, group, pattern, write_bundle

ROOT = Path(__file__).resolve().parents[1]
BUILDER = runpy.run_path(str(ROOT / "scripts/build_native_flirt_references.py"))
VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_native_flirt_pair.py"))
coff_patterns = BUILDER["coff_patterns"]
macho_patterns = BUILDER["macho_patterns"]
patch_population = BUILDER["patch_population"]
verify_cross = VERIFIER["verify_cross"]
verify_own = VERIFIER["verify_own"]
artifact_assertion = VERIFIER["artifact_assertion"]

PATCH_NAMES = (
    "DecodeLiteralBlockSwitch",
    "DecodeCommandBlockSwitch",
    "DecodeDistanceBlockSwitch",
    "SafeDecodeLiteralBlockSwitch",
    "SafeDecodeCommandBlockSwitch",
    "SafeDecodeDistanceBlockSwitch",
    "ProcessCommands",
    "SafeProcessCommands",
)


def function_code(name):
    return (hashlib.sha256(name.encode()).digest() * 2)[:64]


def coff_object():
    header_size = 20 + len(PATCH_NAMES) * 40
    code_offsets = [header_size + index * 64 for index in range(len(PATCH_NAMES))]
    relocation_offset = header_size + len(PATCH_NAMES) * 64
    symbol_offset = relocation_offset + 10
    symbol_count = len(PATCH_NAMES) * 2
    strings = bytearray(b"\x04\0\0\0")
    names = []
    for name in PATCH_NAMES:
        names.append(len(strings))
        strings.extend(name.encode() + b"\0")
    struct.pack_into("<I", strings, 0, len(strings))
    result = bytearray(symbol_offset + symbol_count * 18 + len(strings))
    struct.pack_into(
        "<HHIIIHH", result, 0, 0x8664, len(PATCH_NAMES), 0, symbol_offset, symbol_count, 0, 0
    )
    for index, (name, code_offset) in enumerate(zip(PATCH_NAMES, code_offsets, strict=True)):
        section_offset = 20 + index * 40
        relocations = 1 if index == 0 else 0
        struct.pack_into(
            "<8sIIIIIIHHI",
            result,
            section_offset,
            f".t${index}".encode().ljust(8, b"\0"),
            0,
            0,
            64,
            code_offset,
            relocation_offset if relocations else 0,
            0,
            relocations,
            0,
            0x60000020,
        )
        result[code_offset : code_offset + 64] = function_code(name)
        symbol = symbol_offset + index * 36
        result[symbol : symbol + 8] = bytes(4) + names[index].to_bytes(4, "little")
        struct.pack_into("<IhHBB", result, symbol + 8, 0, index + 1, 0x20, 2, 1)
        struct.pack_into("<I", result, symbol + 18 + 4, 64)
    struct.pack_into("<IIH", result, relocation_offset, 4, 0, 4)
    result[-len(strings) :] = strings
    return bytes(result)


def macho_object():
    segment_size = 72 + len(PATCH_NAMES) * 80
    command_size = segment_size + 24
    code_offset = 32 + command_size
    symbol_offset = code_offset + len(PATCH_NAMES) * 64
    string_offset = symbol_offset + len(PATCH_NAMES) * 16
    strings = bytearray(b"\0")
    names = []
    for name in PATCH_NAMES:
        names.append(len(strings))
        strings.extend(("_" + name).encode() + b"\0")
    result = bytearray(string_offset + len(strings))
    struct.pack_into("<8I", result, 0, 0xFEEDFACF, 0x0100000C, 0, 1, 2, command_size, 0, 0)
    struct.pack_into(
        "<II16sQQQQIIII",
        result,
        32,
        0x19,
        segment_size,
        b"__TEXT" + bytes(10),
        0,
        len(PATCH_NAMES) * 64,
        code_offset,
        len(PATCH_NAMES) * 64,
        7,
        5,
        len(PATCH_NAMES),
        0,
    )
    for index, name in enumerate(PATCH_NAMES):
        struct.pack_into(
            "<16s16sQQIIIIIIII",
            result,
            32 + 72 + index * 80,
            f"__t{index}".encode().ljust(16, b"\0"),
            b"__TEXT" + bytes(10),
            index * 64,
            64,
            code_offset + index * 64,
            4,
            0,
            0,
            0x80000400,
            0,
            0,
            0,
        )
        result[code_offset + index * 64 : code_offset + (index + 1) * 64] = function_code(name)
        struct.pack_into(
            "<IBBHQ",
            result,
            symbol_offset + index * 16,
            names[index],
            0x0F,
            index + 1,
            0,
            index * 64,
        )
    struct.pack_into(
        "<6I",
        result,
        32 + segment_size,
        2,
        24,
        symbol_offset,
        len(PATCH_NAMES),
        string_offset,
        len(strings),
    )
    result[string_offset:] = strings
    return bytes(result)


def pe_executable(payload):
    result = bytearray(0x200 + len(payload))
    result[:2] = b"MZ"
    struct.pack_into("<I", result, 0x3C, 0x80)
    result[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", result, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", result, 0x98, 0x20B)
    section = 0x98 + 0xF0
    result[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", result, section + 8, len(payload), 0x1000, len(payload), 0x200)
    struct.pack_into("<I", result, section + 36, 0x60000020)
    result[0x200:] = payload
    return bytes(result)


def test_coff_extracts_and_masks_complete_patch_population():
    patterns, format_name, machine, abi = coff_patterns(coff_object())

    assert (format_name, machine, abi) == ("pe", 62, "windows")
    assert {item.name for item in patterns} == set(PATCH_NAMES)
    assert patterns[0].mask[4:8] == bytes(4)
    assert patch_population(patterns)["safe_process"] == ["SafeProcessCommands"]


def test_macho_extracts_complete_patch_population():
    patterns, format_name, machine, abi = macho_patterns(macho_object())

    assert (format_name, machine, abi) == ("mach_o", 183, "darwin")
    assert {item.name for item in patterns} == set(PATCH_NAMES)
    assert all(item.mask == b"\xff" * 64 for item in patterns)
    assert patch_population(patterns)["literal"] == ["DecodeLiteralBlockSwitch"]


def test_complete_native_patch_population_remains_provenance_without_copy_binding(tmp_path):
    patterns, _, _, _ = coff_patterns(coff_object())
    functions = {item.name: [item.signature_id] for item in patterns}
    roles = patch_population(patterns)
    entry = group(functions, state="vulnerable", machine=62, native=("pe", "windows"))
    entry.update(evidence_scope="patch_bearing_population_v1", patch_functions=roles)
    lines = [
        pattern(
            item.code,
            item.signature_id,
            wildcards=[index for index, value in enumerate(item.mask) if not value],
        )
        for item in patterns
    ]
    catalog = runtime.load_flirt_bundle(
        write_bundle(tmp_path, lines, [entry]), backend=FakeBackend()
    )
    target = pe_executable(b"".join(item.code for item in patterns))

    assessment = inventory.assess_binary(target, [], catalog)

    assert assessment["patch_status"] == "unknown"
    assert assessment["kind"] == "decoder_function_signature"
    profile = assessment["flirt"]["patch_profiles"][0]
    assert profile["source_state"] == "provenance_only"
    assert profile["source_state_provenance"] == "vulnerable"
    assert profile["target_patch_status"] == "unknown"


def test_runtime_rejects_incomplete_patch_role_population(tmp_path):
    code = function_code(PATCH_NAMES[0])
    entry = group({PATCH_NAMES[0]: ["native"]}, native=("pe", "windows"))
    entry.update(
        evidence_scope="patch_bearing_population_v1",
        patch_functions={
            "literal": [PATCH_NAMES[0]],
            "command": [],
            "distance": [],
            "safe_literal": [],
            "safe_command": [],
            "safe_distance": [],
            "process": [],
            "safe_process": [],
            "helpers": [],
        },
    )
    bundle = write_bundle(tmp_path, [pattern(code, "native")], [entry])

    with pytest.raises(ValueError, match="identity or provenance"):
        runtime.load_flirt_bundle(bundle, backend=FakeBackend())


def paired_fixture(tmp_path, state, salt):
    directory = tmp_path / state
    directory.mkdir()
    codes = {name: function_code(name + salt) for name in PATCH_NAMES}
    functions = {name: [name] for name in PATCH_NAMES}
    roles = {
        role: [next(name for name in PATCH_NAMES if expression.fullmatch(name))]
        for role, expression in BUILDER["PATCH_ROLE_PATTERNS"].items()
    }
    roles["helpers"] = []
    entry = group(functions, state=state, machine=62, native=("pe", "windows"))
    entry.update(evidence_scope="patch_bearing_population_v1", patch_functions=roles)
    bundle = write_bundle(
        directory,
        [pattern(codes[name], name) for name in PATCH_NAMES],
        [entry],
    )
    binary = directory / "brotlidec.dll"
    binary.write_bytes(pe_executable(b"".join(codes.values())))
    return binary, bundle


def test_paired_native_profiles_match_own_state_and_reject_opposite_state(tmp_path):
    pytest.importorskip("flirt")
    affected_binary, affected_bundle = paired_fixture(tmp_path, "vulnerable", "old")
    fixed_binary, fixed_bundle = paired_fixture(tmp_path, "fixed", "new")

    affected = verify_own(affected_binary, affected_bundle, "vulnerable")
    fixed = verify_own(fixed_binary, fixed_bundle, "fixed")
    assert affected["patch_profiles"]
    assert fixed["patch_profiles"]
    verify_cross(fixed_binary, affected_bundle, "vulnerable")
    verify_cross(affected_binary, fixed_bundle, "fixed")
    assertion = artifact_assertion(fixed_binary, "fixed", fixed)
    assert assertion["patch_status"] == "fixed_code_match"
    assert assertion["negative_control"] == "opposite_source_state_rejected"
    assert assertion["provenance"][0]["source_state"] == "fixed"
