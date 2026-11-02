import hashlib
import runpy
import struct
from pathlib import Path

import brotli_flirt as runtime
import brotli_inventory as inventory
import pytest
from brotli_debug_companions import FunctionHint
from test_binary_layout import mach_fixture
from test_flirt import FakeBackend, group, pattern, write_bundle

ROOT = Path(__file__).resolve().parents[1]
BUILDER = runpy.run_path(str(ROOT / "scripts/build_native_flirt_references.py"))
VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_native_flirt_pair.py"))
coff_patterns = BUILDER["coff_patterns"]
macho_patterns = BUILDER["macho_patterns"]
patch_population = BUILDER["patch_population"]
postlink_patterns = BUILDER["postlink_patterns"]
postlink_mach_patterns = BUILDER["postlink_mach_patterns"]
verify_cross = VERIFIER["verify_cross"]
verify_own = VERIFIER["verify_own"]
artifact_assertion = VERIFIER["artifact_assertion"]
verify_mixed_components = VERIFIER["verify_mixed_components"]

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


def postlink_entry(  # noqa: PLR0913
    functions,
    offsets,
    *,
    state="fixed",
    identifier="postlink",
    native=("pe", "windows"),
    machine=62,
):
    roles = {
        role: [next(name for name in PATCH_NAMES if expression.fullmatch(name))]
        for role, expression in BUILDER["PATCH_ROLE_PATTERNS"].items()
    }
    roles["helpers"] = []
    entry = group(
        functions,
        identifier=identifier,
        state=state,
        machine=machine,
        native=native,
    )
    entry.update(
        evidence_scope="postlink_patch_component_v1",
        patch_functions=roles,
        component_offsets=offsets,
        linked_artifact_sha256="d" * 64,
        symbol_evidence_sha256="e" * 64,
        symbol_evidence_format=(
            "llvm-pdbutil-symbols-v1" if native[0] == "pe" else "llvm-dwarfdump-symbols-v1"
        ),
        transformation="LTCG",
    )
    return entry


def test_postlink_profile_requires_one_complete_relative_layout(tmp_path):
    codes = {name: function_code(name + "postlink") for name in PATCH_NAMES}
    offsets = {name: index * 80 for index, name in enumerate(PATCH_NAMES)}
    functions = {name: [name] for name in PATCH_NAMES}
    entry = postlink_entry(functions, offsets, state="vulnerable")
    catalog = runtime.load_flirt_bundle(
        write_bundle(
            tmp_path,
            [pattern(codes[name], name) for name in PATCH_NAMES],
            [entry],
        ),
        backend=FakeBackend(),
    )
    complete = bytearray(max(offsets.values()) + 64)
    for name, offset in offsets.items():
        complete[offset : offset + 64] = codes[name]
    scrambled = b"".join(codes[name] for name in reversed(PATCH_NAMES))

    owned = runtime.match_flirt(pe_executable(complete), catalog)
    unowned = runtime.match_flirt(pe_executable(scrambled), catalog)
    binary_assessment = inventory.assess_binary(pe_executable(complete), [], catalog)

    assert owned["patch_profiles"][0]["target_patch_status"] == "vulnerable_code_match"
    assert owned["patch_profiles"][0]["component_file_offset"] == 0x200
    assert binary_assessment["patch_status"] == "vulnerable_code_match"
    assert unowned["status"] == "recognized"
    assert len(unowned["matches"]) == len(PATCH_NAMES)
    assert unowned["patch_profiles"] == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda entry: entry["component_offsets"].pop(PATCH_NAMES[-1]),
        lambda entry: entry["component_offsets"].update({PATCH_NAMES[-1]: 0}),
        lambda entry: entry.update(symbol_evidence_format="unverified-symbols"),
        lambda entry: entry.update(linked_artifact_sha256="not-a-digest"),
    ],
)
def test_postlink_profile_rejects_unowned_or_unverified_layout(tmp_path, mutate):
    codes = {name: function_code(name + "invalid-postlink") for name in PATCH_NAMES}
    offsets = {name: index * 64 for index, name in enumerate(PATCH_NAMES)}
    functions = {name: [name] for name in PATCH_NAMES}
    entry = postlink_entry(functions, offsets)
    mutate(entry)
    bundle = write_bundle(
        tmp_path,
        [pattern(codes[name], name) for name in PATCH_NAMES],
        [entry],
    )

    with pytest.raises(ValueError, match="post-link FLIRT component evidence"):
        runtime.load_flirt_bundle(bundle, backend=FakeBackend())


def test_postlink_scope_requires_closed_schema_and_exact_code(tmp_path):
    codes = {name: function_code(name + "closed-postlink") for name in PATCH_NAMES}
    offsets = {name: index * 64 for index, name in enumerate(PATCH_NAMES)}
    functions = {name: [name] for name in PATCH_NAMES}
    incomplete = postlink_entry(functions, offsets)
    for field in (
        "component_offsets",
        "linked_artifact_sha256",
        "symbol_evidence_sha256",
        "symbol_evidence_format",
        "transformation",
    ):
        incomplete.pop(field)
    incomplete_bundle = write_bundle(
        tmp_path,
        [pattern(codes[name], name) for name in PATCH_NAMES],
        [incomplete],
    )
    with pytest.raises(ValueError, match="complete closed schema"):
        runtime.load_flirt_bundle(incomplete_bundle, backend=FakeBackend())

    exact_directory = tmp_path / "masked"
    exact_directory.mkdir()
    masked_bundle = write_bundle(
        exact_directory,
        [
            pattern(codes[name], name, wildcards=[4] if name == PATCH_NAMES[0] else [])
            for name in PATCH_NAMES
        ],
        [postlink_entry(functions, offsets)],
    )
    with pytest.raises(ValueError, match="post-link FLIRT component evidence"):
        runtime.load_flirt_bundle(masked_bundle, backend=FakeBackend())


def test_postlink_profile_reports_repeated_copies_separately(tmp_path):
    codes = {name: function_code(name + "copies") for name in PATCH_NAMES}
    offsets = {name: index * 64 for index, name in enumerate(PATCH_NAMES)}
    functions = {name: [name] for name in PATCH_NAMES}
    catalog = runtime.load_flirt_bundle(
        write_bundle(
            tmp_path,
            [pattern(codes[name], name) for name in PATCH_NAMES],
            [postlink_entry(functions, offsets)],
        ),
        backend=FakeBackend(),
    )
    component = b"".join(codes.values())
    assessment = runtime.match_flirt(pe_executable(component + bytes(64) + component), catalog)

    assert [item["component_file_offset"] for item in assessment["patch_profiles"]] == [
        0x200,
        0x200 + len(component) + 64,
    ]
    assert {item["target_patch_status"] for item in assessment["patch_profiles"]} == {
        "fixed_code_match"
    }
    assert (
        inventory.assess_binary(pe_executable(component + bytes(64) + component), [], catalog)[
            "patch_status"
        ]
        == "unknown"
    )


def test_affected_and_fixed_postlink_components_report_mixed_code(tmp_path):
    affected_codes = {name: function_code(name + "affected-mixed") for name in PATCH_NAMES}
    fixed_codes = {name: function_code(name + "fixed-mixed") for name in PATCH_NAMES}
    offsets = {name: index * 64 for index, name in enumerate(PATCH_NAMES)}
    affected_functions = {name: ["affected_" + name] for name in PATCH_NAMES}
    fixed_functions = {name: ["fixed_" + name] for name in PATCH_NAMES}
    groups = [
        postlink_entry(
            affected_functions,
            offsets,
            state="vulnerable",
            identifier="affected-postlink",
        ),
        postlink_entry(fixed_functions, offsets, state="fixed", identifier="fixed-postlink"),
    ]
    lines = [
        *[pattern(affected_codes[name], "affected_" + name) for name in PATCH_NAMES],
        *[pattern(fixed_codes[name], "fixed_" + name) for name in PATCH_NAMES],
    ]
    catalog = runtime.load_flirt_bundle(
        write_bundle(tmp_path, lines, groups), backend=FakeBackend()
    )
    affected_component = b"".join(affected_codes.values())
    fixed_component = b"".join(fixed_codes.values())
    target = pe_executable(affected_component + bytes(64) + fixed_component)

    assessment = inventory.assess_binary(target, [], catalog)

    assert assessment["patch_status"] == "mixed_code_matches"
    assert {
        profile["target_patch_status"] for profile in assessment["flirt"]["patch_profiles"]
    } == {"vulnerable_code_match", "fixed_code_match"}


def test_postlink_builder_uses_verified_bounds_and_rejects_aliases():
    payload = b"".join(function_code(name + "bounds") for name in PATCH_NAMES)
    binary = pe_executable(payload)
    hints = tuple(
        FunctionHint(
            name=name,
            virtual_address=0x1000 + index * 64,
            size=64,
            file_offset=0x200 + index * 64,
        )
        for index, name in enumerate(PATCH_NAMES)
    )

    patterns, offsets, format_name, machine, abi = postlink_patterns(binary, hints)

    assert (format_name, machine, abi) == ("pe", 62, "windows")
    assert {item.name for item in patterns} == set(PATCH_NAMES)
    assert offsets[PATCH_NAMES[0]] == 0
    with pytest.raises(ValueError, match="overlap or alias"):
        postlink_patterns(
            binary,
            (
                hints[0],
                FunctionHint(
                    hints[1].name,
                    0x1000,
                    hints[1].size,
                    hints[1].file_offset,
                ),
            ),
        )


def test_mach_postlink_builder_keeps_uuid_slice_ownership():
    payload = b"".join(function_code(name + "mach-bounds") for name in PATCH_NAMES)
    binary = bytearray(mach_fixture())
    binary[0x200 : 0x200 + len(payload)] = payload
    hints = tuple(
        FunctionHint(
            name=name,
            virtual_address=0x100000 + index * 64,
            size=64,
            file_offset=0x200 + index * 64,
            source_file="decode.c",
            source_line=index + 1,
        )
        for index, name in enumerate(PATCH_NAMES)
    )

    patterns, offsets, format_name, machine, abi = postlink_mach_patterns(
        bytes(binary), hints, bytes(range(16)).hex()
    )

    assert (format_name, machine, abi) == ("mach_o", 183, "darwin")
    assert {item.name for item in patterns} == set(PATCH_NAMES)
    assert offsets[PATCH_NAMES[0]] == 0
    with pytest.raises(ValueError, match="slice owner"):
        postlink_mach_patterns(bytes(binary), hints, "f" * 32)


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


def paired_fixture(tmp_path, state, salt, *, component_bound=False):
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
    if component_bound:
        entry = postlink_entry(
            functions,
            {name: index * 64 for index, name in enumerate(PATCH_NAMES)},
            state=state,
        )
    else:
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


def test_component_bound_pair_keeps_mixed_copies_separate(tmp_path):
    pytest.importorskip("flirt")
    affected_binary, affected_bundle = paired_fixture(
        tmp_path, "vulnerable", "old-component", component_bound=True
    )
    fixed_binary, fixed_bundle = paired_fixture(
        tmp_path, "fixed", "new-component", component_bound=True
    )

    affected = verify_own(affected_binary, affected_bundle, "vulnerable", component_bound=True)
    fixed = verify_own(fixed_binary, fixed_bundle, "fixed", component_bound=True)
    assert affected["patch_profiles"][0]["component_file_offset"] == 0x200
    assert fixed["patch_profiles"][0]["component_file_offset"] == 0x200
    control = verify_mixed_components(affected_binary, affected_bundle, fixed_binary, fixed_bundle)
    assert control["status"] == "separate_components_verified"
    assert control["vulnerable_component_offsets"] != control["fixed_component_offsets"]


def test_component_bound_mach_pair_keeps_mixed_copies_separate(tmp_path):
    pytest.importorskip("flirt")
    fixtures = []
    for state, salt in (("vulnerable", "old-mach"), ("fixed", "new-mach")):
        directory = tmp_path / state
        directory.mkdir()
        codes = {name: function_code(name + salt) for name in PATCH_NAMES}
        functions = {name: [name] for name in PATCH_NAMES}
        entry = postlink_entry(
            functions,
            {name: index * 64 for index, name in enumerate(PATCH_NAMES)},
            state=state,
            native=("mach_o", "darwin"),
            machine=183,
        )
        bundle = write_bundle(
            directory,
            [pattern(codes[name], name) for name in PATCH_NAMES],
            [entry],
        )
        binary_data = bytearray(mach_fixture())
        binary_data[0x200:0x400] = b"".join(codes.values())
        binary = directory / "libbrotlidec.dylib"
        binary.write_bytes(binary_data)
        fixtures.append((binary, bundle))

    control = verify_mixed_components(
        fixtures[0][0], fixtures[0][1], fixtures[1][0], fixtures[1][1]
    )

    assert control["status"] == "separate_components_verified"
    assert control["vulnerable_components"] != control["fixed_components"]
