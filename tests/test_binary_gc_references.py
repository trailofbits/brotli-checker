import copy
import hashlib
import struct
import sys
from pathlib import Path
from typing import TypedDict

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/brotli-checker/scripts"
sys.path.insert(0, str(SCRIPTS))
import brotli_binary_match as matcher  # noqa: E402
from test_binary_match import relocatable  # noqa: E402

ROLE_NAMES = {
    "literal": "DecodeLiteralBlockSwitch",
    "command": "DecodeCommandBlockSwitchInternal",
    "distance": "DecodeDistanceBlockSwitch",
    "safe_literal": "SafeDecodeLiteralBlockSwitchInternal",
    "safe_command": "SafeDecodeCommandBlockSwitch",
    "safe_distance": "SafeDecodeDistanceBlockSwitchInternal",
    "process": "ProcessCommandsInternal",
    "safe_process": "SafeProcessCommands",
}
HELPER_NAMES = [
    "DecodeBlockTypeAndLength",
    "DecodeBlockTypeAndLengthInternal.constprop.0",
    "SafeDecodeBlockTypeAndLengthInternal.cold",
]


class CodeSpec(TypedDict):
    content: bytes
    names: list[str]


def metadata(state="fixed", salt=b"fixed"):
    return {
        "id": state + salt.hex(),
        "state": state,
        "source_sha256": hashlib.sha256(b"source" + salt).hexdigest(),
        "object_sha256": hashlib.sha256(b"placeholder").hexdigest(),
        "source": "trusted test fixture",
        "compiler": "fixture compiler",
        "flags": "-O2 -ffunction-sections",
    }


def _code(name, salt, size):
    block = hashlib.sha256(salt + name.encode()).digest()
    return (block * ((size + len(block) - 1) // len(block)))[:size]


def relocatable_function_sections(  # noqa: C901 -- One compact ELF fixture builder.
    *,
    salt=b"fixed",
    missing_role=None,
    colocated=False,
    unrelated=20,
    malformed_role=None,
):
    names = [name for role, name in ROLE_NAMES.items() if role != missing_role]
    names.extend(HELPER_NAMES)
    code_specs: list[CodeSpec] = []
    symbols = []
    if colocated:
        contents = _code("complete-text", salt, 768)
        code_specs.append({"content": contents, "names": names})
    else:
        for name in names:
            size = 320 if name == ROLE_NAMES["process"] else 64
            code_specs.append({"content": _code(name, salt, size), "names": [name]})
    code_specs.extend(
        {"content": _code(f"unrelated-{index}", salt, 48), "names": []}
        for index in range(unrelated)
    )

    offset = matcher.ELF_HEADER.size
    payload = bytearray()
    section_rows = [(0,) * 10]
    for spec in code_specs:
        section_index = len(section_rows)
        section_offset = offset + len(payload)
        payload.extend(spec["content"])
        section_type = matcher.SHT_PROGBITS
        section_flags = matcher.SHF_ALLOC | matcher.SHF_EXECINSTR
        if any(name == ROLE_NAMES.get(malformed_role) for name in spec["names"]):
            if malformed_role == "literal":
                section_type = 8  # SHT_NOBITS cannot own file-backed functions.
            elif malformed_role == "command":
                section_flags = matcher.SHF_EXECINSTR
        section_rows.append(
            (
                0,
                section_type,
                section_flags,
                0,
                section_offset,
                len(spec["content"]),
                0,
                0,
                16,
                0,
            )
        )
        stride = max(1, len(spec["content"]) // max(1, len(spec["names"])))
        for symbol_index, name in enumerate(spec["names"]):
            address = symbol_index * stride
            size = min(16, len(spec["content"]) - address)
            if malformed_role == "distance" and name == ROLE_NAMES["distance"]:
                size = len(spec["content"]) + 1
            symbols.append((name, section_index, address, size))

    strings = bytearray(b"\0")
    name_offsets = {}
    for name, _, _, _ in symbols:
        name_offsets[name] = len(strings)
        strings.extend(name.encode() + b"\0")
    string_index = len(section_rows)
    string_offset = offset + len(payload)
    payload.extend(strings)
    section_rows.append((0, matcher.SHT_STRTAB, 0, 0, string_offset, len(strings), 0, 0, 1, 0))

    symbol_struct = struct.Struct("<IBBHQQ")
    symbol_bytes = bytearray(symbol_struct.size)
    for name, section_index, address, size in symbols:
        symbol_bytes.extend(
            symbol_struct.pack(
                name_offsets[name], matcher.STT_FUNC, 0, section_index, address, size
            )
        )
    symbol_offset = offset + len(payload)
    payload.extend(symbol_bytes)
    section_rows.append(
        (
            0,
            matcher.SHT_SYMTAB,
            0,
            0,
            symbol_offset,
            len(symbol_bytes),
            string_index,
            len(symbols) + 1,
            8,
            symbol_struct.size,
        )
    )
    section_offset = offset + len(payload)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = matcher.ELF_HEADER.pack(
        ident,
        1,
        matcher.EM_AARCH64,
        1,
        0,
        0,
        section_offset,
        0,
        matcher.ELF_HEADER.size,
        0,
        0,
        matcher.SECTION_HEADER.size,
        len(section_rows),
        0,
    )
    return header + payload + b"".join(matcher.SECTION_HEADER.pack(*row) for row in section_rows)


def linked_elf(payload):
    data_offset = matcher.ELF_HEADER.size + matcher.PROGRAM_HEADER.size
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = matcher.ELF_HEADER.pack(
        ident,
        2,
        matcher.EM_AARCH64,
        1,
        0,
        matcher.ELF_HEADER.size,
        0,
        0,
        matcher.ELF_HEADER.size,
        matcher.PROGRAM_HEADER.size,
        1,
        0,
        0,
        0,
    )
    program = matcher.PROGRAM_HEADER.pack(
        1, 5, data_offset, 0x400000, 0x400000, len(payload), len(payload), 16
    )
    return header + program + payload


def reference_sections(entry):
    return [
        bytes.fromhex(entry["code"]),
        *(bytes.fromhex(part["code"]) for part in entry.get("additional_sections", [])),
    ]


def test_auto_single_text_preserves_legacy_without_function_symbols():
    obj = relocatable()
    complete = matcher.reference_from_object(obj, metadata(), section_scope="complete")
    assert matcher.reference_from_object(obj, metadata(), section_scope="auto") == complete
    with pytest.raises(ValueError, match="Cannot establish"):
        matcher.reference_from_object(obj, metadata(), section_scope="patch")


def test_auto_scope_selects_bounded_patch_population_after_input_enumeration():
    obj = relocatable_function_sections(unrelated=20)
    entry = matcher.reference_from_object(obj, metadata(), section_scope="auto")

    assert entry["code_scope"] == matcher.REFERENCE_SCOPE_PATCH
    assert set(entry["patch_functions"]) == {*ROLE_NAMES, "helpers"}
    assert entry["patch_functions"]["helpers"] == sorted(HELPER_NAMES)
    assert 1 + len(entry["additional_sections"]) == len(ROLE_NAMES) + len(HELPER_NAMES)
    assert len(entry["section_functions"]) == 1 + len(entry["additional_sections"])
    assert {name for names in entry["section_functions"] for name in names} == set(
        ROLE_NAMES.values()
    ) | set(HELPER_NAMES)

    assessment = matcher.match_code(
        linked_elf(b"padding".join(reference_sections(entry))),
        [matcher.CodeReference.from_json(entry)],
    )
    assert assessment.patch_status == "fixed_code_match"
    assert assessment.matches[0]["method"] == "relocation_masked_patch_sections"


@pytest.mark.parametrize("missing_role", ROLE_NAMES)
def test_patch_scope_requires_every_semantic_role(missing_role):
    obj = relocatable_function_sections(missing_role=missing_role)
    with pytest.raises(ValueError, match=missing_role):
        matcher.reference_from_object(obj, metadata(), section_scope="auto")


@pytest.mark.parametrize("malformed_role", ["literal", "command", "distance"])
def test_patch_scope_rejects_non_file_backed_or_out_of_range_role(malformed_role):
    obj = relocatable_function_sections(malformed_role=malformed_role)
    with pytest.raises(ValueError, match=malformed_role):
        matcher.reference_from_object(obj, metadata(), section_scope="patch")


def test_separate_helper_sections_are_required_to_match():
    entry = matcher.reference_from_object(
        relocatable_function_sections(), metadata(), section_scope="patch"
    )
    sections = reference_sections(entry)
    helper_index = next(
        index
        for index, names in enumerate(entry["section_functions"])
        if any(name in HELPER_NAMES for name in names)
    )
    del sections[helper_index]

    assessment = matcher.match_code(
        linked_elf(b"padding".join(sections)), [matcher.CodeReference.from_json(entry)]
    )
    assert assessment.patch_status == "unknown"


def test_co_located_patch_functions_preserve_complete_reference_semantics():
    entry = matcher.reference_from_object(
        relocatable_function_sections(colocated=True, unrelated=1),
        metadata(),
        section_scope="auto",
    )
    assert "code_scope" not in entry
    assert "patch_functions" not in entry
    assert len(entry["additional_sections"]) == 1
    assessment = matcher.match_code(
        linked_elf(b"padding".join(reference_sections(entry))),
        [matcher.CodeReference.from_json(entry)],
    )
    assert assessment.matches[0]["method"] == "relocation_masked_decoder_text"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda entry: entry.update(section_functions=entry["section_functions"][:-1]),
        lambda entry: entry["patch_functions"].update(literal=["ProcessCommands"]),
        lambda entry: entry["section_functions"][0].append("unbound function"),
    ],
)
def test_patch_reference_schema_binds_roles_to_serialized_sections(mutate):
    entry = matcher.reference_from_object(
        relocatable_function_sections(), metadata(), section_scope="patch"
    )
    mutate(entry)
    with pytest.raises(ValueError, match="patch-bearing"):
        matcher.CodeReference.from_json(entry)


def test_opposite_states_do_not_satisfy_each_other_and_complete_population_is_mixed():
    vulnerable = matcher.reference_from_object(
        relocatable_function_sections(salt=b"vulnerable"),
        metadata("vulnerable", b"vulnerable"),
        section_scope="patch",
    )
    fixed = matcher.reference_from_object(
        relocatable_function_sections(salt=b"fixed"),
        metadata("fixed", b"fixed"),
        section_scope="patch",
    )
    references = [
        matcher.CodeReference.from_json(vulnerable),
        matcher.CodeReference.from_json(fixed),
    ]
    vulnerable_payload = b"padding".join(reference_sections(vulnerable))
    fixed_payload = b"padding".join(reference_sections(fixed))

    assert matcher.match_code(linked_elf(vulnerable_payload), references).patch_status == (
        "vulnerable_code_match"
    )
    assert matcher.match_code(linked_elf(fixed_payload), references).patch_status == (
        "fixed_code_match"
    )
    assert (
        matcher.match_code(
            linked_elf(vulnerable_payload + b"padding" + fixed_payload), references
        ).patch_status
        == "mixed_code_matches"
    )

    incomplete = copy.deepcopy(vulnerable)
    sections = reference_sections(incomplete)
    sections.pop()
    assert matcher.match_code(linked_elf(b"padding".join(sections)), references).patch_status == (
        "unknown"
    )
