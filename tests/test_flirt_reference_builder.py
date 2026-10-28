import hashlib
import json
import runpy
import struct
from pathlib import Path

import brotli_binary_match as matcher
import pytest
from test_binary_metadata import CODE_ADDRESS, elf_with_symbols

ROOT = Path(__file__).resolve().parents[1]
BUILDER = runpy.run_path(str(ROOT / "scripts/build_flirt_references.py"))
FunctionPattern = BUILDER["FunctionPattern"]
patterns_from_object = BUILDER["patterns_from_object"]
load_catalog = BUILDER["load_catalog"]
merge_catalogs = BUILDER["merge_catalogs"]
prune_ambiguous_names = BUILDER["prune_ambiguous_names"]
render_pattern = BUILDER["render_pattern"]
render_pat = BUILDER["render_pat"]
resolve_ambiguities = BUILDER["resolve_ambiguities"]
validate_pat = BUILDER["validate_pat"]
validated_bundle = BUILDER["validated_bundle"]
write_catalog = BUILDER["write_catalog"]


def relocatable_with_symbols(code, symbols, machine=62):
    data = bytearray(elf_with_symbols(code, machine, symbols))
    struct.pack_into("<H", data, 16, 1)  # ET_REL; section layout remains self-contained.
    return bytes(data)


def arm_thumb_relocatable(code):
    layout = matcher.ELFLayout(32, "little")
    header_struct = layout.parser("header")
    section_struct = layout.parser("section")
    symbol_struct = layout.parser("symbol")
    code_offset = 0x100
    strings = b"\0SafeProcessCommands\0"
    symbol_data = bytes(symbol_struct.size) + symbol_struct.pack(
        1, 1, len(code), matcher.STT_FUNC, 0, 1
    )
    symbol_offset = code_offset + len(code)
    string_offset = symbol_offset + len(symbol_data)
    section_offset = (string_offset + len(strings) + 3) & ~3
    sections = [
        (0,) * 10,
        (0, matcher.SHT_PROGBITS, 6, 0, code_offset, len(code), 0, 0, 4, 0),
        (0, matcher.SHT_STRTAB, 0, 0, string_offset, len(strings), 0, 0, 1, 0),
        (
            0,
            matcher.SHT_SYMTAB,
            0,
            0,
            symbol_offset,
            len(symbol_data),
            2,
            0,
            4,
            symbol_struct.size,
        ),
    ]
    header = header_struct.pack(
        b"\x7fELF\x01\x01\x01" + bytes(9),
        1,
        matcher.EM_ARM,
        1,
        0,
        0,
        section_offset,
        0,
        header_struct.size,
        0,
        0,
        section_struct.size,
        len(sections),
        0,
    )
    result = bytearray(header)
    result.extend(bytes(code_offset - len(result)))
    result.extend(code)
    result.extend(symbol_data)
    result.extend(strings)
    result.extend(bytes(section_offset - len(result)))
    result.extend(b"".join(section_struct.pack(*section) for section in sections))
    return bytes(result)


def pattern(name="DecodeLiteralBlockSwitch", *, salt=0, mask=None, machine=62):
    code = bytes((index + salt) % 256 for index in range(96))
    return FunctionPattern(
        name=name,
        machine=machine,
        elf_class=64,
        byteorder="little",
        code=code,
        mask=mask or b"\xff" * len(code),
    )


def group(patterns):
    functions = {}
    for item in patterns:
        functions.setdefault(item.name, []).append(item.signature_id)
    return {
        "id": "fixture",
        "machine": 62,
        "elf_class": 64,
        "byteorder": "little",
        "source_sha256": hashlib.sha256(b"source").hexdigest(),
        "headers_sha256": hashlib.sha256(b"headers").hexdigest(),
        "object_sha256": hashlib.sha256(b"object").hexdigest(),
        "source": "https://example.invalid/reviewed-source",
        "source_state": "fixed",
        "compiler": "fixture compiler",
        "flags": "-O2",
        "build_note": "trusted fixture headers; decode.c unchanged",
        "functions": functions,
    }


def test_extracts_one_individual_function_without_group_role_requirements():
    code = bytes(range(96))
    patterns, rejected = patterns_from_object(
        relocatable_with_symbols(code, [{"name": "DecodeLiteralBlockSwitch"}])
    )
    assert [(item.name, item.code, item.mask) for item in patterns] == [
        ("DecodeLiteralBlockSwitch", code, b"\xff" * len(code))
    ]
    assert rejected == {"tiny_or_weak": 0, "ambiguous": 0}


def test_arm_thumb_symbol_low_bit_is_not_part_of_function_offset():
    code = bytes(range(64))
    patterns, _ = patterns_from_object(arm_thumb_relocatable(code))
    assert patterns[0].code == code
    assert patterns[0].machine == 40


def test_tiny_and_overlapping_functions_are_rejected_independently():
    code = bytes(range(192))
    patterns, rejected = patterns_from_object(
        relocatable_with_symbols(
            code,
            [
                {"name": "tiny", "address": CODE_ADDRESS, "size": 16},
                {"name": "overlap_a", "address": CODE_ADDRESS + 16, "size": 64},
                {"name": "overlap_b", "address": CODE_ADDRESS + 48, "size": 64},
                {"name": "valid", "address": CODE_ADDRESS + 128, "size": 64},
            ],
        )
    )
    assert [item.name for item in patterns] == ["valid"]
    assert rejected == {"tiny_or_weak": 1, "ambiguous": 2}


def test_complete_tail_and_relocation_wildcards_are_retained():
    mask = bytearray(b"\xff" * 96)
    mask[7:11] = bytes(4)
    mask[70:78] = bytes(8)
    item = pattern(mask=bytes(mask))
    line = render_pattern(item)
    fields = line.split()
    assert fields[1:6] == ["00", "0000", "0060", ":0000", item.signature_id]
    assert len(fields[0]) == 64
    assert fields[0][14:22] == "........"
    assert len(fields[6]) == 128
    assert fields[6][76:92] == "." * 16
    assert validate_pat(render_pat([item])) == {item.signature_id: line}


def test_weak_patterns_and_oversize_functions_fail_closed():
    weak_mask = bytes([0xFF] * 15 + [0] * 81)
    with pytest.raises(ValueError, match="Weak or unsupported"):
        render_pattern(pattern(mask=weak_mask))
    too_large = FunctionPattern(
        name="too_large",
        machine=62,
        elf_class=64,
        byteorder="little",
        code=b"A" * (64 * 1024 + 1),
        mask=b"\xff" * (64 * 1024 + 1),
    )
    with pytest.raises(ValueError, match="Weak or unsupported"):
        render_pattern(too_large)


def test_exact_tail_anchor_is_valid_even_when_the_head_is_all_wildcards():
    # The runtime prefilter indexes the longest exact run at its real offset;
    # python-flirt never scans the wildcard head across the target by itself.
    item = pattern(mask=bytes(32) + b"\xff" * 64)
    assert render_pattern(item).startswith("." * 64 + " 00 0000 0060 ")


def test_content_dedup_and_same_target_name_collision_are_conservative():
    first = pattern("first")
    duplicate = pattern("first")
    other_name = pattern("second")
    unique, ambiguous = resolve_ambiguities([first, duplicate])
    assert unique == [first]
    assert ambiguous == set()
    unique, ambiguous = resolve_ambiguities([first, other_name])
    assert unique == []
    assert ambiguous == {first.signature_id}


def test_bundle_pins_adjacent_pat_and_individual_function_ids(tmp_path):
    first, second = pattern("first"), pattern("second", salt=1)
    text = render_pat([first, second])
    bundle = validated_bundle(tmp_path / "brotli-flirt.pat", text, [group([first, second])])
    assert set(bundle) == {"schema_version", "pat_file", "pat_sha256", "groups"}
    assert bundle["pat_file"] == "brotli-flirt.pat"
    assert bundle["pat_sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert bundle["groups"][0]["functions"] == {
        "first": [first.signature_id],
        "second": [second.signature_id],
    }


def test_bundle_rejects_unreferenced_records_and_extra_group_fields(tmp_path):
    first, second = pattern("first"), pattern("second", salt=1)
    text = render_pat([first, second])
    with pytest.raises(ValueError, match="Every FLIRT PAT record"):
        validated_bundle(tmp_path / "refs.pat", text, [group([first])])
    invalid = group([first, second])
    invalid["state"] = "fixed"
    with pytest.raises(ValueError, match="group fields"):
        validated_bundle(tmp_path / "refs.pat", text, [invalid])


def test_duplicate_normalized_patterns_under_different_ids_are_rejected():
    first = pattern("first")
    line = render_pattern(first)
    duplicate = line.replace(first.signature_id, "brotli_different")
    with pytest.raises(ValueError, match="Duplicate FLIRT pattern"):
        validate_pat(f"{line}\n{duplicate}\n---\n")


def test_pat_requires_one_final_terminator():
    line = render_pattern(pattern())
    with pytest.raises(ValueError, match="one --- terminator"):
        validate_pat(f"{line}\n---\n---\n")
    with pytest.raises(ValueError, match="one --- terminator"):
        validate_pat(f"---\n{line}\n")


def test_validated_writer_preserves_existing_files_on_invalid_input(tmp_path):
    bundle_path, pat_path = tmp_path / "refs.json", tmp_path / "refs.pat"
    bundle_path.write_text("old bundle\n")
    pat_path.write_text("old patterns\n")
    item = pattern()
    invalid_group = group([item])
    invalid_group["functions"] = {"name": ["missing"]}
    with pytest.raises(ValueError, match="function-to-signature mapping"):
        write_catalog(bundle_path, pat_path, render_pat([item]), [invalid_group])
    assert bundle_path.read_text() == "old bundle\n"
    assert pat_path.read_text() == "old patterns\n"


def test_writer_output_round_trips(tmp_path):
    bundle_path, pat_path = tmp_path / "refs.json", tmp_path / "refs.pat"
    item = pattern()
    text = render_pat([item])
    write_catalog(bundle_path, pat_path, text, [group([item])])
    assert pat_path.read_text() == text
    bundle = json.loads(bundle_path.read_text())
    assert bundle == validated_bundle(pat_path, text, [group([item])])
    assert load_catalog(bundle_path) == (
        {item.signature_id: render_pattern(item)},
        [group([item])],
    )


def test_merge_deduplicates_identical_records_and_rejects_conflicts():
    item = pattern()
    line = render_pattern(item)
    records, groups = merge_catalogs(
        [{item.signature_id: line}, {item.signature_id: line}],
        [[group([item])], [group([item])]],
    )
    assert records == {item.signature_id: line}
    assert groups == [group([item])]
    with pytest.raises(ValueError, match="Conflicting FLIRT signature"):
        merge_catalogs(
            [{item.signature_id: line}, {item.signature_id: line + "AA"}],
            [[group([item])]],
        )


def test_merge_loader_normalizes_untrusted_json_encoding_failure(tmp_path):
    bundle = tmp_path / "bad.json"
    bundle.write_bytes(b"\xff")
    with pytest.raises(ValueError, match="Invalid FLIRT bundle JSON"):
        load_catalog(bundle)


def test_merge_loader_normalizes_json_recursion_failure(tmp_path, monkeypatch):
    bundle = tmp_path / "bad.json"
    bundle.write_text("{}")

    def recursive(_data):
        raise RecursionError

    monkeypatch.setattr(BUILDER["json"], "loads", recursive)
    with pytest.raises(ValueError, match="Invalid FLIRT bundle JSON"):
        load_catalog(bundle)


def test_post_merge_same_target_name_ambiguity_is_pruned():
    first, second = pattern("first"), pattern("second")
    assert first.signature_id == second.signature_id
    first_group, second_group = group([first]), group([second])
    second_group["id"] = "second-profile"
    records = {first.signature_id: render_pattern(first)}
    kept_records, kept_groups = prune_ambiguous_names(records, [first_group, second_group])
    assert kept_records == {}
    assert kept_groups == []


def test_same_pattern_can_retain_different_names_for_different_target_identities():
    first, second = pattern("first"), pattern("second", machine=183)
    assert first.signature_id == second.signature_id
    first_group, second_group = group([first]), group([second])
    second_group.update(id="aarch64-profile", machine=183)
    records = {first.signature_id: render_pattern(first)}
    kept_records, kept_groups = prune_ambiguous_names(records, [first_group, second_group])
    assert kept_records == records
    assert kept_groups == [first_group, second_group]
