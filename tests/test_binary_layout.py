import struct

import brotli_binary_data as binary_data
import brotli_binary_layout as layout
import pytest
from brotli_binary_data import file_data


def pe_fixture():
    data = bytearray(0xD20)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optional_size = 0xF0
    struct.pack_into("<HHIIIHH", data, 0x84, 0xAA64, 3, 0, 0, 0, optional_size, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 108, 16)
    directories = [
        (0x2000, 0x100),
        (0x2100, 0x100),
        (0x3000, 0x100),
        (0x2200, 12),
        (0xD00, 0x20),
        (0x2300, 8),
        (0x2400, 28),
    ]
    for index, value in enumerate(directories):
        struct.pack_into("<II", data, optional + 112 + index * 8, *value)
    section_table = optional + optional_size
    sections = [
        (b".text\0\0\0", 0x200, 0x1000, 0x200, 0x400, 0x60000020),
        (b".rdata\0\0", 0x600, 0x2000, 0x600, 0x600, 0x40000040),
        (b".rsrc\0\0\0", 0x100, 0x3000, 0x100, 0xC00, 0x40000040),
    ]
    for index, (name, virtual_size, rva, raw_size, raw, flags) in enumerate(sections):
        offset = section_table + index * 40
        data[offset : offset + 8] = name
        struct.pack_into("<IIII", data, offset + 8, virtual_size, rva, raw_size, raw)
        struct.pack_into("<I", data, offset + 36, flags)
    struct.pack_into(
        "<IIHHIIIIIII", data, 0x600, 0, 0, 0, 0, 0x2050, 1, 1, 1, 0x2060, 0x2070, 0x2080
    )
    data[0x650:0x659] = b"fixture\0\0"
    struct.pack_into("<I", data, 0x660, 0x1000)
    struct.pack_into("<I", data, 0x670, 0x2090)
    struct.pack_into("<H", data, 0x680, 0)
    data[0x690:0x69C] = b"DecodeThing\0"
    struct.pack_into("<IIIII", data, 0x700, 0x21A0, 0, 0, 0x2180, 0x21A0)
    data[0x780:0x78B] = b"brotli.dll\0"
    struct.pack_into("<Q", data, 0x7A0, 0x21C0)
    struct.pack_into("<Q", data, 0x7A8, 0)
    struct.pack_into("<H", data, 0x7C0, 7)
    data[0x7C2:0x7D0] = b"DecodeImport\0\0"
    struct.pack_into("<III", data, 0x800, 0x1000, 0x1010, 0x2250)
    struct.pack_into("<II", data, 0x900, 0x1000, 8)
    payload = b"RSDS" + bytes(range(16)) + struct.pack("<I", 3) + b"C:\\build\\fixture.pdb\0"
    struct.pack_into("<IIHHIIII", data, 0xA00, 0, 0, 0, 0, 2, len(payload), 0x2440, 0xA40)
    data[0xA40 : 0xA40 + len(payload)] = payload
    data[0xC00:0xC08] = b"RESOURCE"
    data[0xD00:0xD08] = b"CERTDATA"
    return bytes(data)


def mach_fixture(cpu=0x0100000C):
    data = bytearray(0x500)
    commands = [
        struct.pack(
            "<II16sQQQQIIII",
            0x19,
            72,
            b"__TEXT" + bytes(10),
            0x100000,
            0x200,
            0x200,
            0x200,
            7,
            5,
            0,
            0,
        )
    ]
    dependency = b"/usr/lib/libbrotli.dylib\0"
    dylib_size = (24 + len(dependency) + 7) & ~7
    commands.append(
        struct.pack("<IIIIII", 0xC, dylib_size, 24, 0, 0, 0)
        + dependency
        + bytes(dylib_size - 24 - len(dependency))
    )
    commands.extend(
        [
            struct.pack("<IIIIII", 2, 24, 0x400, 2, 0x420, 11),
            struct.pack("<II16s", 0x1B, 24, bytes(range(16))),
            struct.pack("<IIII", 0x26, 16, 0x480, 3),
        ]
    )
    blob = b"".join(commands)
    struct.pack_into("<8I", data, 0, 0xFEEDFACF, cpu, 0, 6, len(commands), len(blob), 0, 0)
    data[32 : 32 + len(blob)] = blob
    strings = b"\0_imp\0_exp\0"
    data[0x420 : 0x420 + len(strings)] = strings
    struct.pack_into("<IBBHQ", data, 0x400, 1, 1, 0, 0, 0)
    struct.pack_into("<IBBHQ", data, 0x410, 6, 0x0F, 1, 0, 0x100010)
    data[0x480:0x483] = b"\x10\x20\0"
    return bytes(data)


def uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def wasm_name(value):
    raw = value.encode()
    return uleb(len(raw)) + raw


def wasm_section(kind, payload):
    return bytes((kind,)) + uleb(len(payload)) + payload


def wasm_fixture():
    types = uleb(1) + b"\x60\0\0"
    imported = uleb(1) + wasm_name("env") + wasm_name("imp") + b"\0" + uleb(0)
    functions = uleb(1) + uleb(0)
    exported = uleb(1) + wasm_name("decode") + b"\0" + uleb(1)
    body = b"\0\x10\0\x0b"
    code = uleb(1) + uleb(len(body)) + body
    data = uleb(1) + b"\0\x41\0\x0b" + uleb(4) + b"DATA"
    name_map = uleb(1) + uleb(1) + wasm_name("decoder")
    custom = wasm_name("name") + b"\x01" + uleb(len(name_map)) + name_map
    return b"\0asm\x01\0\0\0" + b"".join(
        [
            wasm_section(0, custom),
            wasm_section(1, types),
            wasm_section(2, imported),
            wasm_section(3, functions),
            wasm_section(7, exported),
            wasm_section(12, uleb(1)),
            wasm_section(10, code),
            wasm_section(11, data),
        ]
    )


def test_pe_scopes_mapped_code_data_resources_and_static_metadata():
    result = layout.inspect_layout(pe_fixture())
    assert result["kind"] == "pe"
    assert result["abi"] == "windows-pe"
    assert (result["machine"], result["bits"], result["byteorder"]) == ("aarch64", 64, "little")
    assert [item["file_offset"] for item in result["ranges"]["mapped"]] == [0x400, 0x600, 0xC00]
    assert [item["file_offset"] for item in result["ranges"]["executable"]] == [0x400]
    assert [item["file_offset"] for item in result["ranges"]["data"]] == [0x600]
    assert [item["file_offset"] for item in result["ranges"]["resources"]] == [0xC00]
    assert result["ranges"]["relocations"] == [
        {"file_offset": 0x900, "size": 8, "rva": 0x2300, "entry_count": 0, "types": {}}
    ]
    assert result["dependencies"] == ["brotli.dll"]
    assert result["imports"][0]["name"] == "DecodeImport"
    assert result["exports"][0]["name"] == "DecodeThing"
    assert result["functions"][0]["file_offset"] == 0x400
    assert result["debug_identities"][0] == {
        "kind": "pdb_rsds",
        "guid": bytes(range(16)).hex(),
        "age": 3,
        "embedded_path": "C:\\build\\fixture.pdb",
        "path_followed": False,
    }
    assert all(item["file_offset"] != 0xD00 for item in result["ranges"]["mapped"])
    assert result["gaps"] == []


def test_pe_malformed_directory_fails_closed_with_partial_layout():
    data = bytearray(pe_fixture())
    struct.pack_into("<II", data, 0x98 + 112 + 8, 0xFFFFFF00, 0x100)
    result = layout.inspect_layout(bytes(data))
    assert result["kind"] == "pe"
    assert result["gaps"]
    assert "RVA" in result["gaps"][0]


def test_pe_certificate_bounds_and_unsupported_delay_imports_are_explicit():
    certificate = bytearray(pe_fixture())
    struct.pack_into("<II", certificate, 0x98 + 112 + 4 * 8, len(certificate) - 4, 8)
    assert any("range outside" in gap for gap in layout.inspect_layout(bytes(certificate))["gaps"])
    delayed = bytearray(pe_fixture())
    struct.pack_into("<II", delayed, 0x98 + 112 + 13 * 8, 0x2000, 32)
    assert any("delay-import" in gap for gap in layout.inspect_layout(bytes(delayed))["gaps"])


def test_pe_overlapping_raw_sections_are_not_accepted_as_loader_scope():
    data = bytearray(pe_fixture())
    second_section = 0x98 + 0xF0 + 40
    struct.pack_into("<I", data, second_section + 20, 0x500)
    result = layout.inspect_layout(bytes(data))
    assert any("overlapping PE raw section" in gap for gap in result["gaps"])


def test_mach_thin_dependencies_symbols_uuid_and_function_starts():
    result = layout.inspect_layout(mach_fixture())
    assert result["kind"] == "mach_o"
    assert result["abi"] == "darwin-mach-o"
    assert result["machine"] == "aarch64"
    assert result["dependencies"] == ["/usr/lib/libbrotli.dylib"]
    assert result["imports"][0]["name"] == "_imp"
    assert result["exports"][0]["name"] == "_exp"
    assert result["debug_identities"] == [{"kind": "mach_uuid", "uuid": bytes(range(16)).hex()}]
    assert [item["file_offset"] for item in result["functions"]] == [0x210, 0x230]
    assert result["ranges"]["executable"][0]["file_offset"] == 0x200


def test_mach_export_trie_names_and_rebases_addresses():
    trie = b"\0\x01_foo\0\x08\x02\0\x10\0"
    result = layout._layout("mach_o")  # noqa: SLF001 -- Focused format fixture.
    layout._mach_export_trie(  # noqa: SLF001 -- Focused format fixture.
        trie,
        result,
        0,
        len(trie),
        (0, len(trie)),
        [{"vmaddr": 0x1000, "file_offset": 0x200, "size": 0x100}],
    )
    assert result["exports"] == [
        {
            "name": "_foo",
            "flags": 0,
            "source": "export_trie",
            "address": 0x1010,
            "file_offset": 0x210,
        }
    ]


def test_mach_universal_rebases_each_slice_to_original_file_offsets():
    first, second = mach_fixture(0x0100000C), mach_fixture(0x01000007)
    data = bytearray(0x100 + len(first) + len(second))
    data[:8] = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2)
    struct.pack_into(">IIIII", data, 8, 0x0100000C, 0, 0x100, len(first), 0)
    second_offset = 0x100 + len(first)
    struct.pack_into(">IIIII", data, 28, 0x01000007, 0, second_offset, len(second), 0)
    data[0x100 : 0x100 + len(first)] = first
    data[second_offset : second_offset + len(second)] = second
    result = layout.inspect_layout(bytes(data))
    assert result["kind"] == "mach_o_universal"
    assert [child["machine"] for child in result["slices"]] == ["aarch64", "x86_64"]
    assert result["slices"][0]["ranges"]["mapped"][0]["file_offset"] == 0x300
    assert result["slices"][1]["ranges"]["mapped"][0]["file_offset"] == second_offset + 0x200


def test_mach_universal_overlapping_slices_fail_closed():
    thin = mach_fixture()
    data = bytearray(0x100 + len(thin))
    data[:8] = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2)
    struct.pack_into(">IIIII", data, 8, 0x0100000C, 0, 0x100, len(thin), 0)
    struct.pack_into(">IIIII", data, 28, 0x01000007, 0, 0x180, len(thin) - 0x80, 0)
    data[0x100:] = thin
    result = layout.inspect_layout(bytes(data))
    assert any("overlapping Mach universal slices" in gap for gap in result["gaps"])


def test_mach_universal_slice_count_is_bounded_before_rows():
    data = b"\xca\xfe\xba\xbe" + struct.pack(">I", layout.MAX_MACH_SLICES + 1)
    result = layout.inspect_layout(data)
    assert any("slice count" in gap for gap in result["gaps"])


def test_mach_arm64e_is_explicitly_incomplete():
    data = bytearray(mach_fixture())
    struct.pack_into("<I", data, 8, 2)
    result = layout.inspect_layout(bytes(data))
    assert any("arm64e" in gap for gap in result["gaps"])


@pytest.mark.parametrize(
    ("command", "reason"),
    [(0x21, "encrypted"), (0x34, "chained fixups")],
)
def test_mach_runtime_transforms_are_reported_as_static_gaps(command, reason):
    data = bytearray(mach_fixture())
    command_offset = 32 + 72
    struct.pack_into("<I", data, command_offset, command)
    if command == 0x21:
        struct.pack_into("<I", data, command_offset + 16, 1)
    result = layout.inspect_layout(bytes(data))
    assert any(reason in gap for gap in result["gaps"])


def test_wasm_scopes_real_data_and_code_and_recovers_direct_calls():
    module = wasm_fixture()
    result = layout.inspect_layout(module)
    assert result["kind"] == "wasm"
    assert result["abi"] == "wasm-core-1"
    assert result["dependencies"] == ["env"]
    assert result["imports"] == [
        {
            "module": "env",
            "name": "imp",
            "kind": 0,
            "type_index": 0,
            "type": {"parameters": [], "results": []},
        }
    ]
    assert result["exports"] == [{"name": "decode", "kind": 0, "index": 1}]
    assert result["functions"][0]["name"] == "decoder"
    assert result["functions"][0]["direct_calls"] == [0]
    assert result["functions"][0]["calls_complete"] is True
    offset = result["ranges"]["data"][0]["file_offset"]
    assert module[offset : offset + 4] == b"DATA"
    assert result["gaps"] == []


def test_wasm_custom_lookalike_is_not_a_data_initializer():
    lookalike = b"\0asm\x01\0\0\0" + wasm_section(0, wasm_name("fake") + b"DATA")
    result = layout.inspect_layout(lookalike)
    assert result["ranges"]["data"] == []
    assert result["functions"] == []


def test_wasm_passive_and_explicit_memory_data_ranges_are_scoped():
    passive = b"\x01" + uleb(4) + b"PASS"
    explicit = b"\x02" + uleb(0) + b"\x41\0\x0b" + uleb(4) + b"DATA"
    module = b"\0asm\x01\0\0\0" + wasm_section(11, uleb(2) + passive + explicit)
    result = layout.inspect_layout(module)
    assert [item["mode"] for item in result["ranges"]["data"]] == ["passive", "active"]
    assert result["ranges"]["data"][1]["memory_index"] == 0
    assert result["gaps"] == []


def test_wasm_invalid_data_mode_and_unterminated_expression_fail_closed():
    invalid_mode = b"\0asm\x01\0\0\0" + wasm_section(11, b"\x01\x03")
    assert any("data-segment flags" in gap for gap in layout.inspect_layout(invalid_mode)["gaps"])
    unterminated = b"\0asm\x01\0\0\0" + wasm_section(11, b"\x01\0\x41\0\x01x")
    assert any(
        "initializer expression" in gap for gap in layout.inspect_layout(unterminated)["gaps"]
    )


def test_wasm_section_order_and_direct_call_indices_fail_closed():
    types = wasm_section(1, uleb(1) + b"\x60\0\0")
    functions = wasm_section(3, uleb(1) + uleb(0))
    reordered = b"\0asm\x01\0\0\0" + functions + types
    assert any(
        "out of specification order" in gap for gap in layout.inspect_layout(reordered)["gaps"]
    )
    invalid_call = wasm_fixture().replace(b"\x00\x10\x00\x0b", b"\x00\x10\x09\x0b")
    assert any("call index" in gap for gap in layout.inspect_layout(invalid_call)["gaps"])
    memory64 = b"\0asm\x01\0\0\0" + wasm_section(5, uleb(1) + uleb(4) + uleb(0))
    assert any("memory64" in gap for gap in layout.inspect_layout(memory64)["gaps"])


def test_wasm_aggregate_code_budget_is_checked_before_body_walk(monkeypatch):
    monkeypatch.setattr(layout, "MAX_WASM_TOTAL_CODE_BYTES", 3)
    result = layout.inspect_layout(wasm_fixture())
    assert any("aggregate code-byte limit" in gap for gap in result["gaps"])


def test_recognized_malformed_inputs_return_deterministic_gaps():
    for data, kind in [(b"MZ", "pe"), (b"\xcf\xfa\xed\xfe", "mach_o"), (b"\0asm", "wasm")]:
        result = layout.inspect_layout(data)
        assert result["kind"] == kind
        assert len(result["gaps"]) == 1
        assert result["ranges"]["mapped"] == []


def test_unknown_input_has_stable_empty_contract():
    result = layout.inspect_layout(b"not a binary")
    assert result["kind"] == "unknown"
    assert result["gaps"] == []
    assert result["slices"] == []


def test_layout_parsers_use_sparse_filedata_contract(tmp_path):
    target = tmp_path / "fixture.exe"
    target.write_bytes(pe_fixture())
    with target.open("rb") as stream, file_data(stream) as data:
        result = layout.inspect_layout(data)
    assert result["machine"] == "aarch64"
    assert result["ranges"]["resources"][0]["file_offset"] == 0xC00


def test_sparse_pe_high_raw_range_does_not_read_section_body(tmp_path, monkeypatch):
    raw_offset = 3 * 1024 * 1024 * 1024
    fixture = bytearray(pe_fixture())
    first_section = 0x98 + 0xF0
    struct.pack_into("<I", fixture, first_section + 20, raw_offset)
    target = tmp_path / "sparse.exe"
    with target.open("wb") as stream:
        stream.write(fixture)
        stream.seek(raw_offset)
        stream.write(bytes(0x200))
    requested = 0
    real_pread = binary_data.os.pread

    def recording_pread(descriptor, size, offset):
        nonlocal requested
        requested += size
        return real_pread(descriptor, size, offset)

    monkeypatch.setattr(binary_data.os, "pread", recording_pread)
    with target.open("rb") as stream, file_data(stream) as data:
        result = layout.inspect_layout(data)
    assert result["functions"][0]["file_offset"] == raw_offset
    assert requested < 128 * 1024


def test_sparse_fat64_slice_above_four_gib_keeps_outer_offsets(tmp_path, monkeypatch):
    slice_offset = (1 << 32) + 0x1000
    thin = mach_fixture()
    target = tmp_path / "universal"
    with target.open("wb") as stream:
        stream.write(b"\xca\xfe\xba\xbf" + struct.pack(">I", 1))
        stream.write(struct.pack(">IIQQII", 0x0100000C, 0, slice_offset, len(thin), 12, 0))
        stream.seek(slice_offset)
        stream.write(thin)
    requested = 0
    real_pread = binary_data.os.pread

    def recording_pread(descriptor, size, offset):
        nonlocal requested
        requested += size
        return real_pread(descriptor, size, offset)

    monkeypatch.setattr(binary_data.os, "pread", recording_pread)
    with target.open("rb") as stream, file_data(stream) as data:
        result = layout.inspect_layout(data)
    assert result["slices"][0]["ranges"]["mapped"][0]["file_offset"] == slice_offset + 0x200
    assert requested < 128 * 1024
