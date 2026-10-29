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


def pe32_fixture():
    data = bytearray(0x300)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x02)
    struct.pack_into("<H", data, 0x98, 0x10B)
    struct.pack_into("<I", data, 0x98 + 92, 0)
    section = 0x98 + 0xE0
    data[section : section + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 0x100, 0x200)
    struct.pack_into("<I", data, section + 36, 0x40000040)
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


def mach_section_fixture():
    data = bytearray(0x400)
    section_size = 80
    command_size = 72 + 2 * section_size
    command = bytearray(command_size)
    struct.pack_into(
        "<II16sQQQQIIII",
        command,
        0,
        0x19,
        command_size,
        b"__TEXT" + bytes(10),
        0x100000,
        0x200,
        0x200,
        0x200,
        7,
        5,
        2,
        0,
    )
    struct.pack_into(
        "<16s16sQQIIIIIIII",
        command,
        72,
        b"__text" + bytes(10),
        b"__TEXT" + bytes(10),
        0x100000,
        0x80,
        0x200,
        4,
        0,
        0,
        0x80000400,
        0,
        0,
        0,
    )
    struct.pack_into(
        "<16s16sQQIIIIIIII",
        command,
        72 + section_size,
        b"__const" + bytes(9),
        b"__TEXT" + bytes(10),
        0x100080,
        0x80,
        0x280,
        4,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    struct.pack_into("<8I", data, 0, 0xFEEDFACF, 0x0100000C, 0, 6, 1, command_size, 0, 0)
    data[32 : 32 + command_size] = command
    data[0x200:0x280] = b"T" * 0x80
    data[0x280:0x300] = b"D" * 0x80
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


def test_pe32_uses_i386_width_and_data_scope_without_directories():
    result = layout.inspect_layout(pe32_fixture())
    assert (result["machine"], result["bits"], result["byteorder"]) == (
        "i386",
        32,
        "little",
    )
    assert result["ranges"]["data"][0]["file_offset"] == 0x200
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


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda data: struct.pack_into("<H", data, 0x86, 0), "section count"),
        (lambda data: struct.pack_into("<H", data, 0x98, 0x999), "optional-header magic"),
        (lambda data: struct.pack_into("<I", data, 0x98 + 60, len(data) + 1), "headers extend"),
        (
            lambda data: (
                struct.pack_into("<I", data, 0x98 + 60, 0x200),
                struct.pack_into("<I", data, 0x98 + 0xF0 + 20, 0x100),
            ),
            "mapped headers",
        ),
        (lambda data: struct.pack_into("<I", data, 0x900 + 4, 7), "base-relocation block"),
        (lambda data: struct.pack_into("<I", data, 0x800 + 4, 0x1000), "runtime-function"),
        (
            lambda data: struct.pack_into("<II", data, 0x98 + 112 + 6 * 8, 0x2400, 27),
            "debug-directory",
        ),
    ],
    ids=[
        "section-count",
        "optional-magic",
        "header-size",
        "section-in-headers",
        "relocation-block",
        "function-range",
        "debug-size",
    ],
)
def test_pe_structural_boundaries_reject_locally_valid_mutations(mutate, reason):
    data = bytearray(pe_fixture())
    mutate(data)
    assert any(reason in gap for gap in layout.inspect_layout(bytes(data))["gaps"])


def test_pe_ordinal_import_forwarded_export_and_unterminated_rsds_are_distinguished():
    ordinal = bytearray(pe_fixture())
    struct.pack_into("<Q", ordinal, 0x7A0, (1 << 63) | 7)
    result = layout.inspect_layout(bytes(ordinal))
    assert result["imports"] == [{"library": "brotli.dll", "thunk_rva": 0x21A0, "ordinal": 7}]
    forwarded = bytearray(pe_fixture())
    struct.pack_into("<I", forwarded, 0x660, 0x2090)
    assert layout.inspect_layout(bytes(forwarded))["exports"][0]["forwarder"] == "DecodeThing"
    invalid_ordinal = bytearray(pe_fixture())
    struct.pack_into("<H", invalid_ordinal, 0x680, 1)
    assert any(
        "export ordinal" in gap for gap in layout.inspect_layout(bytes(invalid_ordinal))["gaps"]
    )
    unterminated = bytearray(pe_fixture())
    payload_size = struct.unpack_from("<I", unterminated, 0xA00 + 16)[0]
    unterminated[0xA40 + payload_size - 1] = ord("x")
    assert any("RSDS path" in gap for gap in layout.inspect_layout(bytes(unterminated))["gaps"])


def test_pe_directory_termination_and_executable_flag_gaps_are_explicit():
    imports = bytearray(pe_fixture())
    struct.pack_into("<II", imports, 0x98 + 112 + 8, 0x2100, 20)
    assert any(
        "descriptor lacks terminator" in gap
        for gap in layout.inspect_layout(bytes(imports))["gaps"]
    )
    exports = bytearray(pe_fixture())
    struct.pack_into("<II", exports, 0x98 + 112, 0x2000, 39)
    assert any(
        "truncated PE export" in gap for gap in layout.inspect_layout(bytes(exports))["gaps"]
    )
    functions = bytearray(pe_fixture())
    struct.pack_into("<II", functions, 0x98 + 112 + 3 * 8, 0x2200, 13)
    assert any(
        "exception/function" in gap for gap in layout.inspect_layout(bytes(functions))["gaps"]
    )
    non_executable = bytearray(pe_fixture())
    struct.pack_into("<H", non_executable, 0x96, 0x20)
    assert any(
        "not marked executable" in gap
        for gap in layout.inspect_layout(bytes(non_executable))["gaps"]
    )


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


def test_mach_section_scopes_distinguish_instruction_and_const_bytes():
    result = layout.inspect_layout(mach_section_fixture())
    assert result["gaps"] == []
    assert result["ranges"]["executable"] == [
        {
            "file_offset": 0x200,
            "size": 0x80,
            "name": "__text",
            "segment": "__TEXT",
            "vmaddr": 0x100000,
        }
    ]
    assert result["ranges"]["data"] == [
        {
            "file_offset": 0x280,
            "size": 0x80,
            "name": "__const",
            "segment": "__TEXT",
            "vmaddr": 0x100080,
        }
    ]


def test_mach_section_and_command_bounds_fail_closed():
    outside = bytearray(mach_section_fixture())
    struct.pack_into("<I", outside, 32 + 72 + 80 + 48, 0x180)
    assert any(
        "outside its segment" in gap for gap in layout.inspect_layout(bytes(outside))["gaps"]
    )
    overlap = bytearray(mach_section_fixture())
    struct.pack_into("<I", overlap, 32 + 72 + 80 + 48, 0x240)
    assert any(
        "overlapping Mach section" in gap for gap in layout.inspect_layout(bytes(overlap))["gaps"]
    )
    command = bytearray(mach_section_fixture())
    struct.pack_into("<I", command, 32 + 4, 7)
    assert any("load-command size" in gap for gap in layout.inspect_layout(bytes(command))["gaps"])
    command_fill = bytearray(mach_section_fixture())
    struct.pack_into("<I", command_fill, 20, 233)
    assert any("do not fill" in gap for gap in layout.inspect_layout(bytes(command_fill))["gaps"])


def test_mach_zero_fill_symbols_uleb_and_function_tables_are_bounded():
    zero_fill = bytearray(mach_section_fixture())
    second_flags = 32 + 72 + 80 + 64
    struct.pack_into("<I", zero_fill, second_flags, 1)
    result = layout.inspect_layout(bytes(zero_fill))
    assert result["ranges"]["data"] == []
    limit = bytearray(mach_section_fixture())
    struct.pack_into("<I", limit, 16, layout.MAX_ITEMS + 1)
    assert any("load-command limit" in gap for gap in layout.inspect_layout(bytes(limit))["gaps"])
    symbol = bytearray(mach_fixture())
    struct.pack_into("<Q", symbol, 0x410 + 8, 0xDEADBEEF)
    export = layout.inspect_layout(bytes(symbol))["exports"][0]
    assert export["value"] == 0xDEADBEEF
    assert "file_offset" not in export
    with pytest.raises(ValueError, match="not file-backed"):
        layout._mach_vm_to_file([], 0x1000)  # noqa: SLF001 -- Address mapping boundary.
    with pytest.raises(ValueError, match="overlong unsigned"):
        layout._uleb(b"\x80" * 10, 0, 10)  # noqa: SLF001 -- Encoding boundary.
    with pytest.raises(ValueError, match="lack __TEXT"):
        layout._mach_functions(b"\0", layout._layout(), 0, 1, (0, 1), [])  # noqa: SLF001
    unterminated = bytearray(mach_fixture())
    unterminated[0x482] = 1
    assert any(
        "function-start table" in gap for gap in layout.inspect_layout(bytes(unterminated))["gaps"]
    )


@pytest.mark.parametrize(
    ("trie", "expected"),
    [
        (b"\x07\x08\x01orig\0\0", {"reexport_ordinal": 1, "import_name": "orig"}),
        (b"\x03\x10\0\x05\0", {"resolver": 5, "address": 0x1000}),
    ],
    ids=["reexport", "resolver"],
)
def test_mach_export_trie_reexports_and_resolvers_are_distinct(trie, expected):
    result = layout._layout("mach_o")  # noqa: SLF001 -- Focused export-trie fixture.
    layout._mach_export_trie(  # noqa: SLF001 -- Focused export-trie fixture.
        trie,
        result,
        0,
        len(trie),
        (0, len(trie)),
        [{"vmaddr": 0x1000, "file_offset": 0, "size": len(trie)}],
    )
    assert expected.items() <= result["exports"][0].items()


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


def test_wasm_section_identity_type_and_value_boundaries_fail_closed():
    assert any(
        "magic or version" in gap for gap in layout.inspect_layout(b"\0asm\x02\0\0\0")["gaps"]
    )
    duplicate = b"\0asm\x01\0\0\0" + wasm_section(1, b"\0") * 2
    assert any(
        "duplicate WebAssembly section" in gap for gap in layout.inspect_layout(duplicate)["gaps"]
    )
    unknown = b"\0asm\x01\0\0\0" + wasm_section(14, b"")
    assert any(
        "unknown WebAssembly section" in gap for gap in layout.inspect_layout(unknown)["gaps"]
    )
    bad_form = b"\0asm\x01\0\0\0" + wasm_section(1, b"\x01\x5f")
    assert any("non-function" in gap for gap in layout.inspect_layout(bad_form)["gaps"])
    bad_value = b"\0asm\x01\0\0\0" + wasm_section(1, b"\x01\x60\x01\x01\0")
    assert any("value type" in gap for gap in layout.inspect_layout(bad_value)["gaps"])


def test_wasm_all_import_kinds_are_bounded_and_recorded():
    types = wasm_section(1, b"\x01\x60\0\0")
    imports = b"".join(
        [
            wasm_name("env") + wasm_name("function") + b"\0\0",
            wasm_name("env") + wasm_name("table") + b"\x01\x70\x01\0\x01",
            wasm_name("env") + wasm_name("memory") + b"\x02\x01\0\x01",
            wasm_name("env") + wasm_name("global") + b"\x03\x7f\0",
            wasm_name("env") + wasm_name("tag") + b"\x04\0\0",
        ]
    )
    module = b"\0asm\x01\0\0\0" + types + wasm_section(2, uleb(5) + imports)
    result = layout.inspect_layout(module)
    assert result["gaps"] == []
    assert [item["kind"] for item in result["imports"]] == [0, 1, 2, 3, 4]
    assert result["dependencies"] == ["env"]
    unknown = (
        b"\0asm\x01\0\0\0"
        + types
        + wasm_section(2, b"\x01" + wasm_name("env") + wasm_name("bad") + b"\x05")
    )
    assert any(
        "unknown WebAssembly import" in gap for gap in layout.inspect_layout(unknown)["gaps"]
    )
    missing_type = (
        b"\0asm\x01\0\0\0"
        + types
        + wasm_section(2, b"\x01" + wasm_name("env") + wasm_name("function") + b"\0\x01")
    )
    assert any(
        "import references missing type" in gap
        for gap in layout.inspect_layout(missing_type)["gaps"]
    )


def test_wasm_table_memory_function_export_and_start_boundaries():
    bad_table = b"\0asm\x01\0\0\0" + wasm_section(4, b"\x01\x7f\0\0")
    assert any("table reference" in gap for gap in layout.inspect_layout(bad_table)["gaps"])
    shared_without_max = b"\0asm\x01\0\0\0" + wasm_section(5, b"\x01\x02\0")
    assert any("shared memory" in gap for gap in layout.inspect_layout(shared_without_max)["gaps"])
    unsupported_limits = b"\0asm\x01\0\0\0" + wasm_section(5, b"\x01\x08\0")
    assert any("limits flags" in gap for gap in layout.inspect_layout(unsupported_limits)["gaps"])
    function_without_code = (
        b"\0asm\x01\0\0\0" + wasm_section(1, b"\x01\x60\0\0") + wasm_section(3, b"\x01\0")
    )
    assert any("lacks code" in gap for gap in layout.inspect_layout(function_without_code)["gaps"])
    invalid_export = b"\0asm\x01\0\0\0" + wasm_section(7, b"\x01" + wasm_name("bad") + b"\0\0")
    assert any("export index" in gap for gap in layout.inspect_layout(invalid_export)["gaps"])
    invalid_start = b"\0asm\x01\0\0\0" + wasm_section(8, b"\0")
    assert any("start function" in gap for gap in layout.inspect_layout(invalid_start)["gaps"])


def test_wasm_code_counts_body_limits_and_trailing_bytes_are_rejected(monkeypatch):
    types = wasm_section(1, b"\x01\x60\0\0")
    functions = wasm_section(3, b"\x01\0")
    wrong_count = b"\0asm\x01\0\0\0" + types + functions + wasm_section(10, b"\0")
    assert any("function/code counts" in gap for gap in layout.inspect_layout(wrong_count)["gaps"])
    monkeypatch.setattr(layout, "MAX_WASM_BODY_BYTES", 1)
    oversized = b"\0asm\x01\0\0\0" + types + functions + wasm_section(10, b"\x01\x02\0\x0b")
    assert any("function body exceeds" in gap for gap in layout.inspect_layout(oversized)["gaps"])
    trailing_type = b"\0asm\x01\0\0\0" + wasm_section(1, b"\0x")
    assert any(
        "trailing WebAssembly type" in gap for gap in layout.inspect_layout(trailing_type)["gaps"]
    )


def test_wasm_call_decoder_handles_indirect_memory_constants_and_unknown_opcode():
    body = bytes(
        [
            0,
            0x11,
            0,
            0,
            0x28,
            0,
            0,
            0x41,
            0,
            0x43,
            0,
            0,
            0,
            0,
            0x0B,
        ]
    )
    module = (
        b"\0asm\x01\0\0\0"
        + wasm_section(1, b"\x01\x60\0\0")
        + wasm_section(3, b"\x01\0")
        + wasm_section(10, b"\x01" + uleb(len(body)) + body)
    )
    result = layout.inspect_layout(module)
    assert result["functions"][0]["indirect_calls"] == 1
    assert result["functions"][0]["calls_complete"] is True
    incomplete = module.replace(b"\x43\0\0\0\0", b"\xfc\0\0\0\0")
    assert layout.inspect_layout(incomplete)["functions"][0]["calls_complete"] is False


def test_wasm_data_count_and_debug_custom_sections_remain_explicit():
    data = wasm_section(11, b"\x01\x01\x01x")
    count = wasm_section(12, b"\0")
    debug = wasm_section(0, wasm_name("build_id") + b"identity")
    result = layout.inspect_layout(b"\0asm\x01\0\0\0" + debug + count + data)
    assert any("data-count" in gap for gap in result["gaps"])
    assert result["debug_identities"] == [
        {
            "kind": "wasm_custom_section",
            "name": "build_id",
            "file_offset": 19,
            "size": len(b"identity"),
        }
    ]


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
