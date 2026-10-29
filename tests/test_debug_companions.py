import struct
import zlib
from types import SimpleNamespace

import brotli_binary_match as matcher
import brotli_debug_companions as debug
import pytest
from test_binary_layout import mach_fixture
from test_binary_metadata import CODE_ADDRESS, elf_with_symbols


def elf_note(build_id):
    name = b"GNU\0"
    note = struct.pack("<III", len(name), len(build_id), debug.NT_GNU_BUILD_ID)
    note += name + build_id + bytes((-len(build_id)) % 4)
    offset = matcher.ELF_HEADER.size + matcher.PROGRAM_HEADER.size
    header = matcher.ELF_HEADER.pack(
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3,
        matcher.EM_X86_64,
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
    program = matcher.PROGRAM_HEADER.pack(4, 0, offset, 0, 0, len(note), len(note), 4)
    return header + program + note


def elf_debuglink(name, crc):
    names = b"\0.gnu_debuglink\0.shstrtab\0"
    payload = name.encode() + b"\0"
    payload += bytes((-len(payload)) % 4) + crc.to_bytes(4, "little")
    data_offset = matcher.ELF_HEADER.size + matcher.PROGRAM_HEADER.size
    names_offset = data_offset + len(payload)
    section_offset = (names_offset + len(names) + 7) & ~7
    sections = [
        (0,) * 10,
        (1, 1, 0, 0, data_offset, len(payload), 0, 0, 4, 0),
        (16, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0),
    ]
    header = matcher.ELF_HEADER.pack(
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3,
        matcher.EM_X86_64,
        1,
        0,
        matcher.ELF_HEADER.size,
        section_offset,
        0,
        matcher.ELF_HEADER.size,
        matcher.PROGRAM_HEADER.size,
        1,
        matcher.SECTION_HEADER.size,
        len(sections),
        2,
    )
    program = matcher.PROGRAM_HEADER.pack(
        1, 4, data_offset, 0x400000, 0x400000, len(payload), len(payload), 4
    )
    result = bytearray(header + program + payload + names)
    result.extend(bytes(section_offset - len(result)))
    result.extend(b"".join(matcher.SECTION_HEADER.pack(*row) for row in sections))
    return bytes(result)


def elf_section_note(build_id):
    name = b"GNU\0"
    note = struct.pack("<III", len(name), len(build_id), debug.NT_GNU_BUILD_ID)
    note += name + build_id + bytes((-len(build_id)) % 4)
    names = b"\0.note.gnu.build-id\0.shstrtab\0"
    note_offset = matcher.ELF_HEADER.size
    names_offset = note_offset + len(note)
    section_offset = (names_offset + len(names) + 7) & ~7
    sections = [
        (0,) * 10,
        (1, debug.SHT_NOTE, 0, 0, note_offset, len(note), 0, 0, 4, 0),
        (20, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0),
    ]
    header = matcher.ELF_HEADER.pack(
        b"\x7fELF\x02\x01\x01" + bytes(9),
        1,
        matcher.EM_X86_64,
        1,
        0,
        0,
        section_offset,
        0,
        matcher.ELF_HEADER.size,
        0,
        0,
        matcher.SECTION_HEADER.size,
        len(sections),
        2,
    )
    result = bytearray(header + note + names)
    result.extend(bytes(section_offset - len(result)))
    result.extend(b"".join(matcher.SECTION_HEADER.pack(*row) for row in sections))
    return bytes(result)


def macho_uuid(value, *, bits=64, byteorder="little"):
    prefix = "<" if byteorder == "little" else ">"
    magic = {
        (32, "little"): b"\xce\xfa\xed\xfe",
        (32, "big"): b"\xfe\xed\xfa\xce",
        (64, "little"): b"\xcf\xfa\xed\xfe",
        (64, "big"): b"\xfe\xed\xfa\xcf",
    }[(bits, byteorder)]
    command = struct.pack(prefix + "II16s", debug.LC_UUID, 24, value)
    header_values = (0, 0, 2, 1, 24, 0, 0) if bits == 64 else (0, 0, 2, 1, 24, 0)
    header = struct.pack(prefix + ("iiIIIII" if bits == 64 else "iiIIII"), *header_values)
    return magic + header + command


def pdb(guid, age):
    block_size = 512
    result = bytearray(block_size * 4)
    result[:32] = debug.MSF7_MAGIC
    result[32:56] = struct.pack("<IIIIII", block_size, 0, 4, 16, 0, 1)
    result[block_size : block_size + 4] = (2).to_bytes(4, "little")
    directory = struct.pack("<III", 2, debug.MSF_NIL_STREAM_SIZE, 28) + struct.pack("<I", 3)
    result[block_size * 2 : block_size * 2 + len(directory)] = directory
    info = struct.pack("<III16s", 20000404, 0, age, guid)
    result[block_size * 3 : block_size * 3 + len(info)] = info
    return bytes(result)


def multiblock_pdb(guid, age):
    block_size = 512
    block_count = 6
    directory_size = block_size + 8
    info_size = block_size + 28
    result = bytearray(block_size * block_count)
    result[:32] = debug.MSF7_MAGIC
    result[32:56] = struct.pack("<IIIIII", block_size, 0, block_count, directory_size, 0, 1)
    result[block_size : block_size + 8] = struct.pack("<II", 2, 3)
    directory = bytearray(directory_size)
    directory[:12] = struct.pack("<III", 2, debug.MSF_NIL_STREAM_SIZE, info_size)
    directory[12:20] = struct.pack("<II", 4, 5)
    result[block_size * 2 : block_size * 3] = directory[:block_size]
    result[block_size * 3 : block_size * 3 + 8] = directory[block_size:]
    info = struct.pack("<III16s", 20000404, 0, age, guid)
    result[block_size * 4 : block_size * 4 + len(info)] = info
    return bytes(result)


def pe_rsds(guid, age, path="C:\\symbols\\app.pdb"):
    rsds = b"RSDS" + guid + age.to_bytes(4, "little") + path.encode() + b"\0"
    pe_offset = 0x80
    optional_size = 240
    section_offset = pe_offset + 24 + optional_size
    raw_offset = 0x200
    debug_offset = raw_offset
    rsds_offset = raw_offset + 0x40
    result = bytearray(0x400)
    result[:2] = b"MZ"
    result[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    result[pe_offset : pe_offset + 4] = b"PE\0\0"
    result[pe_offset + 4 : pe_offset + 24] = struct.pack(
        "<HHIIIHH", 0x8664, 1, 0, 0, 0, optional_size, 0x2
    )
    optional = bytearray(optional_size)
    optional[:2] = (0x20B).to_bytes(2, "little")
    optional[108:112] = (16).to_bytes(4, "little")
    optional[136:140] = (0x1080).to_bytes(4, "little")
    optional[140:144] = (12).to_bytes(4, "little")
    optional[160:164] = (0x1000).to_bytes(4, "little")
    optional[164:168] = (28).to_bytes(4, "little")
    result[pe_offset + 24 : section_offset] = optional
    section = bytearray(40)
    section[:8] = b".rdata\0\0"
    section[8:12] = (0x200).to_bytes(4, "little")
    section[12:16] = (0x1000).to_bytes(4, "little")
    section[16:20] = (0x200).to_bytes(4, "little")
    section[20:24] = raw_offset.to_bytes(4, "little")
    result[section_offset : section_offset + 40] = section
    directory = bytearray(28)
    directory[12:16] = debug.IMAGE_DEBUG_TYPE_CODEVIEW.to_bytes(4, "little")
    directory[16:20] = len(rsds).to_bytes(4, "little")
    directory[20:24] = (0x1040).to_bytes(4, "little")
    directory[24:28] = rsds_offset.to_bytes(4, "little")
    result[debug_offset : debug_offset + 28] = directory
    result[rsds_offset : rsds_offset + len(rsds)] = rsds
    result[0x280:0x28C] = struct.pack("<III", 0x1100, 0x1110, 0x1120)
    return bytes(result)


def pe32_rsds(guid, age, path="C:\\symbols\\app.pdb"):
    rsds = b"RSDS" + guid + age.to_bytes(4, "little") + path.encode() + b"\0"
    pe_offset = 0x80
    optional_size = 224
    section_offset = pe_offset + 24 + optional_size
    result = bytearray(0x400)
    result[:2] = b"MZ"
    result[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    result[pe_offset : pe_offset + 4] = b"PE\0\0"
    result[pe_offset + 4 : pe_offset + 24] = struct.pack(
        "<HHIIIHH", 0x14C, 1, 0, 0, 0, optional_size, 0x2
    )
    optional = bytearray(optional_size)
    optional[:2] = (0x10B).to_bytes(2, "little")
    optional[92:96] = (16).to_bytes(4, "little")
    optional[144:148] = (0x1000).to_bytes(4, "little")
    optional[148:152] = (28).to_bytes(4, "little")
    result[pe_offset + 24 : section_offset] = optional
    section = bytearray(40)
    section[8:12] = (0x200).to_bytes(4, "little")
    section[12:16] = (0x1000).to_bytes(4, "little")
    section[16:20] = (0x200).to_bytes(4, "little")
    section[20:24] = (0x200).to_bytes(4, "little")
    result[section_offset : section_offset + 40] = section
    result[0x20C:0x210] = debug.IMAGE_DEBUG_TYPE_CODEVIEW.to_bytes(4, "little")
    result[0x210:0x214] = len(rsds).to_bytes(4, "little")
    result[0x214:0x218] = (0x1040).to_bytes(4, "little")
    result[0x218:0x21C] = (0x240).to_bytes(4, "little")
    result[0x240 : 0x240 + len(rsds)] = rsds
    return bytes(result)


def test_matching_elf_build_id_and_duplicate_ambiguity():
    artifact = elf_note(bytes.fromhex("01020304"))
    companion = elf_section_note(bytes.fromhex("01020304"))
    match = debug.verify_debug_companions(
        artifact, (debug.SuppliedCompanion("app.debug", companion),)
    )
    duplicate = debug.verify_debug_companions(
        artifact,
        (
            debug.SuppliedCompanion("a.debug", companion),
            debug.SuppliedCompanion("b.debug", companion),
        ),
    )
    assert match.status == "verified"
    assert match.matches[0].methods == ("gnu_build_id",)
    assert match.matches[0].patch_status == "unknown"
    assert duplicate.status == "ambiguous"
    assert any(gap.code == "ambiguous_debug_companion" for gap in duplicate.gaps)


def test_conflicting_elf_build_ids_are_rejected_not_selected():
    first = bytes.fromhex("01020304")
    second = bytes.fromhex("05060708")
    one = elf_note(first)
    header = matcher.elf_header(one)
    note_offset = next(matcher.program_headers(one, header))[2]
    note = one[note_offset:]
    other = elf_note(second)[note_offset:]
    data = bytearray(one[:note_offset] + note + other)
    struct.pack_into("<Q", data, matcher.ELF_HEADER.size + 32, len(note) + len(other))
    result = debug.debug_identity(bytes(data))
    assert result.identity is None
    assert result.gaps == (
        debug.DebugGap("conflicting_build_ids", "ELF contains conflicting GNU build IDs"),
    )


def test_elf_note_and_debuglink_internal_bounds_fail_closed():
    with pytest.raises(ValueError, match="Truncated ELF note"):
        debug._gnu_build_ids(b"nonzero", "little")  # noqa: SLF001 -- Note boundary.
    malformed_note = struct.pack("<III", 4, 8, debug.NT_GNU_BUILD_ID) + b"GNU\0short"
    with pytest.raises(ValueError, match="outside its segment"):
        debug._gnu_build_ids(malformed_note, "little")  # noqa: SLF001 -- Note boundary.
    for payload, reason in (
        (b"\0" + bytes(7), "filename"),
        (b"../bad\0" + bytes(4), "basename"),
        (b"name\0" + bytes(2), "CRC layout"),
        (b"\xff\0" + bytes(6), "filename"),
    ):
        with pytest.raises(ValueError, match=reason):
            debug._parse_debuglink(payload, "little")  # noqa: SLF001 -- Debuglink boundary.


def test_mismatched_build_id_remains_unresolved():
    result = debug.verify_debug_companions(
        elf_note(b"A" * 8), (debug.SuppliedCompanion("wrong.debug", elf_note(b"B" * 8)),)
    )
    assert result.status == "unresolved"
    assert any(gap.code == "debug_identity_mismatch" for gap in result.gaps)


def test_debuglink_crc_verifies_elf_symbols_but_not_patch_state():
    companion = elf_with_symbols(
        b"\xc3",
        matcher.EM_X86_64,
        [{"name": "DecodeLiteralBlockSwitch", "size": 1}],
    )
    crc = zlib.crc32(companion) & 0xFFFFFFFF
    artifact = elf_debuglink("app.debug", crc)
    result = debug.verify_debug_companions(
        artifact, (debug.SuppliedCompanion("supplied/app.debug", companion),)
    )
    assert result.status == "verified"
    assert result.matches[0].methods == ("gnu_debuglink_crc32",)
    assert result.matches[0].function_hints[0].name == "DecodeLiteralBlockSwitch"
    assert result.matches[0].use_scope == "names_bounds_only"
    assert result.matches[0].patch_status == "unknown"


@pytest.mark.parametrize(
    "symbol",
    [
        {"name": "WrongOwner", "index": 2, "size": 1},
        {"name": "OutsideOwner", "address": 0x500000, "size": 1},
    ],
    ids=["wrong-owner", "outside-owner"],
)
def test_verified_elf_companion_rejects_inconsistent_function_symbol_ownership(symbol):
    companion = elf_with_symbols(b"\xc3", matcher.EM_X86_64, [symbol])
    artifact = elf_debuglink("app.debug", zlib.crc32(companion) & 0xFFFFFFFF)
    result = debug.verify_debug_companions(
        artifact,
        (debug.SuppliedCompanion("app.debug", companion),),
        auto_pyelftools=False,
    )
    assert result.status == "verified"
    assert result.matches[0].function_hints == ()
    assert any(gap.code == "malformed_elf_function_hints" for gap in result.gaps)


class FakeLineProgram:
    header = SimpleNamespace(version=4)

    def __getitem__(self, name):
        assert name == "file_entry"
        return [SimpleNamespace(name=b"embedded/path/decode.c")]

    def get_entries(self):
        state = SimpleNamespace(
            address=0x400100,
            file=1,
            line=17,
            end_sequence=False,
        )
        return [SimpleNamespace(state=state)]


class FakeDwarf:
    def iter_CUs(self):  # noqa: N802 -- Mirrors pyelftools API.
        return [object()]

    def line_program_for_CU(self, _unit):  # noqa: N802 -- Mirrors pyelftools API.
        return FakeLineProgram()


class FakeELFFile:
    def __init__(self, _stream):
        pass

    def has_dwarf_info(self):
        return True

    def get_dwarf_info(self):
        return FakeDwarf()


class FakePyelftools:
    __name__ = "fake_pyelftools"
    __version__ = debug.PINNED_PYELFTOOLS_VERSION
    ELFFile = FakeELFFile


def fake_pyelftools(*, version, states, files):
    class LineProgram:
        header = SimpleNamespace(version=version)

        def __getitem__(self, name):
            assert name == "file_entry"
            return [SimpleNamespace(name=item) for item in files]

        def get_entries(self):
            return [SimpleNamespace(state=state) for state in states]

    class Dwarf:
        def iter_CUs(self):  # noqa: N802 -- Mirrors pyelftools API.
            return [object()]

        def line_program_for_CU(self, _unit):  # noqa: N802 -- Mirrors pyelftools API.
            return LineProgram()

    class Elf:
        def __init__(self, _stream):
            pass

        def has_dwarf_info(self):
            return True

        def get_dwarf_info(self):
            return Dwarf()

    return SimpleNamespace(
        __name__="fake_pyelftools",
        __version__=debug.PINNED_PYELFTOOLS_VERSION,
        ELFFile=Elf,
    )


def test_verified_elf_symbols_gain_bounded_dwarf_lines(monkeypatch):
    companion = elf_with_symbols(
        b"\xc3",
        matcher.EM_X86_64,
        [{"name": "DecodeLiteralBlockSwitch", "size": 1}],
    )
    artifact = elf_debuglink("app.debug", zlib.crc32(companion) & 0xFFFFFFFF)
    monkeypatch.setattr(debug, "_dwarf_size_allowed", lambda *_args: True)
    result = debug.verify_debug_companions(
        artifact,
        (debug.SuppliedCompanion("app.debug", companion),),
        pyelftools_module=FakePyelftools(),
    )
    hint = result.matches[0].function_hints[0]
    assert (hint.source_file, hint.source_line) == ("decode.c", 17)
    assert all(gap.code != "source_locations_unavailable" for gap in result.gaps)


def test_dwarf_v5_uses_zero_based_file_index_and_exact_function_bounds(monkeypatch):
    monkeypatch.setattr(debug, "_dwarf_size_allowed", lambda *_args: True)
    hint = debug.FunctionHint("decode", 0x1000, 4)
    in_range = SimpleNamespace(
        address=0x1003,
        file=0,
        line=21,
        end_sequence=False,
    )
    enriched, gaps, limited = debug._dwarf_line_hints(  # noqa: SLF001 -- DWARF v5 boundary.
        b"fixture",
        (hint,),
        debug.DEFAULT_DEBUG_LIMITS,
        fake_pyelftools(version=5, states=[in_range], files=[b"src/decode.c"]),
    )
    assert (enriched[0].source_file, enriched[0].source_line) == ("decode.c", 21)
    assert gaps == ()
    assert limited is False

    at_end = SimpleNamespace(
        address=0x1004,
        file=0,
        line=22,
        end_sequence=False,
    )
    unchanged, gaps, limited = debug._dwarf_line_hints(  # noqa: SLF001 -- Half-open bound.
        b"fixture",
        (hint,),
        debug.DEFAULT_DEBUG_LIMITS,
        fake_pyelftools(version=5, states=[at_end], files=[b"src/decode.c"]),
    )
    assert unchanged == (hint,)
    assert gaps[0].code == "dwarf_lines_unresolved"
    assert limited is False


def test_dwarf_line_population_and_file_indices_are_bounded(monkeypatch):
    monkeypatch.setattr(debug, "_dwarf_size_allowed", lambda *_args: True)
    hint = debug.FunctionHint("decode", 0x1000, 4)
    states = [
        SimpleNamespace(address=0x1000, file=2, line=1, end_sequence=False),
        SimpleNamespace(address=0x1001, file=0, line=2, end_sequence=False),
        SimpleNamespace(address=0x1002, file=0, line=3, end_sequence=False),
    ]
    unchanged, gaps, limited = debug._dwarf_line_hints(  # noqa: SLF001 -- Entry budget.
        b"fixture",
        (hint,),
        debug.DebugLimits(max_line_entries=1),
        fake_pyelftools(version=5, states=states, files=[b"decode.c"]),
    )
    assert unchanged == (hint,)
    assert gaps[0].code == "dwarf_line_limit"
    assert limited is True


def test_wrong_pyelftools_version_is_an_explicit_gap(monkeypatch):
    companion = elf_with_symbols(
        b"\xc3",
        matcher.EM_X86_64,
        [{"name": "DecodeLiteralBlockSwitch", "size": 1}],
    )
    artifact = elf_debuglink("app.debug", zlib.crc32(companion) & 0xFFFFFFFF)
    monkeypatch.setattr(debug, "_dwarf_size_allowed", lambda *_args: True)
    wrong = SimpleNamespace(__name__="fake", __version__="0.32", ELFFile=FakeELFFile)
    result = debug.verify_debug_companions(
        artifact,
        (debug.SuppliedCompanion("app.debug", companion),),
        pyelftools_module=wrong,
    )
    assert any(gap.code == "pyelftools_version_unsupported" for gap in result.gaps)


def test_debuglink_path_and_crc_fail_closed():
    companion = elf_note(b"A" * 8)
    bad_path = debug.debug_identity(
        elf_debuglink("/tmp/app.debug", 0)  # noqa: S108 -- Inert embedded path fixture.
    )
    mismatch = debug.verify_debug_companions(
        elf_debuglink("app.debug", 1),
        (debug.SuppliedCompanion("app.debug", companion),),
    )
    assert bad_path.identity is None
    assert any(gap.code == "malformed_elf_identity" for gap in bad_path.gaps)
    assert mismatch.status == "unresolved"


def test_macho_uuid_requires_exact_supplied_uuid():
    uuid = bytes(range(16))
    verified = debug.verify_debug_companions(
        mach_fixture(), (debug.SuppliedCompanion("app.dsym", mach_fixture()),)
    )
    mismatch = debug.verify_debug_companions(
        macho_uuid(uuid), (debug.SuppliedCompanion("wrong.dsym", macho_uuid(bytes(16))),)
    )
    assert verified.status == "verified"
    assert verified.matches[0].methods == ("macho_uuid",)
    assert [hint.file_offset for hint in verified.matches[0].function_hints] == [0x210, 0x230]
    assert mismatch.status == "unresolved"


@pytest.mark.parametrize(
    ("bits", "byteorder"),
    [(32, "little"), (32, "big"), (64, "big")],
    ids=["le32", "be32", "be64"],
)
def test_macho_uuid_all_thin_header_encodings(bits, byteorder):
    uuid = bytes(range(16))
    result = debug.debug_identity(macho_uuid(uuid, bits=bits, byteorder=byteorder))
    assert result.identity == debug.DebugIdentity("macho", macho_uuid=uuid.hex())
    assert result.gaps == ()


def test_macho_conflicting_uuid_commands_are_rejected():
    prefix = "<"
    commands = b"".join(
        [
            struct.pack(prefix + "II16s", debug.LC_UUID, 24, bytes(16)),
            struct.pack(prefix + "II16s", debug.LC_UUID, 24, bytes(range(16))),
        ]
    )
    data = (
        b"\xcf\xfa\xed\xfe"
        + struct.pack(prefix + "iiIIIII", 0, 0, 2, 2, len(commands), 0, 0)
        + commands
    )
    result = debug.debug_identity(data)
    assert result.identity is None
    assert result.gaps[0].code == "missing_macho_uuid"
    assert "conflicting" in result.gaps[0].reason


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda data: data.__setitem__(
                slice(16, 20), (debug.DEFAULT_DEBUG_LIMITS.max_commands + 1).to_bytes(4, "little")
            ),
            "macho_command_limit",
        ),
        (
            lambda data: data.__setitem__(slice(20, 24), (0x1000).to_bytes(4, "little")),
            "malformed_macho_identity",
        ),
        (
            lambda data: data.__setitem__(slice(36, 40), (16).to_bytes(4, "little")),
            "malformed_macho_identity",
        ),
        (
            lambda data: data.__setitem__(slice(32, 36), (1).to_bytes(4, "little")),
            "missing_macho_uuid",
        ),
    ],
    ids=["command-count", "command-bytes", "uuid-size", "missing-uuid"],
)
def test_macho_identity_command_boundaries(mutate, code):
    data = bytearray(macho_uuid(bytes(range(16))))
    mutate(data)
    result = debug.debug_identity(bytes(data))
    assert result.identity is None
    assert result.gaps[0].code == code


def test_macho_load_command_population_must_consume_declared_bytes():
    data = bytearray(macho_uuid(bytes(range(16))))
    data[20:24] = (32).to_bytes(4, "little")
    data.extend(bytes(8))
    result = debug.debug_identity(bytes(data))
    assert result.identity is None
    assert result.gaps[0].code == "malformed_macho_identity"


def test_pe_pdb_guid_age_and_basename_are_verified():
    guid = bytes(range(16))
    artifact = pe_rsds(guid, 7)
    verified = debug.verify_debug_companions(
        artifact, (debug.SuppliedCompanion("app.pdb", pdb(guid, 7)),)
    )
    mismatch = debug.verify_debug_companions(
        artifact, (debug.SuppliedCompanion("app.pdb", pdb(guid, 8)),)
    )
    assert verified.status == "verified"
    assert verified.matches[0].methods == ("pdb_guid_age",)
    assert verified.matches[0].patch_status == "unknown"
    assert verified.matches[0].function_hints[0].file_offset == 0x300
    assert verified.matches[0].function_hints[0].size == 0x10
    assert any(gap.code == "debug_names_unavailable" for gap in verified.gaps)
    assert mismatch.status == "unresolved"


def test_pe32_codeview_and_multiblock_pdb_identity_match():
    guid = bytes(range(16))
    artifact = pe32_rsds(guid, 9)
    companion = multiblock_pdb(guid, 9)
    result = debug.verify_debug_companions(
        artifact,
        (debug.SuppliedCompanion("app.pdb", companion),),
    )
    assert result.status == "verified"
    assert result.matches[0].methods == ("pdb_guid_age",)
    assert result.matches[0].identity == debug.DebugIdentity("pdb", pdb_guid=guid.hex(), pdb_age=9)


def test_pe_conflicting_rsds_records_are_rejected():
    first_guid = bytes(range(16))
    data = bytearray(pe_rsds(first_guid, 7))
    second = b"RSDS" + bytes(reversed(range(16))) + (7).to_bytes(4, "little") + b"app.pdb\0"
    data[0x13C:0x140] = (56).to_bytes(4, "little")
    data[0x21C:0x238] = data[0x200:0x21C]
    data[0x228:0x22C] = debug.IMAGE_DEBUG_TYPE_CODEVIEW.to_bytes(4, "little")
    data[0x22C:0x230] = len(second).to_bytes(4, "little")
    data[0x230:0x234] = (0x1100).to_bytes(4, "little")
    data[0x234:0x238] = (0x300).to_bytes(4, "little")
    data[0x300 : 0x300 + len(second)] = second
    result = debug.debug_identity(bytes(data))
    assert result.identity is None
    assert result.gaps[0].code == "missing_pe_pdb_identity"
    assert "conflicting" in result.gaps[0].reason


def test_pe_identity_header_directory_and_codeview_bounds_fail_closed():
    guid = bytes(range(16))
    section_limit = bytearray(pe_rsds(guid, 7))
    section_limit[0x86:0x88] = (2).to_bytes(2, "little")
    result = debug.debug_identity(bytes(section_limit), debug.DebugLimits(max_commands=1))
    assert result.identity is None
    assert result.gaps[0].code == "pe_section_limit"

    malformed_directory = bytearray(pe_rsds(guid, 7))
    malformed_directory[0x13C:0x140] = (27).to_bytes(4, "little")
    assert debug.debug_identity(bytes(malformed_directory)).gaps[0].code == "malformed_pe_identity"
    no_codeview = bytearray(pe_rsds(guid, 7))
    no_codeview[0x20C:0x210] = (1).to_bytes(4, "little")
    missing = debug.debug_identity(bytes(no_codeview))
    assert missing.identity is None
    assert missing.gaps[0].code == "missing_pe_pdb_identity"
    invalid_rsds = bytearray(pe_rsds(guid, 7))
    invalid_rsds[0x240:0x244] = b"NB10"
    assert debug.debug_identity(bytes(invalid_rsds)).gaps[0].code == "missing_pe_pdb_identity"


def test_multiblock_pdb_block_geometry_and_stream_ownership_fail_closed():
    guid = bytes(range(16))
    outside = bytearray(multiblock_pdb(guid, 7))
    outside[512 + 4 : 512 + 8] = (6).to_bytes(4, "little")
    assert debug.debug_identity(bytes(outside)).gaps[0].code == "malformed_pdb_identity"
    missing_info = bytearray(pdb(guid, 7))
    missing_info[512 * 2 + 8 : 512 * 2 + 12] = (0).to_bytes(4, "little")
    assert debug.debug_identity(bytes(missing_info)).gaps[0].code == "malformed_pdb_identity"
    geometry = bytearray(pdb(guid, 7))
    geometry[32:36] = (513).to_bytes(4, "little")
    assert debug.debug_identity(bytes(geometry)).gaps[0].code == "malformed_pdb_identity"


def test_pe_codeview_rva_must_uniquely_match_raw_pointer():
    guid = bytes(range(16))
    data = bytearray(pe_rsds(guid, 7))
    record_size = int.from_bytes(data[0x210:0x214], "little")
    data[0x300 : 0x300 + record_size] = data[0x240 : 0x240 + record_size]
    data[0x218:0x21C] = (0x300).to_bytes(4, "little")
    result = debug.debug_identity(bytes(data))
    assert result.identity is None
    assert result.gaps[0].code == "malformed_pe_identity"

    map_rva = debug._pe_rva_to_offset  # noqa: SLF001 -- Ambiguous ownership regression.
    assert map_rva(0x1010, 4, [(0x1000, 0x100, 0x200, 0x100)]) == 0x210
    assert (
        map_rva(
            0x1010,
            4,
            [(0x1000, 0x100, 0x200, 0x100), (0x1000, 0x100, 0x400, 0x100)],
        )
        is None
    )


def test_companion_and_identity_limits_accept_exact_population():
    artifact = elf_note(b"A" * 8)
    companion = debug.SuppliedCompanion("app.debug", elf_section_note(b"A" * 8))
    exact = debug.verify_debug_companions(
        artifact,
        (companion,),
        limits=debug.DebugLimits(max_companions=1),
    )
    overflow = debug.verify_debug_companions(
        artifact,
        (companion, companion),
        limits=debug.DebugLimits(max_companions=1),
    )
    assert exact.status == "verified"
    assert exact.limited is False
    assert overflow.status == "verified"
    assert overflow.limited is True
    assert any(gap.code == "companion_limit" for gap in overflow.gaps)


def test_identity_byte_and_geometry_limits_are_explicit_at_boundary():
    note = elf_note(b"A" * 8)
    header = matcher.elf_header(note)
    note_size = next(matcher.program_headers(note, header))[5]
    exact_note = debug.debug_identity(note, debug.DebugLimits(max_identity_bytes=note_size))
    limited_note = debug.debug_identity(note, debug.DebugLimits(max_identity_bytes=note_size - 1))
    assert exact_note.identity is not None
    assert limited_note.identity is None
    assert limited_note.limited is True
    assert limited_note.gaps[0].code == "note_limit"

    pe = pe_rsds(bytes(range(16)), 7)
    record_size = int.from_bytes(pe[0x210:0x214], "little")
    assert (
        debug.debug_identity(pe, debug.DebugLimits(max_identity_bytes=record_size)).identity
        is not None
    )
    oversized_pe = bytearray(pe)
    oversized_pe[0x13C:0x140] = (record_size + 1).to_bytes(4, "little")
    pe_limit = debug.debug_identity(
        bytes(oversized_pe), debug.DebugLimits(max_identity_bytes=record_size)
    )
    assert pe_limit.identity is None
    assert pe_limit.limited is True
    assert pe_limit.gaps[0].code == "pe_debug_limit"

    exact_pdb = debug.debug_identity(
        pdb(bytes(range(16)), 7),
        debug.DebugLimits(max_pdb_blocks=4, max_pdb_directory_bytes=16),
    )
    limited_pdb = debug.debug_identity(
        pdb(bytes(range(16)), 7),
        debug.DebugLimits(max_pdb_blocks=3, max_pdb_directory_bytes=16),
    )
    assert exact_pdb.identity is not None
    assert limited_pdb.identity is None
    assert limited_pdb.limited is True
    assert limited_pdb.gaps[0].code == "pdb_limit"


def test_function_hint_limit_accepts_exact_population_without_partial_claim():
    companion = elf_with_symbols(
        b"\xc3\xc3",
        matcher.EM_X86_64,
        [
            {"name": "one", "address": CODE_ADDRESS, "size": 1},
            {"name": "two", "address": CODE_ADDRESS + 1, "size": 1},
        ],
    )
    artifact = elf_debuglink("app.debug", zlib.crc32(companion) & 0xFFFFFFFF)
    exact = debug.verify_debug_companions(
        artifact,
        (debug.SuppliedCompanion("app.debug", companion),),
        limits=debug.DebugLimits(max_function_hints=2),
        auto_pyelftools=False,
    )
    limited = debug.verify_debug_companions(
        artifact,
        (debug.SuppliedCompanion("app.debug", companion),),
        limits=debug.DebugLimits(max_function_hints=1),
        auto_pyelftools=False,
    )
    assert [hint.name for hint in exact.matches[0].function_hints] == ["one", "two"]
    assert exact.limited is False
    assert [hint.name for hint in limited.matches[0].function_hints] == ["one"]
    assert limited.limited is True
    assert any(gap.code == "function_hint_limit" for gap in limited.gaps)


def test_missing_malformed_and_fat_inputs_are_explicit():
    missing = debug.verify_debug_companions(elf_note(b"A" * 8), ())
    malformed = debug.debug_identity(b"MZ")
    fat = debug.debug_identity(b"\xca\xfe\xba\xbe" + bytes(32))
    assert missing.status == "unresolved"
    assert any(gap.code == "missing_debug_companion" for gap in missing.gaps)
    assert malformed.identity is None
    assert fat.gaps[0].code == "unsupported_fat_macho"


def test_assessment_is_json_compatible():
    result = debug.verify_debug_companions(
        macho_uuid(bytes(16)),
        (debug.SuppliedCompanion("a.dsym", macho_uuid(bytes(16))),),
    )
    assert result.as_dict()["matches"][0]["patch_status"] == "unknown"


@pytest.mark.parametrize("value", [0, -1], ids=["zero", "negative"])
def test_debug_limits_must_be_strictly_positive(value):
    with pytest.raises(ValueError, match="limits must be positive"):
        debug.debug_identity(b"fixture", debug.DebugLimits(max_commands=value))


def test_elf_note_padding_kind_and_name_are_parsed_without_overread():
    name = b"GNU\0"
    raw = struct.pack("<III", len(name), 2, debug.NT_GNU_BUILD_ID) + name + b"\x01\x02\0\0"
    assert debug._gnu_build_ids(raw + bytes(3), "little") == {"0102"}  # noqa: SLF001
    with pytest.raises(ValueError, match="Truncated ELF note header"):
        debug._gnu_build_ids(raw + b"\0\0\x01", "little")  # noqa: SLF001
    wrong_kind = bytearray(raw)
    wrong_kind[8:12] = (debug.NT_GNU_BUILD_ID + 1).to_bytes(4, "little")
    wrong_name = raw[:12] + b"BAD\0" + raw[16:]
    assert debug._gnu_build_ids(bytes(wrong_kind), "little") == set()  # noqa: SLF001
    assert debug._gnu_build_ids(wrong_name, "little") == set()  # noqa: SLF001


def test_elf_bounded_string_and_debuglink_filename_limits_are_half_open():
    bounded = debug._bounded_string  # noqa: SLF001 -- String-table boundary contract.
    assert bounded(b"\0name\0", 0, 6, 1) == "name"
    assert bounded(b"\0name\0", 0, 5, 1) is None
    assert bounded(b"\0name\0", 0, 6, 6) is None
    assert bounded(b"\0\xff\0", 0, 3, 1) is None

    def payload(name):
        raw = name + b"\0"
        return raw + bytes((-len(raw)) % 4) + bytes(4)

    accepted = b"a" * (debug.MAX_NAME_BYTES - 1)
    assert debug._parse_debuglink(payload(accepted), "little")[0] == accepted.decode()  # noqa: SLF001
    with pytest.raises(ValueError, match="filename"):
        debug._parse_debuglink(payload(b"a" * debug.MAX_NAME_BYTES), "little")  # noqa: SLF001


def test_macho_exact_command_limits_are_complete_not_limited():
    data = macho_uuid(bytes(range(16)))
    exact = debug.debug_identity(
        data,
        debug.DebugLimits(max_commands=1, max_identity_bytes=24),
    )
    command_limited = debug.debug_identity(data, debug.DebugLimits(max_commands=0 + 1))
    byte_limited = debug.debug_identity(data, debug.DebugLimits(max_identity_bytes=23))
    assert exact.identity is not None
    assert exact.limited is False
    assert command_limited.identity is not None
    assert byte_limited.identity is None
    assert byte_limited.limited is True
    assert byte_limited.gaps[0].code == "macho_command_limit"


def test_pe_rva_and_rsds_record_boundaries_are_half_open():
    map_rva = debug._pe_rva_to_offset  # noqa: SLF001 -- PE ownership boundary contract.
    sections = [(0x1000, 0x100, 0x200, 0x100)]
    assert map_rva(0x1000, 1, sections) == 0x200
    assert map_rva(0x10FC, 4, sections) == 0x2FC
    assert map_rva(0x10FD, 4, sections) is None
    assert map_rva(0x0FFF, 1, sections) is None

    guid = bytes(range(16))
    one_character = b"RSDS" + guid + (7).to_bytes(4, "little") + b"a\0"
    assert debug._parse_rsds(one_character) == (guid.hex(), 7, "a")  # noqa: SLF001
    assert debug._parse_rsds(one_character[:-1]) is None  # noqa: SLF001
    assert debug._parse_rsds(b"NB10" + one_character[4:]) is None  # noqa: SLF001
    assert debug._parse_rsds(b"RSDS" + guid + (7).to_bytes(4, "little") + b"\xff\0") is None  # noqa: SLF001


def test_pdb_block_population_accepts_last_valid_block_only():
    block_size = 512
    data = bytes(block_size * 3) + b"Z" + bytes(block_size - 1)
    assert debug._pdb_blocks(data, [3], block_size, 1, 4) == b"Z"  # noqa: SLF001
    with pytest.raises(ValueError, match="outside the file"):
        debug._pdb_blocks(data, [4], block_size, 1, 4)  # noqa: SLF001


def test_elf_symbol_budget_accepts_exact_population_and_limits_overflow():
    companion = elf_with_symbols(
        b"\xc3\xc3",
        matcher.EM_X86_64,
        [
            {"name": "one", "address": CODE_ADDRESS, "size": 1},
            {"name": "two", "address": CODE_ADDRESS + 1, "size": 1},
        ],
    )
    exact_hints, exact_gaps, exact_limited = debug._elf_function_hints(  # noqa: SLF001
        companion, debug.DebugLimits(max_symbols=3)
    )
    limited_hints, limited_gaps, limited = debug._elf_function_hints(  # noqa: SLF001
        companion, debug.DebugLimits(max_symbols=2)
    )
    assert [hint.name for hint in exact_hints] == ["one", "two"]
    assert exact_gaps == ()
    assert exact_limited is False
    assert limited_hints == ()
    assert limited_gaps == ()
    assert limited is True


def test_layout_function_hints_require_valid_kind_ranges_and_exact_limit(monkeypatch):
    layout = {
        "kind": "pe",
        "gaps": [],
        "exports": [{"file_offset": 10, "name": "named"}],
        "functions": [
            {"file_offset": 10, "size": 4},
            {"file_offset": 20, "size": 2, "rva": 0x2020},
            {"file_offset": 14, "size": 1},
            {"file_offset": 30, "size": 0},
            "invalid",
        ],
        "ranges": {"mapped": [{"file_offset": 10, "vmaddr": 0x1000, "size": 4}]},
    }
    monkeypatch.setattr(debug, "inspect_layout", lambda _data: layout)
    hints, limited = debug._layout_function_hints(  # noqa: SLF001
        b"fixture", "pe", debug.DebugLimits(max_function_hints=3)
    )
    assert [(hint.name, hint.virtual_address, hint.size) for hint in hints] == [
        ("named", 0x1000, 4),
        (None, 0x2020, 2),
        (None, None, 1),
    ]
    assert limited is False
    limited_hints, limited = debug._layout_function_hints(  # noqa: SLF001
        b"fixture", "pe", debug.DebugLimits(max_function_hints=2)
    )
    assert len(limited_hints) == 2
    assert limited is True
    layout["gaps"] = ["incomplete"]
    assert debug._layout_function_hints(b"fixture", "pe", debug.DEFAULT_DEBUG_LIMITS) == (  # noqa: SLF001
        (),
        False,
    )


def test_dwarf_line_filtering_ignores_terminal_and_incomplete_states(monkeypatch):
    monkeypatch.setattr(debug, "_dwarf_size_allowed", lambda *_args: True)
    hint = debug.FunctionHint("decode", 0x1000, 4)
    states = [
        None,
        SimpleNamespace(address=0x1000, file=1, line=1, end_sequence=True),
        SimpleNamespace(address=0x1000, file=1, line=None, end_sequence=False),
        SimpleNamespace(address=0x1000, file=1, line=17, end_sequence=False),
    ]
    enriched, gaps, limited = debug._dwarf_line_hints(  # noqa: SLF001
        b"fixture",
        (hint,),
        debug.DEFAULT_DEBUG_LIMITS,
        fake_pyelftools(version=4, states=states, files=[b"src/decode.c"]),
    )
    assert (enriched[0].source_file, enriched[0].source_line) == ("decode.c", 17)
    assert gaps == ()
    assert limited is False


def test_matching_methods_keep_each_identity_failure_distinct():
    data = b"companion"
    checksum = zlib.crc32(data) & 0xFFFFFFFF

    def mismatch(artifact, companion, label, content):
        methods, reason = debug._matching_methods(  # noqa: SLF001
            artifact, companion, label, content
        )
        assert methods == []
        assert reason is not None
        return reason

    elf_link = debug.DebugIdentity("elf", debuglink_name="app.debug", debuglink_crc32=checksum)
    assert debug._matching_methods(elf_link, None, "app.debug", data) == (  # noqa: SLF001
        ["gnu_debuglink_crc32"],
        None,
    )
    assert "filename" in mismatch(elf_link, None, "wrong.debug", data)
    assert "CRC" in mismatch(elf_link, None, "app.debug", b"different")

    elf_build = debug.DebugIdentity("elf", build_id="aa")
    assert debug._matching_methods(  # noqa: SLF001
        elf_build, debug.DebugIdentity("elf", build_id="aa"), "ignored", data
    ) == (["gnu_build_id"], None)
    assert "differ" in mismatch(
        elf_build, debug.DebugIdentity("elf", build_id="bb"), "ignored", data
    )
    assert "No comparable" in mismatch(elf_build, None, "ignored", data)

    macho = debug.DebugIdentity("macho", macho_uuid="aa")
    assert debug._matching_methods(  # noqa: SLF001
        macho, debug.DebugIdentity("macho", macho_uuid="aa"), "ignored", data
    ) == (["macho_uuid"], None)
    assert "UUID" in mismatch(macho, None, "ignored", data)

    pe = debug.DebugIdentity("pe", pdb_guid="aa", pdb_age=7, pdb_name="app.pdb")
    pdb_identity = debug.DebugIdentity("pdb", pdb_guid="aa", pdb_age=7)
    assert debug._matching_methods(pe, pdb_identity, "dir/app.pdb", data) == (  # noqa: SLF001
        ["pdb_guid_age"],
        None,
    )
    assert "supported PDB" in mismatch(pe, None, "app.pdb", data)
    assert "GUID/age" in mismatch(
        pe, debug.DebugIdentity("pdb", pdb_guid="aa", pdb_age=8), "app.pdb", data
    )
    assert "basename" in mismatch(pe, pdb_identity, "wrong.pdb", data)


def test_dwarf_backend_absence_malformed_data_and_unresolved_rows_are_distinct(monkeypatch):
    monkeypatch.setattr(debug, "_dwarf_size_allowed", lambda *_args: True)
    hint = debug.FunctionHint("decode", 0x1000, 4)

    class NoDwarfFile:
        def __init__(self, _stream):
            pass

        def has_dwarf_info(self):
            return False

    no_dwarf = SimpleNamespace(
        __name__="fake",
        __version__=debug.PINNED_PYELFTOOLS_VERSION,
        ELFFile=NoDwarfFile,
    )
    unchanged, gaps, limited = debug._dwarf_line_hints(  # noqa: SLF001
        b"fixture", (hint,), debug.DEFAULT_DEBUG_LIMITS, no_dwarf
    )
    assert unchanged == (hint,)
    assert gaps[0].code == "dwarf_lines_unavailable"
    assert limited is False

    def fail(_stream):
        message = "broken DWARF"
        raise ValueError(message)

    malformed = SimpleNamespace(
        __name__="fake",
        __version__=debug.PINNED_PYELFTOOLS_VERSION,
        ELFFile=fail,
    )
    unchanged, gaps, limited = debug._dwarf_line_hints(  # noqa: SLF001
        b"fixture", (hint,), debug.DEFAULT_DEBUG_LIMITS, malformed
    )
    assert unchanged == (hint,)
    assert gaps[0].code == "malformed_dwarf_lines"
    assert limited is False

    invalid_file = SimpleNamespace(
        address=0x1000,
        file=2,
        line=7,
        end_sequence=False,
    )
    unchanged, gaps, limited = debug._dwarf_line_hints(  # noqa: SLF001
        b"fixture",
        (hint,),
        debug.DEFAULT_DEBUG_LIMITS,
        fake_pyelftools(version=5, states=[invalid_file], files=[b"decode.c"]),
    )
    assert unchanged == (hint,)
    assert gaps[0].code == "dwarf_lines_unresolved"
    assert limited is False


def test_rsds_name_and_pdb_stream_count_exact_boundaries():
    guid = bytes(range(16))
    maximum = b"RSDS" + guid + (7).to_bytes(4, "little")
    maximum += b"a" * (debug.MAX_NAME_BYTES - 1) + b"\0"
    assert debug._parse_rsds(maximum) is not None  # noqa: SLF001
    assert debug._parse_rsds(maximum[:-1] + b"a\0") is None  # noqa: SLF001

    data = pdb(guid, 7)
    exact = debug.debug_identity(data, debug.DebugLimits(max_commands=2))
    overflow = debug.debug_identity(data, debug.DebugLimits(max_commands=1))
    assert exact.identity is not None
    assert overflow.identity is None
    assert overflow.gaps[0].code == "malformed_pdb_identity"

    too_small = bytearray(data)
    too_small[32:36] = (511).to_bytes(4, "little")
    assert debug.debug_identity(bytes(too_small)).gaps[0].code == "malformed_pdb_identity"


def test_elf_identity_section_limit_and_missing_identity_states_are_exact():
    build_id = debug.debug_identity(elf_note(b"identity"))
    assert build_id.identity is not None
    assert build_id.gaps == ()
    assert build_id.limited is False

    sectioned = elf_section_note(b"identity")
    exact = debug.debug_identity(sectioned, debug.DebugLimits(max_commands=3))
    limited = debug.debug_identity(sectioned, debug.DebugLimits(max_commands=2))
    assert exact.identity is not None
    assert exact.limited is False
    assert limited.identity is None
    assert limited.gaps[0].code == "section_limit"
    assert limited.limited is True

    no_identity = bytearray(sectioned)
    header = list(matcher.ELF_HEADER.unpack_from(no_identity))
    header[12] = 0
    header[13] = 0
    matcher.ELF_HEADER.pack_into(no_identity, 0, *header)
    missing = debug.debug_identity(bytes(no_identity))
    assert missing.identity == debug.DebugIdentity("elf")
    assert missing.gaps[0].code == "missing_debug_identity"
    assert missing.limited is False


def test_dwarf_section_byte_limit_accepts_exact_positive_population():
    data = bytearray(elf_section_note(b"identity"))
    old_name = b".note.gnu.build-id"
    name_offset = data.find(old_name)
    assert name_offset >= 0
    replacement = b".debug_info\0" + bytes(len(old_name) - len(b".debug_info") - 1)
    data[name_offset : name_offset + len(old_name)] = replacement
    header = matcher.elf_header(bytes(data))
    sections = matcher.section_headers(bytes(data), header)
    debug_bytes = sections[1][5]
    assert debug._dwarf_size_allowed(  # noqa: SLF001
        bytes(data), debug.DebugLimits(max_identity_bytes=debug_bytes)
    )
    assert not debug._dwarf_size_allowed(  # noqa: SLF001
        bytes(data), debug.DebugLimits(max_identity_bytes=debug_bytes - 1)
    )
    assert not debug._dwarf_size_allowed(elf_note(b"identity"), debug.DEFAULT_DEBUG_LIMITS)  # noqa: SLF001


def test_unsupported_artifact_assessment_preserves_identity_gap_and_limit_state():
    result = debug.verify_debug_companions(b"unsupported", ())
    assert result.artifact_identity is None
    assert result.matches == ()
    assert result.status == "unsupported"
    assert result.limited is False
    assert result.gaps == (
        debug.DebugGap(
            "unsupported_debug_format",
            "Unsupported supplied debug companion format",
        ),
    )
