import struct
import zlib
from types import SimpleNamespace

import brotli_binary_match as matcher
import brotli_debug_companions as debug
from test_binary_layout import mach_fixture
from test_binary_metadata import elf_with_symbols


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


def macho_uuid(value):
    command = struct.pack("<II16s", debug.LC_UUID, 24, value)
    return b"\xcf\xfa\xed\xfe" + struct.pack("<iiIIIII", 0, 0, 2, 1, 24, 0, 0) + command


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
