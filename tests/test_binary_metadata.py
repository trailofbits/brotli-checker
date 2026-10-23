import struct
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/brotli-checker/scripts"
sys.path.insert(0, str(SCRIPTS))
import brotli_binary_match as matcher  # noqa: E402
import brotli_binary_metadata as metadata  # noqa: E402

CODE_OFFSET = 0x100
CODE_ADDRESS = 0x400100


def encoded_version(major: int, minor: int, patch: int) -> int:
    return major << 24 | minor << 12 | patch


def x86_return(value: int, *, cet: bool = False, frame: bool = False) -> bytes:
    code = b"\xb8" + value.to_bytes(4, "little") + b"\xc3"
    if frame:
        code = bytes.fromhex("554889e5") + code[:-1] + b"\x5d\xc3"
    if cet:
        code = bytes.fromhex("f30f1efa") + code
    return code


def move_wide(opcode: int, immediate: int, shift: int = 0, register: int = 0) -> int:
    return opcode | (shift // 16 << 21) | (immediate << 5) | register


def aarch64_return(value: int) -> list[int]:
    low = value & 0xFFFF
    high = value >> 16
    words = [move_wide(0x52800000, low)]
    if high:
        words.append(move_wide(0x72800000, high, 16))
    return [*words, 0xD65F03C0]


def words(values: list[int]) -> bytes:
    return struct.pack(f"<{len(values)}I", *values)


def elf_with_symbols(  # noqa: PLR0913 -- ELF fixture corruption controls are explicit.
    code: bytes,
    machine: int,
    symbols: list[dict],
    *,
    owner_type: int = 1,
    owner_flags: int = 6,
    owner_address: int = CODE_ADDRESS,
    owner_offset: int = CODE_OFFSET,
    program_flags: int = 5,
    string_type: int = 3,
    symbol_entry_size: int = metadata.SYMBOL.size,
    symbol_table_copies: int = 1,
) -> bytes:
    strings = bytearray(b"\0")
    packed_symbols = [metadata.SYMBOL.pack(0, 0, 0, 0, 0, 0)]
    for symbol in symbols:
        name_offset = symbol.get("name_offset")
        if name_offset is None:
            name_offset = len(strings)
            strings.extend(symbol["name"].encode("ascii") + b"\0")
        packed_symbols.append(
            metadata.SYMBOL.pack(
                name_offset,
                symbol.get("info", 0x12),
                0,
                symbol.get("index", 1),
                symbol.get("address", CODE_ADDRESS),
                symbol.get("size", len(code)),
            )
        )
    symbol_bytes = b"".join(packed_symbols)
    symbol_offset = (CODE_OFFSET + len(code) + 7) & ~7
    string_offset = symbol_offset + len(symbol_bytes)
    section_offset = (string_offset + len(strings) + 7) & ~7
    sections = [
        (0,) * 10,
        (0, owner_type, owner_flags, owner_address, owner_offset, len(code), 0, 0, 4, 0),
        (0, string_type, 0, 0, string_offset, len(strings), 0, 0, 1, 0),
    ]
    sections.extend(
        (0, 2, 0, 0, symbol_offset, len(symbol_bytes), 2, 0, 8, symbol_entry_size)
        for _ in range(symbol_table_copies)
    )
    header = matcher.ELF_HEADER.pack(
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3,
        machine,
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
        0,
    )
    program = matcher.PROGRAM_HEADER.pack(
        1,
        program_flags,
        CODE_OFFSET,
        CODE_ADDRESS,
        CODE_ADDRESS,
        len(code),
        len(code),
        0x1000,
    )
    result = bytearray(header + program)
    result.extend(bytes(CODE_OFFSET - len(result)))
    result.extend(code)
    result.extend(bytes(symbol_offset - len(result)))
    result.extend(symbol_bytes)
    result.extend(strings)
    result.extend(bytes(section_offset - len(result)))
    result.extend(b"".join(matcher.SECTION_HEADER.pack(*section) for section in sections))
    return bytes(result)


@pytest.mark.parametrize(
    "release",
    [(1, 0, 9), (1, 0, 10), (1, 1, 0), (1, 1, 1), (1, 2, 0), (1, 2, 1)],
)
def test_extracts_six_release_versions(release):
    value = encoded_version(*release)
    code = x86_return(value)
    result = metadata.decoder_metadata(
        elf_with_symbols(
            code,
            matcher.EM_X86_64,
            [{"name": "BrotliDecoderVersion"}],
        )
    )
    assert result["defined_symbols"] == ["BrotliDecoderVersion"]
    assert result["versions"] == [
        {
            "version": ".".join(map(str, release)),
            "file_offset": CODE_OFFSET,
            "method": "constant_decoder_version_return",
        }
    ]
    assert not result["limited"]


@pytest.mark.parametrize(
    ("cet", "frame"), [(False, False), (True, False), (False, True), (True, True)]
)
def test_x86_constant_return_forms(cet, frame):
    value = encoded_version(1, 2, 1)
    assert (
        metadata.constant_version(x86_return(value, cet=cet, frame=frame), matcher.EM_X86_64)
        == value
    )


def test_imports_and_definitions_require_function_symbols():
    code = x86_return(encoded_version(1, 2, 1))
    result = metadata.decoder_metadata(
        elf_with_symbols(
            code,
            matcher.EM_X86_64,
            [
                {"name": "BrotliDecoderVersion"},
                {"name": "BrotliDecoderDecompress", "index": 0, "address": 0, "size": 0},
                {"name": "BrotliDecoderCreateInstance", "info": 0x11},
                {"name": "BrotliDecoderDestroyInstance", "index": 99},
            ],
        )
    )
    assert result["defined_symbols"] == ["BrotliDecoderVersion"]
    assert result["imported_symbols"] == ["BrotliDecoderDecompress"]
    assert result["versions"][0]["version"] == "1.2.1"


@pytest.mark.parametrize("prefix", [[], [0xD503245F]])
@pytest.mark.parametrize("frame", [False, True])
def test_aarch64_direct_bti_and_pac_forms(prefix, frame):
    value = encoded_version(1, 2, 1)
    body = aarch64_return(value)
    if frame:
        body = [
            0xD503233F,
            0xA9BF7BFD,
            *body[:-1],
            0x910003FD,
            0xA8C17BFD,
            0xD50323BF,
            0xD65F03C0,
        ]
    assert metadata.constant_version(words([*prefix, *body]), matcher.EM_AARCH64) == value


def test_aarch64_rejects_unallocated_move_wide_halfwords():
    ret = 0xD65F03C0
    invalid_movz = move_wide(0x52800000, 1) | 1 << 22
    invalid_movk = move_wide(0x72800000, 1, 16) | 1 << 22
    assert metadata.constant_version(words([invalid_movz, ret]), matcher.EM_AARCH64) is None
    assert (
        metadata.constant_version(
            words([move_wide(0x52800000, 1), invalid_movk, ret]), matcher.EM_AARCH64
        )
        is None
    )


@pytest.mark.parametrize(
    ("code", "machine"),
    [
        (b"\xb9\x01\x00\x00\x00\xc3", matcher.EM_X86_64),
        (b"\xb8\x01\x00\x00\x00\xc3\x90", matcher.EM_X86_64),
        (words([move_wide(0x52800000, 1, register=1), 0xD65F03C0]), matcher.EM_AARCH64),
        (words([move_wide(0x52800000, 1), 0xD503201F, 0xD65F03C0]), matcher.EM_AARCH64),
        (b"\xb8\x01\x00\x00\x00\xc3", 3),
    ],
)
def test_unknown_code_forms_are_rejected(code, machine):
    assert metadata.constant_version(code, machine) is None


@pytest.mark.parametrize(
    "changes",
    [
        {"owner_type": 3},
        {"owner_flags": 2},
        {"owner_flags": 4},
        {"owner_address": CODE_ADDRESS + 4},
        {"owner_offset": CODE_OFFSET + 4},
    ],
)
def test_symbol_must_belong_to_its_executable_section(changes):
    code = x86_return(encoded_version(1, 2, 1))
    result = metadata.decoder_metadata(
        elf_with_symbols(
            code,
            matcher.EM_X86_64,
            [{"name": "BrotliDecoderVersion"}],
            **changes,
        )
    )
    assert result["defined_symbols"] == []
    assert result["versions"] == []


def test_symbol_code_must_map_through_an_executable_load_segment():
    code = x86_return(encoded_version(1, 2, 1))
    result = metadata.decoder_metadata(
        elf_with_symbols(
            code,
            matcher.EM_X86_64,
            [{"name": "BrotliDecoderVersion"}],
            program_flags=4,
        )
    )
    assert result["versions"] == []
    assert result["reason"].startswith("Decoder metadata unavailable:")


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"symbol_entry_size": 1}, "Malformed ELF symbol table"),
        ({"string_type": 1}, "ELF symbol names do not reference a string table"),
    ],
)
def test_malformed_symbol_tables_are_rejected(changes, reason):
    code = x86_return(encoded_version(1, 2, 1))
    result = metadata.decoder_metadata(
        elf_with_symbols(
            code,
            matcher.EM_X86_64,
            [{"name": "BrotliDecoderVersion"}],
            **changes,
        )
    )
    assert result["versions"] == []
    assert reason in result["reason"]


def test_symbol_name_must_be_inside_string_table():
    code = x86_return(encoded_version(1, 2, 1))
    result = metadata.decoder_metadata(
        elf_with_symbols(
            code,
            matcher.EM_X86_64,
            [{"name": "BrotliDecoderVersion", "name_offset": 1000}],
        )
    )
    assert result["versions"] == []
    assert "symbol name outside string table" in result["reason"]


def test_symbol_and_table_budgets_are_explicit(monkeypatch):
    code = x86_return(encoded_version(1, 2, 1))
    data = elf_with_symbols(
        code,
        matcher.EM_X86_64,
        [{"name": "BrotliDecoderVersion"}],
        symbol_table_copies=2,
    )
    monkeypatch.setattr(metadata, "MAX_SYMBOLS", 1)
    result = metadata.decoder_metadata(data)
    assert result["limited"]
    assert result["reason"] == "Decoder symbol limit reached"

    monkeypatch.setattr(metadata, "MAX_SYMBOLS", 1_000_000)
    monkeypatch.setattr(metadata, "MAX_SYMBOL_TABLES", 1)
    result = metadata.decoder_metadata(data)
    assert result["limited"]
    assert result["reason"] == "Decoder symbol-table limit reached"


def test_missing_or_truncated_section_metadata_is_unknown():
    truncated = metadata.decoder_metadata(b"\x7fELF")
    assert truncated["versions"] == []
    assert truncated["reason"].startswith("Decoder metadata unavailable:")

    code = x86_return(encoded_version(1, 2, 1))
    data = bytearray(elf_with_symbols(code, matcher.EM_X86_64, [{"name": "BrotliDecoderVersion"}]))
    struct.pack_into("<H", data, 60, 0)
    result = metadata.decoder_metadata(bytes(data))
    assert result["versions"] == []
    assert result["reason"] == "No ELF section table; symbol-based decoder evidence unavailable"


def test_repeated_symbols_do_not_reread_program_table(monkeypatch):
    code = x86_return(encoded_version(1, 2, 0))
    data = elf_with_symbols(code, matcher.EM_X86_64, [{"name": "BrotliDecoderVersion"}] * 200)
    header = matcher.elf_header(data)
    original = metadata.checked_slice
    table_reads = []

    def count_reads(data, offset, size):
        if offset == header[5] and size == header[9] * header[10]:
            table_reads.append(size)
        return original(data, offset, size)

    monkeypatch.setattr(metadata, "checked_slice", count_reads)
    result = metadata.decoder_metadata(data)
    assert not result["limited"]
    assert len(result["versions"]) == 1
    assert len(table_reads) <= 1


@pytest.mark.parametrize(
    ("limit", "reason"),
    [
        ("MAX_MAPPING_WORK", "mapping work limit"),
        ("MAX_FUNCTION_QUERIES", "function query limit"),
    ],
)
def test_metadata_mapping_work_is_jointly_bounded(monkeypatch, limit, reason):
    code = x86_return(encoded_version(1, 2, 0))
    data = elf_with_symbols(
        code * 3,
        matcher.EM_X86_64,
        [
            {
                "name": "BrotliDecoderVersion",
                "address": CODE_ADDRESS + index * len(code),
                "size": len(code),
            }
            for index in range(3)
        ],
    )
    monkeypatch.setattr(metadata, limit, 2, raising=False)
    result = metadata.decoder_metadata(data)
    assert result["limited"]
    assert reason in result["reason"]
    assert len(result["versions"]) == 2
