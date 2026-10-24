"""Bounded ELF decoder symbols and constant version returns, without target execution."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from brotli_binary_match import (
    EM_386,
    EM_AARCH64,
    EM_ARM,
    EM_X86_64,
    ELFLayout,
    checked_range,
    checked_slice,
    elf_header,
    executable_ranges,
    program_headers,
    section_headers,
    symbol_rows,
)

if TYPE_CHECKING:
    from brotli_binary_data import Buffer

SYMBOL = struct.Struct("<IBBHQQ")
MAX_SYMBOLS = 1_000_000
MAX_SYMBOL_TABLES = 16
MAX_MAPPING_WORK = 1_000_000
MAX_FUNCTION_QUERIES = 4096
MAX_SYMBOL_NAME_BYTES = 64
MAX_VERSION_FUNCTION_BYTES = 64
SHT_STRTAB = 3
STT_FUNC = 2
SHF_ALLOC = 2
SHF_EXECINSTR = 4
X86_CONST_RETURN_BYTES = 6
X86_MOV_EAX_IMMEDIATE = 0xB8
X86_RET = 0xC3
AARCH64_BTI_C = 0xD503245F
AARCH64_RET = 0xD65F03C0
AARCH64_MOVZ_W0 = 0x52800000
AARCH64_MOVK_W0 = 0x72800000
AARCH64_MIN_RETURN_WORDS = 2
AARCH64_MAX_RETURN_WORDS = 3
DECODER_APIS = frozenset(
    name.encode("ascii")
    for name in (
        "BrotliDecoderVersion",
        "BrotliDecoderDecompress",
        "BrotliDecoderDecompressStream",
        "BrotliDecoderCreateInstance",
        "BrotliDecoderDestroyInstance",
    )
)


def constant_version(  # noqa: C901, PLR0911 -- Strict instruction-form decoder.
    code: bytes, machine: int
) -> int | None:
    """Recognize only complete, straight-line constant-return function forms."""
    if machine in (EM_X86_64, EM_386):
        code = code.removeprefix(bytes.fromhex("f30f1efa" if machine == EM_X86_64 else "f30f1efb"))
        if code.startswith(bytes.fromhex("554889e5")) and code.endswith(b"\x5d\xc3"):
            code = code[4:-2] + b"\xc3"
        if (
            len(code) == X86_CONST_RETURN_BYTES
            and code[0] == X86_MOV_EAX_IMMEDIATE
            and code[-1] == X86_RET
        ):
            return int.from_bytes(code[1:5], "little")
        return None
    if machine != EM_AARCH64 or len(code) % 4:
        return None
    words = list(struct.unpack(f"<{len(code) // 4}I", code))
    if words and words[0] == AARCH64_BTI_C:
        words.pop(0)
    # GCC branch-protected frame, with no arbitrary intervening instructions.
    if words[:2] == [0xD503233F, 0xA9BF7BFD] and words[-4:] == [
        0x910003FD,
        0xA8C17BFD,
        0xD50323BF,
        0xD65F03C0,
    ]:
        words = [*words[2:-4], AARCH64_RET]
    if (
        not words
        or words[-1] != AARCH64_RET
        or not AARCH64_MIN_RETURN_WORDS <= len(words) <= AARCH64_MAX_RETURN_WORDS
    ):
        return None
    first = words[0]
    if first & 0xFFC0001F != AARCH64_MOVZ_W0:  # MOVZ W0, imm16, LSL {0,16}.
        return None
    value = ((first >> 5) & 0xFFFF) << (((first >> 21) & 1) * 16)
    if len(words) == AARCH64_MAX_RETURN_WORDS:
        second = words[1]
        if second & 0xFFC0001F != AARCH64_MOVK_W0:
            return None
        shift = ((second >> 21) & 1) * 16
        value = (value & ~(0xFFFF << shift)) | (((second >> 5) & 0xFFFF) << shift)
    return value


class MetadataLimitError(ValueError):
    """Decoder metadata exceeded a combined CPU or retained-query budget."""


class FunctionOffsets:
    """Parse mappings once and bound work across all distinct function lookups."""

    def __init__(self, data: Buffer, header: tuple) -> None:
        self.segments = [
            (start, virtual, file_size)
            for kind, flags, start, virtual, _, file_size, _, _ in program_headers(data, header)
            if kind == 1 and flags & 1
        ]
        self.cache: dict[tuple[int, int], int | None] = {}
        self.work_left = MAX_MAPPING_WORK

    def resolve(self, address: int, size: int) -> int | None:
        key = (address, size)
        if key in self.cache:
            return self.cache[key]
        if len(self.cache) >= MAX_FUNCTION_QUERIES:
            msg = "Decoder function query limit reached"
            raise MetadataLimitError(msg)
        for start, virtual, file_size in self.segments:
            if self.work_left <= 0:
                msg = "Decoder mapping work limit reached"
                raise MetadataLimitError(msg)
            self.work_left -= 1
            if virtual <= address and address + size <= virtual + file_size:
                offset = start + address - virtual
                self.cache[key] = offset
                return offset
        self.cache[key] = None
        return None


def decoder_metadata(data: Buffer) -> dict:
    result = {
        "defined_symbols": [],
        "imported_symbols": [],
        "versions": [],
        "reason": "No decoder API symbols found; stripped copies remain possible",
        "limited": False,
        "limits": {
            "max_symbols": MAX_SYMBOLS,
            "max_symbol_tables": MAX_SYMBOL_TABLES,
            "max_mapping_work": MAX_MAPPING_WORK,
            "max_function_queries": MAX_FUNCTION_QUERIES,
        },
    }
    try:
        _read_symbols(data, result)
    except MetadataLimitError as error:
        result.update(reason=str(error), limited=True)
    except (ValueError, struct.error) as error:
        result["reason"] = f"Decoder metadata unavailable: {error}"
    return result


def _read_symbols(  # noqa: C901, PLR0912, PLR0915 -- Bounded ELF table walk.
    data: Buffer, result: dict
) -> None:
    header = elf_header(data)
    executable_ranges(data)
    if not header[12]:
        result["reason"] = "No ELF section table; symbol-based decoder evidence unavailable"
        return
    sections = section_headers(data, header)
    symbol = ELFLayout.of(header).parser("symbol")
    seen = 0
    tables_seen = 0
    offsets = FunctionOffsets(data, header)
    version_locations: set[tuple[int, int]] = set()
    for section in sections:
        if section[1] not in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM.
            continue
        tables_seen += 1
        if tables_seen > MAX_SYMBOL_TABLES:
            result.update(reason="Decoder symbol-table limit reached", limited=True)
            return
        if section[9] != symbol.size or section[5] % symbol.size or section[6] >= len(sections):
            msg = "Malformed ELF symbol table"
            raise ValueError(msg)
        seen += section[5] // symbol.size
        if seen > MAX_SYMBOLS:
            result.update(reason="Decoder symbol limit reached", limited=True)
            return
        string_section = sections[section[6]]
        if string_section[1] != SHT_STRTAB:
            msg = "ELF symbol names do not reference a string table"
            raise ValueError(msg)
        string_start, string_end = checked_range(data, string_section[4], string_section[5])
        for name_offset, info, _, index, symbol_address, size in symbol_rows(data, header, section):
            if name_offset >= string_section[5]:
                msg = "ELF symbol name outside string table"
                raise ValueError(msg)
            name_start = string_start + name_offset
            end = data.find(b"\0", name_start, min(name_start + MAX_SYMBOL_NAME_BYTES, string_end))
            name = data[name_start:end] if end >= 0 else b""
            if name not in DECODER_APIS or info & 0xF != STT_FUNC:
                continue
            offset = None
            if index == 0:
                bucket = result["imported_symbols"]
            else:
                if index >= len(sections):
                    continue
                owner = sections[index]
                # ARM function pointers mark Thumb state in bit zero.
                address = symbol_address & (~1 if header[2] == EM_ARM else -1)
                offset = offsets.resolve(address, max(size, 1))
                if (
                    owner[1] != 1
                    or owner[2] & (SHF_ALLOC | SHF_EXECINSTR) != (SHF_ALLOC | SHF_EXECINSTR)
                    or address < owner[3]
                    or address + max(size, 1) > owner[3] + owner[5]
                    or offset != owner[4] + address - owner[3]
                ):
                    continue
                bucket = result["defined_symbols"]
            text = name.decode("ascii")
            if text not in bucket:
                bucket.append(text)
            if (
                name != b"BrotliDecoderVersion"
                or index == 0
                or not 0 < size <= MAX_VERSION_FUNCTION_BYTES
                or offset is None
            ):
                continue
            location = (offset, size)
            if location in version_locations:
                continue
            version_locations.add(location)
            value = constant_version(checked_slice(data, offset, size), header[2])
            if value is not None:
                version = f"{value >> 24}.{(value >> 12) & 0xFFF}.{value & 0xFFF}"
                evidence = {
                    "version": version,
                    "file_offset": offset,
                    "method": "constant_decoder_version_return",
                }
                result["versions"].append(evidence)
    if result["defined_symbols"] or result["imported_symbols"]:
        result["reason"] = (
            "Defined/imported decoder symbols; reported versions do not establish patch status"
        )
