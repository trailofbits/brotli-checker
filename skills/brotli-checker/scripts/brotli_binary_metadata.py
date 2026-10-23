"""Bounded ELF decoder symbols and constant version returns, without target execution."""

from __future__ import annotations

import struct

from brotli_binary_match import (
    EM_AARCH64,
    EM_X86_64,
    PROGRAM_HEADER,
    SECTION_HEADER,
    checked_slice,
    elf_header,
    executable_ranges,
)

SYMBOL = struct.Struct("<IBBHQQ")
MAX_SYMBOLS = 1_000_000
MAX_SYMBOL_TABLES = 16
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
    if machine == EM_X86_64:
        code = code.removeprefix(bytes.fromhex("f30f1efa"))  # CET ENDBR64.
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


def _function_offset(data: bytes, header: tuple, address: int, size: int) -> int | None:
    table = checked_slice(data, header[5], header[9] * header[10])
    for kind, flags, start, virtual, _, file_size, _, _ in PROGRAM_HEADER.iter_unpack(table):
        if kind == 1 and flags & 1 and virtual <= address and address + size <= virtual + file_size:
            return start + address - virtual
    return None


def _checked_range(data: bytes, offset: int, size: int) -> tuple[int, int]:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        msg = "ELF range outside file"
        raise ValueError(msg)
    return offset, offset + size


def decoder_metadata(data: bytes) -> dict:
    result = {
        "defined_symbols": [],
        "imported_symbols": [],
        "versions": [],
        "reason": "No decoder API symbols found; stripped copies remain possible",
        "limited": False,
    }
    try:
        _read_symbols(data, result)
    except (ValueError, struct.error) as error:
        result["reason"] = f"Decoder metadata unavailable: {error}"
    return result


def _read_symbols(  # noqa: C901, PLR0912, PLR0915 -- Bounded ELF table walk.
    data: bytes, result: dict
) -> None:
    header = elf_header(data)
    executable_ranges(data)
    if not header[12]:
        result["reason"] = "No ELF section table; symbol-based decoder evidence unavailable"
        return
    if header[11] != SECTION_HEADER.size:
        msg = "Unsupported ELF section table"
        raise ValueError(msg)
    sections = list(
        SECTION_HEADER.iter_unpack(checked_slice(data, header[6], header[12] * header[11]))
    )
    seen = 0
    tables_seen = 0
    for section in sections:
        if section[1] not in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM.
            continue
        tables_seen += 1
        if tables_seen > MAX_SYMBOL_TABLES:
            result.update(reason="Decoder symbol-table limit reached", limited=True)
            return
        if section[9] != SYMBOL.size or section[5] % SYMBOL.size or section[6] >= len(sections):
            msg = "Malformed ELF symbol table"
            raise ValueError(msg)
        seen += section[5] // SYMBOL.size
        if seen > MAX_SYMBOLS:
            result.update(reason="Decoder symbol limit reached", limited=True)
            return
        string_section = sections[section[6]]
        if string_section[1] != SHT_STRTAB:
            msg = "ELF symbol names do not reference a string table"
            raise ValueError(msg)
        string_start, string_end = _checked_range(data, string_section[4], string_section[5])
        symbols = checked_slice(data, section[4], section[5])
        for name_offset, info, _, index, address, size in SYMBOL.iter_unpack(symbols):
            if name_offset >= string_section[5]:
                msg = "ELF symbol name outside string table"
                raise ValueError(msg)
            name_start = string_start + name_offset
            end = data.find(b"\0", name_start, min(name_start + MAX_SYMBOL_NAME_BYTES, string_end))
            name = data[name_start:end] if end >= 0 else b""
            if name not in DECODER_APIS or info & 0xF != STT_FUNC:
                continue
            if index == 0:
                bucket = result["imported_symbols"]
            else:
                if index >= len(sections):
                    continue
                owner = sections[index]
                offset = _function_offset(data, header, address, max(size, 1))
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
            ):
                continue
            offset = _function_offset(data, header, address, size)
            if offset is None:
                continue
            value = constant_version(checked_slice(data, offset, size), header[2])
            if value is not None:
                version = f"{value >> 24}.{(value >> 12) & 0xFFF}.{value & 0xFFF}"
                evidence = {
                    "version": version,
                    "file_offset": offset,
                    "method": "constant_decoder_version_return",
                }
                if evidence not in result["versions"]:
                    result["versions"].append(evidence)
    if result["defined_symbols"] or result["imported_symbols"]:
        result["reason"] = (
            "Defined/imported decoder symbols; reported versions do not establish patch status"
        )
