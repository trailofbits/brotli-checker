"""Verify identities of explicitly supplied local debug companions."""

# ruff: noqa: ANN401, BLE001, C901, EM101, FBT003, PERF401, PLR0911, PLR0912, PLR0915, PLR2004, TRY003, TRY300, TRY301
# Bounded binary-format parsers keep validation branches adjacent to their layouts.

from __future__ import annotations

import importlib
import importlib.metadata
import io
import json
import struct
import zlib
from bisect import bisect_left
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from typing import TYPE_CHECKING, Any, Literal

from brotli_binary_layout import inspect_layout
from brotli_binary_match import (
    SHT_DYNSYM,
    SHT_STRTAB,
    SHT_SYMTAB,
    STT_FUNC,
    ELFLayout,
    checked_range,
    checked_slice,
    elf_header,
    program_headers,
    section_headers,
    symbol_rows,
)

if TYPE_CHECKING:
    from collections.abc import Generator

    from brotli_binary_data import Buffer

PT_NOTE = 4
SHT_NOTE = 7
SHF_ALLOC = 2
SHF_EXECINSTR = 4
NT_GNU_BUILD_ID = 3
LC_UUID = 0x1B
IMAGE_DEBUG_TYPE_CODEVIEW = 2
PE_DEBUG_DIRECTORY_INDEX = 6
MSF_NIL_STREAM_SIZE = 0xFFFFFFFF
MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
MAX_NAME_BYTES = 1024
COPY_CHUNK_BYTES = 1024 * 1024
PINNED_PYELFTOOLS_VERSION = "0.33"


@dataclass(frozen=True)
class DebugLimits:
    max_companions: int = 64
    max_identity_bytes: int = 16 * 1024 * 1024
    max_commands: int = 65_536
    max_symbols: int = 1_000_000
    max_function_hints: int = 4096
    max_pdb_directory_bytes: int = 16 * 1024 * 1024
    max_pdb_blocks: int = 1_000_000
    max_line_entries: int = 1_000_000


DEFAULT_DEBUG_LIMITS = DebugLimits()


@dataclass(frozen=True)
class DebugIdentity:
    format: Literal["elf", "macho", "pe", "pdb"]
    build_id: str | None = None
    debuglink_name: str | None = None
    debuglink_crc32: int | None = None
    macho_uuid: str | None = None
    pdb_guid: str | None = None
    pdb_age: int | None = None
    pdb_name: str | None = None


@dataclass(frozen=True)
class FunctionHint:
    name: str | None
    virtual_address: int | None
    size: int
    file_offset: int | None = None
    source_file: str | None = None
    source_line: int | None = None


@dataclass(frozen=True)
class DebugGap:
    code: str
    reason: str
    label: str | None = None


@dataclass(frozen=True)
class IdentityInspection:
    identity: DebugIdentity | None
    gaps: tuple[DebugGap, ...]
    limited: bool


@dataclass(frozen=True)
class SuppliedCompanion:
    label: str
    data: Buffer


@dataclass(frozen=True)
class VerifiedDebugCompanion:
    label: str
    methods: tuple[str, ...]
    identity: DebugIdentity
    function_hints: tuple[FunctionHint, ...]
    patch_status: Literal["unknown"] = "unknown"
    use_scope: Literal["names_bounds_only"] = "names_bounds_only"


@dataclass(frozen=True)
class DebugAssessment:
    artifact_identity: DebugIdentity | None
    matches: tuple[VerifiedDebugCompanion, ...]
    gaps: tuple[DebugGap, ...]
    status: Literal["verified", "ambiguous", "unresolved", "unsupported"]
    limited: bool

    def as_dict(self) -> dict[str, Any]:
        return json.loads(json.dumps(asdict(self), sort_keys=True))


def _validate_limits(limits: DebugLimits) -> None:
    if any(value <= 0 for value in asdict(limits).values()):
        msg = "Debug companion limits must be positive"
        raise ValueError(msg)


def _leaf_name(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def _crc32_data(data: Buffer) -> int:
    checksum = 0
    for offset in range(0, len(data), COPY_CHUNK_BYTES):
        checksum = zlib.crc32(data[offset : offset + COPY_CHUNK_BYTES], checksum)
    return checksum & 0xFFFFFFFF


def debug_identity(data: Buffer, limits: DebugLimits = DEFAULT_DEBUG_LIMITS) -> IdentityInspection:
    """Read one local artifact identity without following embedded paths."""
    _validate_limits(limits)
    if data.startswith(b"\x7fELF"):
        return _elf_identity(data, limits)
    magic = data[:4]
    if magic in (
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
    ):
        return _macho_identity(data, limits)
    if magic in (
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    ):
        gap = DebugGap(
            "unsupported_fat_macho", "Fat Mach-O companions require explicit slice selection"
        )
        return IdentityInspection(None, (gap,), False)
    if data.startswith(b"MZ"):
        return _pe_identity(data, limits)
    if data.startswith(MSF7_MAGIC):
        return _pdb_identity(data, limits)
    gap = DebugGap("unsupported_debug_format", "Unsupported supplied debug companion format")
    return IdentityInspection(None, (gap,), False)


def _elf_identity(data: Buffer, limits: DebugLimits) -> IdentityInspection:
    gaps = []
    try:
        header = elf_header(data)
        layout = ELFLayout.of(header)
        byteorder = layout.byteorder
        notes = []
        if header[10]:
            for kind, _, offset, _, _, size, _, _ in program_headers(data, header):
                if kind == PT_NOTE and size:
                    notes.append((offset, size))
        debuglink_name = None
        debuglink_crc = None
        if header[12]:
            sections = section_headers(data, header)
            if len(sections) > limits.max_commands:
                gap = DebugGap("section_limit", "ELF section limit reached")
                return IdentityInspection(None, (gap,), True)
            for section in sections:
                if section[1] == SHT_NOTE and section[5]:
                    notes.append((section[4], section[5]))
            names = _section_names(data, header, sections)
            for index, name in names.items():
                if name == ".gnu_debuglink":
                    debuglink_name, debuglink_crc = _parse_debuglink(
                        checked_slice(data, sections[index][4], sections[index][5]),
                        byteorder,
                    )
                    break
        build_ids = set()
        total = 0
        for offset, size in sorted(set(notes)):
            total += size
            if total > limits.max_identity_bytes:
                gaps.append(DebugGap("note_limit", "ELF note byte limit reached"))
                return IdentityInspection(None, tuple(gaps), True)
            build_ids.update(_gnu_build_ids(checked_slice(data, offset, size), byteorder))
        if len(build_ids) > 1:
            gaps.append(DebugGap("conflicting_build_ids", "ELF contains conflicting GNU build IDs"))
            return IdentityInspection(None, tuple(gaps), False)
        build_id = next(iter(build_ids), None)
        if build_id is None and debuglink_name is None:
            gaps.append(
                DebugGap("missing_debug_identity", "ELF has no GNU build ID or .gnu_debuglink")
            )
        identity = DebugIdentity(
            "elf",
            build_id=build_id,
            debuglink_name=debuglink_name,
            debuglink_crc32=debuglink_crc,
        )
        return IdentityInspection(identity, tuple(gaps), False)
    except (ValueError, struct.error) as error:
        gap = DebugGap("malformed_elf_identity", f"Cannot parse ELF debug identity: {error}")
        return IdentityInspection(None, (gap,), False)


def _gnu_build_ids(data: bytes, byteorder: Literal["little", "big"]) -> set[str]:
    values = set()
    cursor = 0
    while cursor < len(data):
        if len(data) - cursor < 12:
            if any(data[cursor:]):
                msg = "Truncated ELF note header"
                raise ValueError(msg)
            break
        namesz = int.from_bytes(data[cursor : cursor + 4], byteorder)
        descsz = int.from_bytes(data[cursor + 4 : cursor + 8], byteorder)
        kind = int.from_bytes(data[cursor + 8 : cursor + 12], byteorder)
        cursor += 12
        name_end = cursor + namesz
        desc_start = (name_end + 3) & ~3
        desc_end = desc_start + descsz
        next_note = (desc_end + 3) & ~3
        if next_note > len(data):
            msg = "ELF note extends outside its segment"
            raise ValueError(msg)
        name = data[cursor:name_end].rstrip(b"\0")
        if kind == NT_GNU_BUILD_ID and name == b"GNU" and descsz:
            values.add(data[desc_start:desc_end].hex())
        cursor = next_note
    return values


def _section_names(data: Buffer, header: tuple, sections: list[tuple]) -> dict[int, str]:
    index = header[13]
    if index == 0 or index >= len(sections):
        return {}
    strings = sections[index]
    if strings[1] != SHT_STRTAB:
        msg = "ELF section names do not reference a string table"
        raise ValueError(msg)
    start, end = checked_range(data, strings[4], strings[5])
    result = {}
    for section_index, section in enumerate(sections):
        name = _bounded_string(data, start, end, section[0])
        if name is not None:
            result[section_index] = name
    return result


def _bounded_string(data: Buffer, start: int, end: int, offset: int) -> str | None:
    if offset < 0 or start + offset >= end:
        return None
    value_start = start + offset
    value_end = data.find(b"\0", value_start, min(value_start + MAX_NAME_BYTES, end))
    if value_end < 0:
        return None
    try:
        return data[value_start:value_end].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _parse_debuglink(data: bytes, byteorder: Literal["little", "big"]) -> tuple[str, int]:
    terminator = data.find(b"\0")
    if terminator <= 0 or terminator >= MAX_NAME_BYTES:
        msg = "Invalid .gnu_debuglink filename"
        raise ValueError(msg)
    try:
        name = data[:terminator].decode("utf-8")
    except UnicodeDecodeError as error:
        msg = "Invalid .gnu_debuglink filename"
        raise ValueError(msg) from error
    if _leaf_name(name) != name or name in (".", ".."):
        msg = ".gnu_debuglink must contain a basename, not a path"
        raise ValueError(msg)
    crc_offset = (terminator + 1 + 3) & ~3
    if crc_offset + 4 != len(data):
        msg = "Invalid .gnu_debuglink CRC layout"
        raise ValueError(msg)
    return name, int.from_bytes(data[crc_offset : crc_offset + 4], byteorder)


def _macho_identity(data: Buffer, limits: DebugLimits) -> IdentityInspection:
    magic = data[:4]
    layouts: dict[bytes, tuple[Literal["little", "big"], bool]] = {
        b"\xfe\xed\xfa\xce": ("big", False),
        b"\xce\xfa\xed\xfe": ("little", False),
        b"\xfe\xed\xfa\xcf": ("big", True),
        b"\xcf\xfa\xed\xfe": ("little", True),
    }
    byteorder, is_64 = layouts[magic]
    header_size = 32 if is_64 else 28
    if len(data) < header_size:
        gap = DebugGap("malformed_macho_identity", "Truncated Mach-O header")
        return IdentityInspection(None, (gap,), False)
    ncmds = int.from_bytes(data[16:20], byteorder)
    sizeofcmds = int.from_bytes(data[20:24], byteorder)
    if ncmds > limits.max_commands or sizeofcmds > limits.max_identity_bytes:
        gap = DebugGap("macho_command_limit", "Mach-O load-command limit reached")
        return IdentityInspection(None, (gap,), True)
    if header_size + sizeofcmds > len(data):
        gap = DebugGap("malformed_macho_identity", "Mach-O load commands exceed the file")
        return IdentityInspection(None, (gap,), False)
    cursor = header_size
    uuids = set()
    for _ in range(ncmds):
        if cursor + 8 > header_size + sizeofcmds:
            gap = DebugGap("malformed_macho_identity", "Truncated Mach-O load command")
            return IdentityInspection(None, (gap,), False)
        command = int.from_bytes(data[cursor : cursor + 4], byteorder)
        size = int.from_bytes(data[cursor + 4 : cursor + 8], byteorder)
        if size < 8 or cursor + size > header_size + sizeofcmds:
            gap = DebugGap("malformed_macho_identity", "Invalid Mach-O load-command size")
            return IdentityInspection(None, (gap,), False)
        if command == LC_UUID:
            if size != 24:
                gap = DebugGap("malformed_macho_identity", "Invalid LC_UUID size")
                return IdentityInspection(None, (gap,), False)
            uuids.add(data[cursor + 8 : cursor + 24].hex())
        cursor += size
    if cursor != header_size + sizeofcmds:
        gap = DebugGap("malformed_macho_identity", "Mach-O load-command sizes are inconsistent")
        return IdentityInspection(None, (gap,), False)
    if len(uuids) != 1:
        reason = "Mach-O has no LC_UUID" if not uuids else "Mach-O has conflicting LC_UUID values"
        gap = DebugGap("missing_macho_uuid", reason)
        return IdentityInspection(None, (gap,), False)
    return IdentityInspection(DebugIdentity("macho", macho_uuid=next(iter(uuids))), (), False)


def _pe_identity(data: Buffer, limits: DebugLimits) -> IdentityInspection:
    try:
        if len(data) < 0x40:
            raise ValueError("Truncated DOS header")
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if checked_slice(data, pe_offset, 4) != b"PE\0\0":
            raise ValueError("Missing PE signature")
        coff = checked_slice(data, pe_offset + 4, 20)
        section_count = int.from_bytes(coff[2:4], "little")
        optional_size = int.from_bytes(coff[16:18], "little")
        if section_count > limits.max_commands:
            gap = DebugGap("pe_section_limit", "PE section limit reached")
            return IdentityInspection(None, (gap,), True)
        optional_offset = pe_offset + 24
        optional = checked_slice(data, optional_offset, optional_size)
        if len(optional) < 2:
            raise ValueError("Truncated PE optional header")
        magic = int.from_bytes(optional[:2], "little")
        directory_offset = 112 if magic == 0x20B else 96 if magic == 0x10B else -1
        if directory_offset < 0 or directory_offset + (PE_DEBUG_DIRECTORY_INDEX + 1) * 8 > len(
            optional
        ):
            raise ValueError("PE debug data directory is unavailable")
        debug_entry = directory_offset + PE_DEBUG_DIRECTORY_INDEX * 8
        debug_rva = int.from_bytes(optional[debug_entry : debug_entry + 4], "little")
        debug_size = int.from_bytes(optional[debug_entry + 4 : debug_entry + 8], "little")
        if debug_size > limits.max_identity_bytes:
            gap = DebugGap("pe_debug_limit", "PE debug-directory byte limit reached")
            return IdentityInspection(None, (gap,), True)
        section_offset = optional_offset + optional_size
        sections = []
        for index in range(section_count):
            row = checked_slice(data, section_offset + index * 40, 40)
            virtual_size = int.from_bytes(row[8:12], "little")
            virtual_address = int.from_bytes(row[12:16], "little")
            raw_size = int.from_bytes(row[16:20], "little")
            raw_offset = int.from_bytes(row[20:24], "little")
            checked_range(data, raw_offset, raw_size)
            sections.append((virtual_address, max(virtual_size, raw_size), raw_offset, raw_size))
        debug_offset = _pe_rva_to_offset(debug_rva, debug_size, sections)
        if debug_offset is None or debug_size % 28:
            raise ValueError("PE debug directory is unmapped or malformed")
        identities = set()
        for offset in range(debug_offset, debug_offset + debug_size, 28):
            row = checked_slice(data, offset, 28)
            kind = int.from_bytes(row[12:16], "little")
            if kind != IMAGE_DEBUG_TYPE_CODEVIEW:
                continue
            size = int.from_bytes(row[16:20], "little")
            if size > limits.max_identity_bytes:
                gap = DebugGap("pe_debug_limit", "PE CodeView record byte limit reached")
                return IdentityInspection(None, (gap,), True)
            address = int.from_bytes(row[20:24], "little")
            raw_offset = int.from_bytes(row[24:28], "little")
            if _pe_rva_to_offset(address, size, sections) != raw_offset:
                raise ValueError("PE CodeView RVA and raw file pointer disagree")
            record = checked_slice(data, raw_offset, size)
            identity = _parse_rsds(record)
            if identity is not None:
                identities.add(identity)
        if len(identities) != 1:
            reason = (
                "PE has no RSDS CodeView identity"
                if not identities
                else "PE has conflicting RSDS identities"
            )
            gap = DebugGap("missing_pe_pdb_identity", reason)
            return IdentityInspection(None, (gap,), False)
        guid, age, name = next(iter(identities))
        return IdentityInspection(
            DebugIdentity("pe", pdb_guid=guid, pdb_age=age, pdb_name=name), (), False
        )
    except (ValueError, struct.error) as error:
        gap = DebugGap("malformed_pe_identity", f"Cannot parse PE debug identity: {error}")
        return IdentityInspection(None, (gap,), False)


def _pe_rva_to_offset(rva: int, size: int, sections: list[tuple[int, int, int, int]]) -> int | None:
    candidates = {
        raw_offset + rva - virtual
        for virtual, memory_size, raw_offset, raw_size in sections
        if virtual <= rva and rva + size <= virtual + min(memory_size, raw_size)
    }
    return next(iter(candidates)) if len(candidates) == 1 else None


def _parse_rsds(data: bytes) -> tuple[str, int, str] | None:
    if len(data) < 25 or data[:4] != b"RSDS":
        return None
    terminator = data.find(b"\0", 24)
    if terminator < 0 or terminator - 24 >= MAX_NAME_BYTES:
        return None
    try:
        name = _leaf_name(data[24:terminator].decode("utf-8"))
    except UnicodeDecodeError:
        return None
    if not name:
        return None
    return data[4:20].hex(), int.from_bytes(data[20:24], "little"), name


def _pdb_identity(data: Buffer, limits: DebugLimits) -> IdentityInspection:
    try:
        if len(data) < 56 or data[:32] != MSF7_MAGIC:
            raise ValueError("Unsupported PDB MSF header")
        block_size = int.from_bytes(data[32:36], "little")
        block_count = int.from_bytes(data[40:44], "little")
        directory_size = int.from_bytes(data[44:48], "little")
        block_map = int.from_bytes(data[52:56], "little")
        if block_count > limits.max_pdb_blocks or directory_size > limits.max_pdb_directory_bytes:
            gap = DebugGap("pdb_limit", "PDB block or directory limit reached")
            return IdentityInspection(None, (gap,), True)
        if (
            block_size < 512
            or block_size & (block_size - 1)
            or block_count * block_size > len(data)
        ):
            raise ValueError("Invalid or over-limit PDB block geometry")
        directory_blocks = (directory_size + block_size - 1) // block_size
        if directory_blocks * 4 > block_size:
            raise ValueError("Multi-block PDB directory maps are unsupported")
        map_offset = block_map * block_size
        block_numbers = [
            int.from_bytes(checked_slice(data, map_offset + index * 4, 4), "little")
            for index in range(directory_blocks)
        ]
        directory = _pdb_blocks(data, block_numbers, block_size, directory_size, block_count)
        if len(directory) < 4:
            raise ValueError("Truncated PDB stream directory")
        stream_count = int.from_bytes(directory[:4], "little")
        if stream_count > limits.max_commands or 4 + stream_count * 4 > len(directory):
            raise ValueError("Invalid PDB stream count")
        sizes = [
            int.from_bytes(directory[4 + index * 4 : 8 + index * 4], "little")
            for index in range(stream_count)
        ]
        cursor = 4 + stream_count * 4
        streams = []
        for size in sizes:
            count = 0 if size == MSF_NIL_STREAM_SIZE else (size + block_size - 1) // block_size
            if cursor + count * 4 > len(directory):
                raise ValueError("Truncated PDB stream block list")
            streams.append(
                [
                    int.from_bytes(directory[cursor + i * 4 : cursor + i * 4 + 4], "little")
                    for i in range(count)
                ]
            )
            cursor += count * 4
        if len(streams) <= 1 or sizes[1] in (MSF_NIL_STREAM_SIZE, 0):
            raise ValueError("PDB info stream is missing")
        info = _pdb_blocks(data, streams[1], block_size, sizes[1], block_count)
        if len(info) < 28:
            raise ValueError("Truncated PDB info stream")
        age = int.from_bytes(info[8:12], "little")
        guid = info[12:28].hex()
        return IdentityInspection(DebugIdentity("pdb", pdb_guid=guid, pdb_age=age), (), False)
    except (ValueError, struct.error) as error:
        gap = DebugGap("malformed_pdb_identity", f"Cannot parse PDB identity: {error}")
        return IdentityInspection(None, (gap,), False)


def _pdb_blocks(
    data: Buffer, blocks: list[int], block_size: int, size: int, block_count: int
) -> bytes:
    content = bytearray()
    for block in blocks:
        if block >= block_count:
            msg = "PDB stream block is outside the file"
            raise ValueError(msg)
        content.extend(checked_slice(data, block * block_size, block_size))
    return bytes(content[:size])


def _elf_function_hints(
    data: Buffer, limits: DebugLimits
) -> tuple[tuple[FunctionHint, ...], tuple[DebugGap, ...], bool]:
    try:
        header = elf_header(data)
        if not header[12]:
            return (), (), False
        sections = section_headers(data, header)
        parser = ELFLayout.of(header).parser("symbol")
        hints = []
        malformed = False
        symbols_seen = 0
        for table in sections:
            if table[1] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            if table[9] != parser.size or table[5] % parser.size or table[6] >= len(sections):
                gap = DebugGap("malformed_elf_function_hints", "Malformed ELF symbol table")
                return tuple(hints), (gap,), False
            strings = sections[table[6]]
            if strings[1] != SHT_STRTAB:
                gap = DebugGap(
                    "malformed_elf_function_hints",
                    "ELF symbol table has no string-table owner",
                )
                return tuple(hints), (gap,), False
            start, end = checked_range(data, strings[4], strings[5])
            symbols_seen += table[5] // parser.size
            if symbols_seen > limits.max_symbols:
                return tuple(hints), (), True
            for name_offset, info, _, index, address, size in symbol_rows(data, header, table):
                if info & 0xF != STT_FUNC or index == 0:
                    continue
                span = max(size, 1)
                if index >= len(sections):
                    malformed = True
                    continue
                owner = sections[index]
                if (
                    owner[2] & (SHF_ALLOC | SHF_EXECINSTR) != (SHF_ALLOC | SHF_EXECINSTR)
                    or address < owner[3]
                    or address + span > owner[3] + owner[5]
                ):
                    malformed = True
                    continue
                name = _bounded_string(data, start, end, name_offset)
                if name:
                    if len(hints) >= limits.max_function_hints:
                        return tuple(hints), (), True
                    hints.append(FunctionHint(name=name, virtual_address=address, size=size))
        gaps = (
            (
                DebugGap(
                    "malformed_elf_function_hints",
                    "ELF function symbol has inconsistent section ownership or bounds",
                ),
            )
            if malformed
            else ()
        )
        return tuple(hints), gaps, False
    except (ValueError, struct.error):
        gap = DebugGap(
            "malformed_elf_function_hints",
            "ELF function hints could not be parsed safely",
        )
        return (), (gap,), False


def _layout_function_hints(
    data: Buffer, expected_kind: str, limits: DebugLimits
) -> tuple[tuple[FunctionHint, ...], bool]:
    layout = inspect_layout(data)
    if layout.get("kind") != expected_kind or layout.get("gaps"):
        return (), False
    names = {
        item["file_offset"]: item.get("name")
        for item in layout.get("exports", [])
        if isinstance(item, dict) and type(item.get("file_offset")) is int
    }
    hints = []
    for function in layout.get("functions", []):
        if not isinstance(function, dict):
            continue
        offset = function.get("file_offset")
        size = function.get("size")
        if type(offset) is not int or type(size) is not int or size <= 0:
            continue
        virtual = function.get("rva")
        if type(virtual) is not int:
            virtual = None
            for mapped in layout.get("ranges", {}).get("mapped", []):
                if (
                    isinstance(mapped, dict)
                    and type(mapped.get("file_offset")) is int
                    and type(mapped.get("vmaddr")) is int
                    and type(mapped.get("size")) is int
                    and mapped["file_offset"] <= offset < mapped["file_offset"] + mapped["size"]
                ):
                    virtual = mapped["vmaddr"] + offset - mapped["file_offset"]
                    break
        hints.append(
            FunctionHint(
                name=names.get(offset),
                virtual_address=virtual,
                size=size,
                file_offset=offset,
            )
        )
        if len(hints) >= limits.max_function_hints:
            return tuple(hints), True
    return tuple(hints), False


@contextmanager
def _stream(data: Buffer) -> Generator[Any, None, None]:
    if isinstance(data, bytes):
        with io.BytesIO(data) as stream:
            yield stream
        return
    position = data.tell()
    try:
        data.seek(0)
        yield data
    finally:
        data.seek(position)


def _dwarf_size_allowed(data: Buffer, limits: DebugLimits) -> bool:
    try:
        header = elf_header(data)
        if not header[12]:
            return False
        sections = section_headers(data, header)
        names = _section_names(data, header, sections)
        total = sum(
            sections[index][5]
            for index, name in names.items()
            if name.startswith((".debug_", ".zdebug_"))
        )
        return 0 < total <= limits.max_identity_bytes
    except (ValueError, struct.error):
        return False


def _dwarf_line_hints(
    data: Buffer,
    hints: tuple[FunctionHint, ...],
    limits: DebugLimits,
    module: Any | None,
) -> tuple[tuple[FunctionHint, ...], tuple[DebugGap, ...], bool]:
    if not hints or not _dwarf_size_allowed(data, limits):
        gap = DebugGap("dwarf_lines_unavailable", "No bounded DWARF line data is available")
        return hints, (gap,), False
    if module is None:
        try:
            module = importlib.import_module("elftools.elf.elffile")
        except (ImportError, OSError) as error:
            gap = DebugGap(
                "pyelftools_unavailable",
                f"Optional pyelftools {PINNED_PYELFTOOLS_VERSION} is unavailable: {error}",
            )
            return hints, (gap,), False
    module_name = getattr(module, "__name__", None)
    version = getattr(module, "__version__", None)
    if module_name == "elftools.elf.elffile":
        try:
            version = importlib.metadata.version("pyelftools")
        except importlib.metadata.PackageNotFoundError:
            version = None
    if version != PINNED_PYELFTOOLS_VERSION or not callable(getattr(module, "ELFFile", None)):
        gap = DebugGap(
            "pyelftools_version_unsupported",
            f"Expected pyelftools {PINNED_PYELFTOOLS_VERSION}",
        )
        return hints, (gap,), False
    rows = []
    try:
        with _stream(data) as stream:
            elf = module.ELFFile(stream)
            if not elf.has_dwarf_info():
                gap = DebugGap("dwarf_lines_unavailable", "ELF companion has no DWARF info")
                return hints, (gap,), False
            dwarf = elf.get_dwarf_info()
            for unit in dwarf.iter_CUs():
                program = dwarf.line_program_for_CU(unit)
                if program is None:
                    continue
                version_value = int(program.header.version)
                for entry in program.get_entries():
                    state = entry.state
                    if state is None or state.end_sequence or state.line is None:
                        continue
                    if len(rows) >= limits.max_line_entries:
                        gap = DebugGap("dwarf_line_limit", "DWARF line-entry limit reached")
                        return hints, (gap,), True
                    file_index = int(state.file) - (1 if version_value < 5 else 0)
                    files = program["file_entry"]
                    if not 0 <= file_index < len(files):
                        continue
                    name = getattr(files[file_index], "name", b"")
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", "replace")
                    if name:
                        rows.append((int(state.address), _leaf_name(str(name)), int(state.line)))
    except Exception as error:
        gap = DebugGap("malformed_dwarf_lines", f"Cannot parse DWARF line data: {error}")
        return hints, (gap,), False
    rows = sorted(set(rows))
    addresses = [row[0] for row in rows]
    enriched = []
    for hint in hints:
        if hint.virtual_address is None:
            enriched.append(hint)
            continue
        index = bisect_left(addresses, hint.virtual_address)
        if index < len(rows) and rows[index][0] < hint.virtual_address + max(hint.size, 1):
            _, source_file, source_line = rows[index]
            enriched.append(replace(hint, source_file=source_file, source_line=source_line))
        else:
            enriched.append(hint)
    gaps = (
        ()
        if any(hint.source_file for hint in enriched)
        else (DebugGap("dwarf_lines_unresolved", "DWARF lines do not cover verified functions"),)
    )
    return tuple(enriched), gaps, False


def verify_debug_companions(
    artifact: Buffer,
    companions: tuple[SuppliedCompanion, ...],
    limits: DebugLimits = DEFAULT_DEBUG_LIMITS,
    *,
    pyelftools_module: Any | None = None,
    auto_pyelftools: bool = True,
) -> DebugAssessment:
    """Verify only explicitly supplied companions; never open embedded paths or use a network."""
    _validate_limits(limits)
    artifact_inspection = debug_identity(artifact, limits)
    gaps = list(artifact_inspection.gaps)
    if artifact_inspection.identity is None:
        return DebugAssessment(None, (), tuple(gaps), "unsupported", artifact_inspection.limited)
    if len(companions) > limits.max_companions:
        gaps.append(DebugGap("companion_limit", "Supplied debug companion limit reached"))
        companions = companions[: limits.max_companions]
    matches = []
    for companion in companions:
        inspection = debug_identity(companion.data, limits)
        methods, mismatch = _matching_methods(
            artifact_inspection.identity,
            inspection.identity,
            companion.label,
            companion.data,
        )
        if mismatch is not None:
            gaps.append(DebugGap("debug_identity_mismatch", mismatch, companion.label))
            continue
        if not methods or inspection.identity is None:
            gaps.extend(DebugGap(gap.code, gap.reason, companion.label) for gap in inspection.gaps)
            continue
        hints = ()
        hint_limited = False
        if inspection.identity.format == "elf":
            hints, hint_gaps, hint_limited = _elf_function_hints(companion.data, limits)
            gaps.extend(DebugGap(gap.code, gap.reason, companion.label) for gap in hint_gaps)
            if auto_pyelftools:
                hints, line_gaps, line_limited = _dwarf_line_hints(
                    companion.data, hints, limits, pyelftools_module
                )
                hint_limited = hint_limited or line_limited
                gaps.extend(DebugGap(gap.code, gap.reason, companion.label) for gap in line_gaps)
        elif artifact_inspection.identity.format == "pe":
            hints, hint_limited = _layout_function_hints(artifact, "pe", limits)
        elif inspection.identity.format == "macho":
            hints, hint_limited = _layout_function_hints(companion.data, "mach_o", limits)
        else:
            gaps.append(
                DebugGap(
                    "debug_names_unavailable",
                    "Verified companion identity has no supported function-name parser",
                    companion.label,
                )
            )
        if hints and not any(hint.name for hint in hints):
            gaps.append(
                DebugGap(
                    "debug_names_unavailable",
                    "Verified function bounds have no supported debug names",
                    companion.label,
                )
            )
        if not any(hint.source_file is not None for hint in hints):
            gaps.append(
                DebugGap(
                    "source_locations_unavailable",
                    "Verified identity provides no supported source-line information",
                    companion.label,
                )
            )
        if hint_limited:
            gaps.append(
                DebugGap(
                    "function_hint_limit", "Debug function-hint limit reached", companion.label
                )
            )
        matches.append(
            VerifiedDebugCompanion(
                companion.label,
                tuple(methods),
                inspection.identity,
                hints,
            )
        )
    if len(matches) == 1:
        status: Literal["verified", "ambiguous", "unresolved", "unsupported"] = "verified"
    elif len(matches) > 1:
        status = "ambiguous"
        gaps.append(
            DebugGap(
                "ambiguous_debug_companion",
                "Multiple supplied companions match; no companion was selected",
            )
        )
    else:
        status = "unresolved"
        if not companions:
            gaps.append(DebugGap("missing_debug_companion", "No debug companions were supplied"))
    limited = artifact_inspection.limited or any(gap.code.endswith("_limit") for gap in gaps)
    return DebugAssessment(
        artifact_inspection.identity, tuple(matches), tuple(gaps), status, limited
    )


def _matching_methods(
    artifact: DebugIdentity,
    companion: DebugIdentity | None,
    label: str,
    data: Buffer,
) -> tuple[list[str], str | None]:
    if artifact.format == "elf":
        methods = []
        if artifact.debuglink_name is not None:
            if _leaf_name(label) != artifact.debuglink_name:
                return [], ".gnu_debuglink filename does not match supplied label"
            if _crc32_data(data) != artifact.debuglink_crc32:
                return [], ".gnu_debuglink CRC does not match supplied bytes"
            methods.append("gnu_debuglink_crc32")
        if (
            artifact.build_id is not None
            and companion is not None
            and companion.build_id is not None
        ):
            if artifact.build_id != companion.build_id:
                return [], "GNU build IDs differ"
            methods.append("gnu_build_id")
        if not methods:
            return [], "No comparable ELF debug identity"
        return methods, None
    if artifact.format == "macho":
        if companion is None or companion.macho_uuid != artifact.macho_uuid:
            return [], "Mach-O UUIDs differ or are unavailable"
        return ["macho_uuid"], None
    if artifact.format == "pe":
        if companion is None or companion.format != "pdb":
            return [], "Supplied companion is not a supported PDB"
        if (companion.pdb_guid, companion.pdb_age) != (artifact.pdb_guid, artifact.pdb_age):
            return [], "PDB GUID/age differs from PE CodeView identity"
        if artifact.pdb_name and _leaf_name(label) != artifact.pdb_name:
            return [], "PDB basename differs from PE CodeView identity"
        return ["pdb_guid_age"], None
    return [], "Artifact format does not accept a separate debug companion"
