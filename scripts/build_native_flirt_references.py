#!/usr/bin/env python3
# ruff: noqa: C901, EM101, EM102, PLR2004, TRY003
"""Build patch-bearing FLIRT references from reviewed COFF or Mach-O objects."""

from __future__ import annotations

import argparse
import hashlib
import json
import runpy
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))
from brotli_binary_match import (  # noqa: E402
    EM_386,
    EM_AARCH64,
    EM_X86_64,
    PATCH_HELPER_PATTERN,
    PATCH_ROLE_PATTERNS,
    valid_patch_functions,
)

ELF_BUILDER = runpy.run_path(str(ROOT / "scripts/build_flirt_references.py"))
FunctionPattern = ELF_BUILDER["FunctionPattern"]
resolve_ambiguities = ELF_BUILDER["resolve_ambiguities"]
render_pat = ELF_BUILDER["render_pat"]
write_catalog = ELF_BUILDER["write_catalog"]
MAX_OBJECT_BYTES = 512 * 1024 * 1024
MAX_SECTIONS = 65_536
MAX_SYMBOLS = 1_000_000
MAX_RELOCATIONS = 1_000_000
MAX_NAME_BYTES = 4096
COFF_HEADER = struct.Struct("<HHIIIHH")
COFF_SECTION = struct.Struct("<8sIIIIIIHHI")
COFF_SYMBOL = struct.Struct("<8sIhHBB")
COFF_RELOCATION = struct.Struct("<IIH")
COFF_MACHINES = {0x14C: (EM_386, 32), 0x8664: (EM_X86_64, 64), 0xAA64: (EM_AARCH64, 64)}
COFF_RELOCATION_WIDTHS = {
    0x14C: {0x0006: 4, 0x0007: 4, 0x0014: 4},
    0x8664: {
        0x0001: 8,
        0x0002: 4,
        0x0003: 4,
        0x0004: 4,
        0x0005: 4,
        0x0006: 4,
        0x0007: 4,
        0x0008: 4,
        0x0009: 4,
        0x000A: 4,
        0x000B: 4,
        0x000C: 2,
    },
    # ARM64 instruction relocations are conservatively wildcarded as complete words.
    0xAA64: {
        0x0001: 4,
        0x0002: 4,
        0x0003: 4,
        0x0004: 4,
        0x0005: 4,
        0x0006: 4,
        0x0007: 4,
        0x0008: 4,
        0x0009: 4,
        0x000A: 4,
        0x000B: 4,
        0x000C: 8,
        0x000D: 4,
        0x000E: 4,
    },
}
MH_MAGIC_64 = 0xFEEDFACF
MH_OBJECT = 1
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 2
MACH_HEADER_64 = struct.Struct("<8I")
MACH_SECTION_64 = struct.Struct("<16s16sQQIIIIIIII")
MACH_NLIST_64 = struct.Struct("<IBBHQ")
MACH_CPUS = {0x01000007: (EM_X86_64, 64), 0x0100000C: (EM_AARCH64, 64)}


@dataclass(frozen=True)
class NativeSection:
    name: str
    address: int
    offset: int
    size: int
    relocation_offset: int
    relocation_count: int
    executable: bool


@dataclass(frozen=True)
class NativeSymbol:
    name: str
    section: int
    address: int
    size: int


def checked(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        msg = "Native object range is outside the supplied bytes"
        raise ValueError(msg)
    return data[offset : offset + size]


def c_string(data: bytes, offset: int, end: int) -> str:
    if not 0 <= offset < end <= len(data):
        msg = "Native object string offset is outside its table"
        raise ValueError(msg)
    terminator = data.find(b"\0", offset, end)
    if terminator < 0 or terminator - offset > MAX_NAME_BYTES:
        msg = "Native object string is unterminated or oversized"
        raise ValueError(msg)
    return data[offset:terminator].decode("utf-8")


def normalized_name(value: str) -> str:
    return value.removeprefix("_")


def is_patch_name(value: str) -> bool:
    return any(pattern.fullmatch(value) for pattern in PATCH_ROLE_PATTERNS.values()) or (
        PATCH_HELPER_PATTERN.fullmatch(value) is not None
    )


def mask_range(mask: bytearray, offset: int, size: int) -> None:
    if offset < 0 or size <= 0 or offset + size > len(mask):
        msg = "Native object relocation is outside its executable section"
        raise ValueError(msg)
    mask[offset : offset + size] = bytes(size)


def _coff_name(raw: bytes, strings: bytes) -> str:
    if raw[:4] == bytes(4):
        return c_string(strings, int.from_bytes(raw[4:], "little"), len(strings))
    return raw.rstrip(b"\0").decode("utf-8")


def coff_patterns(data: bytes) -> tuple[list[FunctionPattern], str, int, str]:
    if len(data) < COFF_HEADER.size:
        raise ValueError("Truncated COFF header")
    machine, section_count, _, symbol_offset, symbol_count, optional_size, _ = (
        COFF_HEADER.unpack_from(data)
    )
    if machine not in COFF_MACHINES or optional_size or not 0 < section_count <= MAX_SECTIONS:
        msg = "Unsupported COFF object identity or section population"
        raise ValueError(msg)
    if symbol_count > MAX_SYMBOLS:
        raise ValueError("COFF symbol limit reached")
    sections = []
    section_table = COFF_HEADER.size
    for index in range(section_count):
        row = COFF_SECTION.unpack(
            checked(data, section_table + index * COFF_SECTION.size, COFF_SECTION.size)
        )
        name = row[0].rstrip(b"\0").decode("ascii", errors="replace")
        checked(data, row[4], row[3])
        if row[7] > MAX_RELOCATIONS:
            raise ValueError("COFF relocation limit reached")
        checked(data, row[5], row[7] * COFF_RELOCATION.size)
        sections.append(
            NativeSection(name, row[2], row[4], row[3], row[5], row[7], bool(row[9] & 0x20000000))
        )
    symbols_end = symbol_offset + symbol_count * COFF_SYMBOL.size
    checked(data, symbol_offset, symbol_count * COFF_SYMBOL.size)
    string_size = int.from_bytes(checked(data, symbols_end, 4), "little")
    if string_size < 4:
        raise ValueError("Invalid COFF string table")
    strings = checked(data, symbols_end, string_size)
    symbols = []
    cursor = 0
    while cursor < symbol_count:
        offset = symbol_offset + cursor * COFF_SYMBOL.size
        raw_name, address, section_number, symbol_type, _, aux_count = COFF_SYMBOL.unpack(
            checked(data, offset, COFF_SYMBOL.size)
        )
        if cursor + aux_count >= symbol_count:
            raise ValueError("Truncated COFF auxiliary symbols")
        name = normalized_name(_coff_name(raw_name, strings))
        size = 0
        if aux_count and symbol_type & 0x20:
            size = int.from_bytes(checked(data, offset + COFF_SYMBOL.size + 4, 4), "little")
        if 0 < section_number <= len(sections) and is_patch_name(name):
            symbols.append(NativeSymbol(name, section_number - 1, address, size))
        cursor += 1 + aux_count
    patterns = _patterns(data, sections, symbols, "coff", machine)
    elf_machine, _bits = COFF_MACHINES[machine]
    return patterns, "pe", elf_machine, "windows"


def _mach_sections(data: bytes) -> tuple[int, list[NativeSection], tuple[int, int, int, int]]:
    if len(data) < MACH_HEADER_64.size:
        raise ValueError("Truncated Mach-O header")
    magic, cpu, _, filetype, commands, command_bytes, _, _ = MACH_HEADER_64.unpack_from(data)
    if magic != MH_MAGIC_64 or filetype != MH_OBJECT or cpu not in MACH_CPUS:
        raise ValueError("Expected a supported 64-bit Mach-O object")
    if commands > MAX_SECTIONS or command_bytes > len(data) - MACH_HEADER_64.size:
        raise ValueError("Invalid Mach-O load-command population")
    sections = []
    symtab = None
    cursor = MACH_HEADER_64.size
    end = cursor + command_bytes
    for _ in range(commands):
        command, size = struct.unpack("<II", checked(data, cursor, 8))
        if size < 8 or cursor + size > end:
            raise ValueError("Invalid Mach-O load command")
        if command == LC_SEGMENT_64:
            section_count = struct.unpack_from("<I", data, cursor + 64)[0]
            if section_count > MAX_SECTIONS or 72 + section_count * MACH_SECTION_64.size > size:
                raise ValueError("Invalid Mach-O section population")
            for index in range(section_count):
                row = MACH_SECTION_64.unpack(
                    checked(data, cursor + 72 + index * MACH_SECTION_64.size, MACH_SECTION_64.size)
                )
                name = row[0].rstrip(b"\0").decode("ascii", errors="replace")
                checked(data, row[4], row[3])
                if row[7] > MAX_RELOCATIONS:
                    raise ValueError("Mach-O relocation limit reached")
                checked(data, row[6], row[7] * 8)
                sections.append(
                    NativeSection(
                        name, row[2], row[4], row[3], row[6], row[7], bool(row[8] & 0x80000000)
                    )
                )
        elif command == LC_SYMTAB:
            symtab = struct.unpack("<4I", checked(data, cursor + 8, 16))
        cursor += size
    if cursor != end or symtab is None:
        raise ValueError("Mach-O object has no canonical symbol table")
    return cpu, sections, symtab


def macho_patterns(data: bytes) -> tuple[list[FunctionPattern], str, int, str]:
    cpu, sections, (symbol_offset, symbol_count, string_offset, string_size) = _mach_sections(data)
    if symbol_count > MAX_SYMBOLS:
        raise ValueError("Mach-O symbol limit reached")
    checked(data, symbol_offset, symbol_count * MACH_NLIST_64.size)
    strings = checked(data, string_offset, string_size)
    symbols = []
    for index in range(symbol_count):
        name_offset, kind, section_number, _, address = MACH_NLIST_64.unpack(
            checked(data, symbol_offset + index * MACH_NLIST_64.size, MACH_NLIST_64.size)
        )
        if kind & 0x0E != 0x0E or not 0 < section_number <= len(sections):
            continue
        name = normalized_name(c_string(strings, name_offset, len(strings)))
        if is_patch_name(name):
            symbols.append(NativeSymbol(name, section_number - 1, address, 0))
    patterns = _patterns(data, sections, symbols, "mach_o", cpu)
    elf_machine, _bits = MACH_CPUS[cpu]
    return patterns, "mach_o", elf_machine, "darwin"


def _patterns(
    data: bytes,
    sections: list[NativeSection],
    symbols: list[NativeSymbol],
    format_name: str,
    machine: int,
) -> list[FunctionPattern]:
    patterns = []
    for section_index, section in enumerate(sections):
        rows = sorted(
            (item for item in symbols if item.section == section_index),
            key=lambda item: item.address,
        )
        if not section.executable or not rows:
            continue
        section_code = checked(data, section.offset, section.size)
        section_mask = bytearray(b"\xff" * section.size)
        relocation_size = COFF_RELOCATION.size if format_name == "coff" else 8
        for index in range(section.relocation_count):
            relocation = checked(
                data,
                section.relocation_offset + index * relocation_size,
                relocation_size,
            )
            if format_name == "coff":
                address, _, kind = COFF_RELOCATION.unpack(relocation)
                width = COFF_RELOCATION_WIDTHS.get(machine, {}).get(kind)
                if width is None:
                    raise ValueError(f"Unsupported COFF executable relocation: {kind}")
            else:
                address = int.from_bytes(relocation[:4], "little", signed=True)
                info = int.from_bytes(relocation[4:], "little")
                if address < 0 or info >> 31:
                    raise ValueError("Unsupported scattered Mach-O relocation")
                width = 1 << ((info >> 25) & 3)
            mask_range(section_mask, address, width)
        for row_index, symbol in enumerate(rows):
            start = symbol.address - section.address
            inferred_end = (
                rows[row_index + 1].address - section.address
                if row_index + 1 < len(rows)
                else section.size
            )
            size = symbol.size or inferred_end - start
            if start < 0 or size <= 0 or start + size > section.size:
                raise ValueError("Native function is outside its executable section")
            pattern = FunctionPattern(
                symbol.name,
                COFF_MACHINES[machine][0] if format_name == "coff" else MACH_CPUS[machine][0],
                COFF_MACHINES[machine][1] if format_name == "coff" else MACH_CPUS[machine][1],
                "little",
                section_code[start : start + size],
                bytes(section_mask[start : start + size]),
            )
            if ELF_BUILDER["strong_pattern"](pattern):
                patterns.append(pattern)
    if not patterns:
        raise ValueError("Native object contains no strong patch-bearing function patterns")
    return patterns


def patch_population(patterns: list[FunctionPattern]) -> dict[str, list[str]]:
    result = {role: [] for role in PATCH_ROLE_PATTERNS}
    result["helpers"] = []
    for pattern in patterns:
        for role, expression in PATCH_ROLE_PATTERNS.items():
            if expression.fullmatch(pattern.name):
                result[role].append(pattern.name)
                break
        if PATCH_HELPER_PATTERN.fullmatch(pattern.name):
            result["helpers"].append(pattern.name)
    result = {role: sorted(set(names)) for role, names in result.items()}
    if not valid_patch_functions(result):
        missing = ", ".join(
            role for role, names in result.items() if role != "helpers" and not names
        )
        raise ValueError(f"Native object lacks required patch-bearing roles: {missing}")
    return result


def group_for_object(
    data: bytes,
    tree: Path,
    compiler: str,
    flags: str,
    build_note: str,
) -> tuple[list[FunctionPattern], dict]:
    if data.startswith((b"\x64\x86", b"\x4c\x01", b"\x64\xaa")):
        patterns, format_name, machine, abi = coff_patterns(data)
    else:
        patterns, format_name, machine, abi = macho_patterns(data)
    patterns, ambiguous = resolve_ambiguities(patterns)
    patterns = [item for item in patterns if item.signature_id not in ambiguous]
    roles = patch_population(patterns)
    names = {name for values in roles.values() for name in values}
    patterns = [item for item in patterns if item.name in names]
    source = tree / "c/dec/decode.c"
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    sources = ELF_BUILDER["reviewed_sources"]()
    if source_sha256 not in sources:
        raise ValueError(f"Unreviewed decoder source: {source_sha256}")
    functions = {
        name: sorted(item.signature_id for item in patterns if item.name == name)
        for name in sorted(names)
    }
    seed = json.dumps(
        {
            "format": format_name,
            "machine": machine,
            "compiler": compiler,
            "flags": flags,
            "source_sha256": source_sha256,
            "object_sha256": hashlib.sha256(data).hexdigest(),
        },
        sort_keys=True,
    ).encode()
    group = {
        "id": "brotli_native_" + hashlib.sha256(seed).hexdigest()[:32],
        "format": format_name,
        "abi": abi,
        "machine": machine,
        "elf_class": patterns[0].elf_class,
        "byteorder": "little",
        "source_sha256": source_sha256,
        "object_sha256": hashlib.sha256(data).hexdigest(),
        "headers_sha256": ELF_BUILDER["header_digest"](tree),
        "source": sources[source_sha256]["sources"][0]["url"],
        "source_state": sources[source_sha256]["state"],
        "compiler": compiler,
        "flags": flags,
        "build_note": build_note,
        "evidence_scope": "patch_bearing_population_v1",
        "patch_functions": roles,
        "functions": functions,
    }
    return patterns, group


def read_object(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_OBJECT_BYTES + 1)
    if len(data) > MAX_OBJECT_BYTES:
        raise ValueError("Native object exceeds byte limit")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--object", required=True, type=Path)
    parser.add_argument("--source-tree", required=True, type=Path)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--flags", required=True)
    parser.add_argument("--build-note", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--pat-output", required=True, type=Path)
    args = parser.parse_args()
    try:
        data = read_object(args.object)
        patterns, group = group_for_object(
            data, args.source_tree.resolve(), args.compiler, args.flags, args.build_note
        )
        ELF_BUILDER["write_catalog"](args.output, args.pat_output, render_pat(patterns), [group])
    except (OSError, UnicodeDecodeError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
