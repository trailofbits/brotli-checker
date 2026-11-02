#!/usr/bin/env python3
# ruff: noqa: C901, EM101, EM102, PERF401, PLR0915, PLR2004, TRY003, TRY301
"""Build native FLIRT references from objects or verified post-link debug bounds."""

from __future__ import annotations

import argparse
import hashlib
import json
import runpy
import struct
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))
from brotli_binary_data import Buffer, file_data, sha256_data  # noqa: E402
from brotli_binary_layout import inspect_layout  # noqa: E402
from brotli_binary_match import (  # noqa: E402
    EM_386,
    EM_AARCH64,
    EM_X86_64,
    PATCH_HELPER_PATTERN,
    PATCH_ROLE_PATTERNS,
    valid_patch_functions,
)
from brotli_debug_companions import (  # noqa: E402
    FunctionHint,
    verify_mach_debug_export,
    verify_pdb_symbol_export,
)

ELF_BUILDER = runpy.run_path(str(ROOT / "scripts/build_flirt_references.py"))
FunctionPattern = ELF_BUILDER["FunctionPattern"]
resolve_ambiguities = ELF_BUILDER["resolve_ambiguities"]
render_pat = ELF_BUILDER["render_pat"]
strong_pattern = ELF_BUILDER["strong_pattern"]
write_catalog = ELF_BUILDER["write_catalog"]
MAX_OBJECT_BYTES = 512 * 1024 * 1024
MAX_SYMBOL_EVIDENCE_BYTES = 64 * 1024 * 1024
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


@dataclass(frozen=True)
class PostlinkFunction:
    name: str
    virtual_address: int
    file_offset: int
    size: int


def checked(data: Buffer, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        msg = "Native object range is outside the supplied bytes"
        raise ValueError(msg)
    return bytes(data[offset : offset + size])


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


def _postlink_patterns(
    data: Buffer,
    functions: tuple[FunctionHint, ...],
    machine: int,
    bits: int,
) -> tuple[list[FunctionPattern], dict[str, int]]:
    selected = []
    for function in functions:
        if (
            isinstance(function.name, str)
            and type(function.virtual_address) is int
            and type(function.file_offset) is int
            and type(function.size) is int
            and is_patch_name(function.name)
        ):
            selected.append(
                PostlinkFunction(
                    function.name,
                    function.virtual_address,
                    function.file_offset,
                    function.size,
                )
            )
    selected.sort(key=lambda function: (function.virtual_address, function.size, function.name))
    if not selected or len({function.name for function in selected}) != len(selected):
        raise ValueError("Post-link symbol evidence has missing or duplicate patch functions")
    previous_end = -1
    for function in selected:
        if function.virtual_address < previous_end:
            raise ValueError("Post-link patch functions overlap or alias after optimization")
        previous_end = function.virtual_address + function.size
    anchor = selected[0].virtual_address
    patterns = []
    offsets = {}
    for function in selected:
        code = bytes(checked(data, function.file_offset, function.size))
        pattern = FunctionPattern(
            function.name,
            machine,
            bits,
            "little",
            code,
            b"\xff" * len(code),
        )
        if strong_pattern(pattern):
            patterns.append(pattern)
            offsets[function.name] = function.virtual_address - anchor
    patterns, ambiguous = resolve_ambiguities(patterns)
    if ambiguous:
        raise ValueError("Post-link patch functions have name-ambiguous code patterns")
    roles = patch_population(patterns)
    names = {name for values in roles.values() for name in values}
    patterns = [pattern for pattern in patterns if pattern.name in names]
    offsets = {name: offsets[name] for name in sorted(names)}
    if min(offsets.values()) != 0:
        raise ValueError("Post-link profile lost its component anchor function")
    return patterns, offsets


def postlink_patterns(
    data: Buffer, functions: tuple[FunctionHint, ...]
) -> tuple[list[FunctionPattern], dict[str, int], str, int, str]:
    """Extract exact PE linked-code patterns from independently verified PDB bounds."""
    layout = inspect_layout(data)
    if layout["kind"] != "pe" or layout["gaps"] or layout["slices"]:
        raise ValueError("Post-link PDB profiles require one complete PE image")
    machine_name = layout["machine"]
    machine = {"i386": EM_386, "x86_64": EM_X86_64, "aarch64": EM_AARCH64}.get(machine_name)
    if machine is None or layout["bits"] not in (32, 64) or layout["byteorder"] != "little":
        raise ValueError("Unsupported post-link PE identity")
    patterns, offsets = _postlink_patterns(data, functions, machine, layout["bits"])
    return patterns, offsets, "pe", machine, "windows"


def postlink_mach_patterns(
    data: Buffer, functions: tuple[FunctionHint, ...], slice_uuid: str
) -> tuple[list[FunctionPattern], dict[str, int], str, int, str]:
    """Extract exact per-slice linked-code patterns from verified dSYM bounds."""
    layout = inspect_layout(data)
    rows = layout["slices"] or [layout]
    owners = [
        row
        for row in rows
        if any(
            identity.get("kind") == "mach_uuid" and identity.get("uuid") == slice_uuid
            for identity in row.get("debug_identities", [])
        )
    ]
    if len(owners) != 1 or owners[0]["gaps"]:
        raise ValueError("Post-link dSYM profile lacks one complete Mach slice owner")
    owner = owners[0]
    machine = {"x86_64": EM_X86_64, "aarch64": EM_AARCH64}.get(owner["machine"])
    if machine is None or owner["bits"] != 64 or owner["byteorder"] != "little":
        raise ValueError("Unsupported post-link Mach identity")
    patterns, offsets = _postlink_patterns(data, functions, machine, owner["bits"])
    return patterns, offsets, "mach_o", machine, "darwin"


def _postlink_group(  # noqa: PLR0913, PLR0917
    patterns: list[FunctionPattern],
    offsets: dict[str, int],
    format_name: str,
    machine: int,
    abi: str,
    binary: Buffer,
    symbol_evidence: bytes,
    symbol_evidence_format: str,
    object_data: bytes,
    tree: Path,
    compiler: str,
    flags: str,
    build_note: str,
    transformation: str,
) -> tuple[list[FunctionPattern], dict]:
    roles = patch_population(patterns)
    names = {name for values in roles.values() for name in values}
    functions = {
        name: sorted(pattern.signature_id for pattern in patterns if pattern.name == name)
        for name in sorted(names)
    }
    source = tree / "c/dec/decode.c"
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    sources = ELF_BUILDER["reviewed_sources"]()
    if source_sha256 not in sources:
        raise ValueError(f"Unreviewed decoder source: {source_sha256}")
    linked_sha256 = sha256_data(binary)
    symbol_sha256 = hashlib.sha256(symbol_evidence).hexdigest()
    seed = json.dumps(
        {
            "format": format_name,
            "machine": machine,
            "compiler": compiler,
            "flags": flags,
            "source_sha256": source_sha256,
            "linked_artifact_sha256": linked_sha256,
            "symbol_evidence_sha256": symbol_sha256,
            "transformation": transformation,
        },
        sort_keys=True,
    ).encode()
    group = {
        "id": "brotli_postlink_" + hashlib.sha256(seed).hexdigest()[:32],
        "format": format_name,
        "abi": abi,
        "machine": machine,
        "elf_class": patterns[0].elf_class,
        "byteorder": "little",
        "source_sha256": source_sha256,
        "object_sha256": hashlib.sha256(object_data).hexdigest(),
        "headers_sha256": ELF_BUILDER["header_digest"](tree),
        "source": sources[source_sha256]["sources"][0]["url"],
        "source_state": sources[source_sha256]["state"],
        "compiler": compiler,
        "flags": flags,
        "build_note": build_note,
        "evidence_scope": "postlink_patch_component_v1",
        "patch_functions": roles,
        "component_offsets": offsets,
        "linked_artifact_sha256": linked_sha256,
        "symbol_evidence_sha256": symbol_sha256,
        "symbol_evidence_format": symbol_evidence_format,
        "transformation": transformation,
        "functions": functions,
    }
    return patterns, group


def group_for_postlink_pe(  # noqa: PLR0913, PLR0917
    binary: Buffer,
    pdb: Buffer,
    symbol_evidence: bytes,
    object_data: bytes,
    tree: Path,
    compiler: str,
    flags: str,
    build_note: str,
    transformation: str,
) -> tuple[list[FunctionPattern], dict]:
    verified = verify_pdb_symbol_export(binary, pdb, symbol_evidence)
    if verified.status != "verified":
        reason = verified.gaps[0].reason if verified.gaps else "unresolved PDB symbol evidence"
        raise ValueError(reason)
    patterns, offsets, format_name, machine, abi = postlink_patterns(
        binary, verified.function_hints
    )
    return _postlink_group(
        patterns,
        offsets,
        format_name,
        machine,
        abi,
        binary,
        symbol_evidence,
        "llvm-pdbutil-symbols-v1",
        object_data,
        tree,
        compiler,
        flags,
        build_note,
        transformation,
    )


def group_for_postlink_mach(  # noqa: PLR0913, PLR0917
    binary: Buffer,
    dsym: Buffer,
    symbol_evidence: bytes,
    object_data: bytes,
    tree: Path,
    compiler: str,
    flags: str,
    build_note: str,
    transformation: str,
) -> tuple[list[FunctionPattern], dict]:
    verified = verify_mach_debug_export(binary, dsym, symbol_evidence)
    if verified.status != "verified" or verified.slice_uuid is None:
        reason = verified.gaps[0].reason if verified.gaps else "unresolved dSYM symbol evidence"
        raise ValueError(reason)
    patterns, offsets, format_name, machine, abi = postlink_mach_patterns(
        binary, verified.function_hints, verified.slice_uuid
    )
    return _postlink_group(
        patterns,
        offsets,
        format_name,
        machine,
        abi,
        binary,
        symbol_evidence,
        "llvm-dwarfdump-symbols-v1",
        object_data,
        tree,
        compiler,
        flags,
        build_note,
        transformation,
    )


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


def read_bounded(path: Path, limit: int, label: str) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{label} exceeds byte limit")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--object", required=True, type=Path)
    parser.add_argument("--linked-binary", type=Path)
    parser.add_argument("--pdb", type=Path)
    parser.add_argument("--pdb-symbol-export", type=Path)
    parser.add_argument("--dsym", type=Path)
    parser.add_argument("--mach-symbol-export", action="append", default=[], type=Path)
    parser.add_argument("--transformation")
    parser.add_argument("--source-tree", required=True, type=Path)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--flags", required=True)
    parser.add_argument("--build-note", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--pat-output", required=True, type=Path)
    args = parser.parse_args()
    try:
        object_data = read_object(args.object)
        windows_postlink = args.pdb is not None or args.pdb_symbol_export is not None
        mach_postlink = args.dsym is not None or bool(args.mach_symbol_export)
        if windows_postlink and mach_postlink:
            raise ValueError("Choose PDB or dSYM post-link evidence, not both")
        if windows_postlink and (
            args.linked_binary is None
            or args.pdb is None
            or args.pdb_symbol_export is None
            or args.transformation is None
        ):
            raise ValueError(
                "Post-link profiles require --linked-binary, --pdb, "
                "--pdb-symbol-export, and --transformation"
            )
        if mach_postlink and (
            args.linked_binary is None
            or args.dsym is None
            or not args.mach_symbol_export
            or args.transformation is None
        ):
            raise ValueError(
                "Mach post-link profiles require --linked-binary, --dsym, "
                "--mach-symbol-export, and --transformation"
            )
        if args.linked_binary is None:
            patterns, group = group_for_object(
                object_data,
                args.source_tree.resolve(),
                args.compiler,
                args.flags,
                args.build_note,
            )
            groups = [group]
        elif windows_postlink:
            with ExitStack() as stack:
                linked_stream = stack.enter_context(args.linked_binary.open("rb"))
                pdb_stream = stack.enter_context(args.pdb.open("rb"))
                linked_data = stack.enter_context(file_data(linked_stream, None))
                pdb_data = stack.enter_context(file_data(pdb_stream, None))
                patterns, group = group_for_postlink_pe(
                    linked_data,
                    pdb_data,
                    read_bounded(
                        args.pdb_symbol_export,
                        MAX_SYMBOL_EVIDENCE_BYTES,
                        "PDB symbol evidence",
                    ),
                    object_data,
                    args.source_tree.resolve(),
                    args.compiler,
                    args.flags,
                    args.build_note,
                    args.transformation,
                )
                groups = [group]
        elif mach_postlink:
            with ExitStack() as stack:
                linked_stream = stack.enter_context(args.linked_binary.open("rb"))
                dsym_stream = stack.enter_context(args.dsym.open("rb"))
                linked_data = stack.enter_context(file_data(linked_stream, None))
                dsym_data = stack.enter_context(file_data(dsym_stream, None))
                patterns = []
                groups = []
                for packet in args.mach_symbol_export:
                    built_patterns, group = group_for_postlink_mach(
                        linked_data,
                        dsym_data,
                        read_bounded(
                            packet,
                            MAX_SYMBOL_EVIDENCE_BYTES,
                            "Mach debug symbol evidence",
                        ),
                        object_data,
                        args.source_tree.resolve(),
                        args.compiler,
                        args.flags,
                        args.build_note,
                        args.transformation,
                    )
                    patterns.extend(built_patterns)
                    groups.append(group)
        else:
            raise ValueError("--linked-binary requires PDB or dSYM symbol evidence")
        ELF_BUILDER["write_catalog"](args.output, args.pat_output, render_pat(patterns), groups)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
