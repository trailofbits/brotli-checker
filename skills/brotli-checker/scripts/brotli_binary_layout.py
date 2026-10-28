# ruff: noqa: ANN401, C901, EM101, EM102, PLR0912, PLR0913, PLR0915, PLR0917, PLR2004, TRY003, TRY300
"""Bounded, read-only PE, Mach-O, and WebAssembly layout evidence.

All reported file offsets refer to the original supplied artifact. Parsing never
loads or executes a target and never resolves embedded paths or dependencies.
"""

from __future__ import annotations

import struct
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from brotli_binary_data import Buffer

MAX_SECTIONS = 4096
MAX_ITEMS = 100_000
MAX_NAME_BYTES = 4096
MAX_LOAD_COMMAND_BYTES = 64 * 1024 * 1024
MAX_WASM_BODY_BYTES = 64 * 1024 * 1024
MAX_WASM_TOTAL_CODE_BYTES = 256 * 1024 * 1024
MAX_EXPORT_TRIE_NODES = 100_000
MAX_MACH_SLICES = 256
MAX_GAPS = 256
WASM_NO_IMMEDIATE = frozenset((0x00, 0x01, 0x05, 0x0F, 0x1A, 0x1B, 0xD1, 0xD3)) | frozenset(
    range(0x45, 0xC5)
)

PE_MACHINES = {
    0x014C: "i386",
    0x01C0: "arm",
    0x01C4: "armv7",
    0x5032: "riscv32",
    0x5064: "riscv64",
    0x5128: "riscv128",
    0x6264: "loongarch64",
    0x8664: "x86_64",
    0xA641: "arm64ec",
    0xAA64: "aarch64",
    0xA64E: "arm64x",
}
MACH_CPUS = {
    7: "i386",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "aarch64",
    18: "ppc",
    0x01000012: "ppc64",
}


def _layout(kind: str = "unknown") -> dict[str, Any]:
    return {
        "kind": kind,
        "machine": "unknown",
        "abi": "unknown",
        "bits": None,
        "byteorder": "unknown",
        "ranges": {
            "mapped": [],
            "executable": [],
            "data": [],
            "resources": [],
            "code": [],
            "relocations": [],
        },
        "imports": [],
        "exports": [],
        "functions": [],
        "dependencies": [],
        "debug_identities": [],
        "gaps": [],
        "slices": [],
    }


def _gap(result: dict[str, Any], reason: str) -> None:
    if len(result["gaps"]) < MAX_GAPS:
        result["gaps"].append(reason)
    elif result["gaps"][-1] != "Layout gap reporting limit reached":
        result["gaps"][-1] = "Layout gap reporting limit reached"


def _validate_range(data: Buffer, offset: int, size: int, end: int | None = None) -> None:
    limit = len(data) if end is None else min(end, len(data))
    if offset < 0 or size < 0 or offset > limit or size > limit - offset:
        msg = "binary range outside artifact or containing slice"
        raise ValueError(msg)


def _checked(data: Buffer, offset: int, size: int, end: int | None = None) -> bytes:
    _validate_range(data, offset, size, end)
    return data[offset : offset + size]


def _cstring(data: Buffer, offset: int, end: int) -> str:
    if offset < 0 or offset >= end:
        msg = "string offset outside bounded region"
        raise ValueError(msg)
    stop = data.find(b"\0", offset, min(end, offset + MAX_NAME_BYTES + 1))
    if stop < 0 or stop - offset > MAX_NAME_BYTES:
        msg = "unterminated or overlong binary name"
        raise ValueError(msg)
    return _checked(data, offset, stop - offset, end).decode("utf-8", "replace")


def _range(offset: int, size: int, **fields: Any) -> dict[str, Any]:
    return {"file_offset": offset, "size": size, **fields}


def inspect_layout(data: Buffer) -> dict[str, Any]:
    """Return conservative static layout evidence for one recognized artifact."""
    if data.startswith(b"MZ"):
        result = _layout("pe")
        try:
            _inspect_pe(data, result)
        except (ValueError, struct.error, UnicodeError, RecursionError) as error:
            _gap(result, f"Malformed or unsupported PE: {error}")
        return result
    if data.startswith(
        (
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
            b"\xbf\xba\xfe\xca",
        )
    ):
        try:
            return _inspect_mach(data)
        except (ValueError, struct.error, UnicodeError, RecursionError) as error:
            result = _layout("mach_o")
            _gap(result, f"Malformed or unsupported Mach-O: {error}")
            return result
    if data.startswith(b"\0asm"):
        result = _layout("wasm")
        try:
            _inspect_wasm(data, result)
        except (ValueError, struct.error, UnicodeError, RecursionError) as error:
            _gap(result, f"Malformed or unsupported WebAssembly: {error}")
        return result
    return _layout()


def _pe_rva(sections: list[dict[str, Any]], rva: int, size: int = 1) -> int:
    for section in sections:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"])
        if start <= rva and rva - start <= span and size <= span - (rva - start):
            delta = rva - start
            if delta > section["raw_size"] or size > section["raw_size"] - delta:
                break
            return section["file_offset"] + delta
    msg = f"PE RVA 0x{rva:x} is not backed by section file bytes"
    raise ValueError(msg)


def _pe_string(data: Buffer, sections: list[dict[str, Any]], rva: int) -> str:
    offset = _pe_rva(sections, rva)
    section = next(
        item
        for item in sections
        if item["file_offset"] <= offset < item["file_offset"] + item["raw_size"]
    )
    return _cstring(data, offset, section["file_offset"] + section["raw_size"])


def _pe_directory(directories: list[tuple[int, int]], index: int) -> tuple[int, int]:
    if index >= len(directories) or not directories[index][0] or not directories[index][1]:
        return 0, 0
    return directories[index]


def _inspect_pe(data: Buffer, result: dict[str, Any]) -> None:
    if len(data) < 0x40:
        raise ValueError("truncated DOS header")
    pe = int.from_bytes(_checked(data, 0x3C, 4), "little")
    if _checked(data, pe, 4) != b"PE\0\0":
        raise ValueError("missing PE signature")
    machine, section_count, _, _, _, optional_size, characteristics = struct.unpack(
        "<HHIIIHH", _checked(data, pe + 4, 20)
    )
    if not 0 < section_count <= MAX_SECTIONS:
        raise ValueError("invalid PE section count")
    optional = pe + 24
    magic = int.from_bytes(_checked(data, optional, 2), "little")
    if magic == 0x10B:
        bits, directory_count_offset, directory_offset, thunk_size = 32, 92, 96, 4
    elif magic == 0x20B:
        bits, directory_count_offset, directory_offset, thunk_size = 64, 108, 112, 8
    else:
        raise ValueError("unsupported PE optional-header magic")
    if optional_size < directory_offset:
        raise ValueError("truncated PE optional header")
    optional_end = optional + optional_size
    _validate_range(data, optional, optional_size)
    size_of_headers = int.from_bytes(_checked(data, optional + 60, 4, optional_end), "little")
    if size_of_headers > len(data):
        raise ValueError("PE declared headers extend beyond file")
    directory_count = min(
        16, int.from_bytes(_checked(data, optional + directory_count_offset, 4), "little")
    )
    directories = [
        struct.unpack("<II", _checked(data, optional + directory_offset + index * 8, 8))
        for index in range(directory_count)
        if optional + directory_offset + (index + 1) * 8 <= optional_end
    ]
    result.update(
        machine=PE_MACHINES.get(machine, f"pe_machine_0x{machine:04x}"),
        abi="windows-pe",
        bits=bits,
        byteorder="little",
    )
    section_table = optional_end
    sections = []
    raw_ranges: list[tuple[int, int]] = []
    resource_rva, resource_size = _pe_directory(directories, 2)
    for index in range(section_count):
        row = _checked(data, section_table + index * 40, 40)
        name = row[:8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", row, 8)
        flags = struct.unpack_from("<I", row, 36)[0]
        if raw_size:
            _validate_range(data, raw_offset, raw_size)
            if raw_offset < size_of_headers:
                raise ValueError("PE raw section overlaps mapped headers")
            if any(
                raw_offset < other_end and other_start < raw_offset + raw_size
                for other_start, other_end in raw_ranges
            ):
                raise ValueError("overlapping PE raw section ranges")
            raw_ranges.append((raw_offset, raw_offset + raw_size))
        section = {
            "name": name,
            "virtual_address": virtual_address,
            "virtual_size": virtual_size,
            "file_offset": raw_offset,
            "raw_size": raw_size,
            "flags": flags,
        }
        sections.append(section)
        if not raw_size:
            continue
        item = _range(raw_offset, raw_size, name=name, rva=virtual_address)
        result["ranges"]["mapped"].append(item)
        is_resource = name == ".rsrc" or (
            resource_rva
            and virtual_address <= resource_rva < virtual_address + max(virtual_size, raw_size)
        )
        if is_resource:
            result["ranges"]["resources"].append(item)
        elif flags & 0x20000000:
            result["ranges"]["executable"].append(item)
        elif flags & 0x00000040:
            result["ranges"]["data"].append(item)
    if resource_rva and resource_size:
        _pe_rva(sections, resource_rva, resource_size)
    # File certificates are deliberately not mapped evidence.
    certificate_offset, certificate_size = _pe_directory(directories, 4)
    if certificate_offset and certificate_size:
        _validate_range(data, certificate_offset, certificate_size)
    reloc_rva, reloc_size = _pe_directory(directories, 5)
    if reloc_rva and reloc_size:
        _pe_relocations(data, result, sections, reloc_rva, reloc_size)
    delay_rva, delay_size = _pe_directory(directories, 13)
    if delay_rva and delay_size:
        _gap(result, "PE delay-import descriptors are not decoded")
    _pe_imports(data, result, sections, directories, thunk_size)
    _pe_exports(data, result, sections, directories)
    _pe_functions(data, result, sections, directories)
    _pe_debug(data, result, sections, directories)
    if not characteristics & 0x0002:
        _gap(result, "PE is not marked executable; mapped-use evidence is limited")


def _pe_relocations(
    data: Buffer,
    result: dict[str, Any],
    sections: list[dict[str, Any]],
    rva: int,
    size: int,
) -> None:
    offset = _pe_rva(sections, rva, size)
    cursor, end = offset, offset + size
    entry_count = 0
    types: dict[int, int] = {}
    while cursor < end:
        page_rva, block_size = struct.unpack("<II", _checked(data, cursor, 8, end))
        if block_size < 8 or block_size & 1 or block_size > end - cursor:
            raise ValueError("invalid PE base-relocation block")
        entries = (block_size - 8) // 2
        entry_count += entries
        if entry_count > MAX_ITEMS:
            raise ValueError("PE base-relocation entry limit reached")
        for index in range(entries):
            value = int.from_bytes(_checked(data, cursor + 8 + index * 2, 2, end), "little")
            kind, page_offset = value >> 12, value & 0x0FFF
            if kind:
                types[kind] = types.get(kind, 0) + 1
                if page_rva + page_offset >= 1 << 32:
                    raise ValueError("PE base-relocation RVA overflow")
        cursor += block_size
    result["ranges"]["relocations"].append(
        _range(offset, size, rva=rva, entry_count=entry_count, types=types)
    )


def _pe_imports(
    data: Buffer,
    result: dict[str, Any],
    sections: list[dict[str, Any]],
    directories: list[tuple[int, int]],
    thunk_size: int,
) -> None:
    rva, size = _pe_directory(directories, 1)
    if not rva or not size:
        return
    offset = _pe_rva(sections, rva, size)
    end = offset + size
    for descriptor in range(min(size // 20, MAX_ITEMS)):
        row = struct.unpack("<IIIII", _checked(data, offset + descriptor * 20, 20, end))
        if row == (0, 0, 0, 0, 0):
            return
        lookup_rva, _, _, name_rva, address_rva = row
        dependency = _pe_string(data, sections, name_rva)
        if dependency not in result["dependencies"]:
            result["dependencies"].append(dependency)
        thunk_rva = lookup_rva or address_rva
        thunk = _pe_rva(sections, thunk_rva, thunk_size)
        ordinal_bit = 1 << (thunk_size * 8 - 1)
        remaining = MAX_ITEMS - len(result["imports"])
        if remaining <= 0:
            raise ValueError("PE aggregate import count exceeds limit")
        for index in range(remaining):
            value = int.from_bytes(_checked(data, thunk + index * thunk_size, thunk_size), "little")
            if not value:
                break
            item: dict[str, Any] = {
                "library": dependency,
                "thunk_rva": thunk_rva + index * thunk_size,
            }
            if value & ordinal_bit:
                item["ordinal"] = value & 0xFFFF
            else:
                item["name"] = _pe_string(data, sections, value + 2)
            result["imports"].append(item)
        else:
            raise ValueError("PE import thunk count exceeds limit")
    raise ValueError("PE import descriptor lacks terminator within directory")


def _pe_exports(
    data: Buffer,
    result: dict[str, Any],
    sections: list[dict[str, Any]],
    directories: list[tuple[int, int]],
) -> None:
    rva, size = _pe_directory(directories, 0)
    if not rva:
        return
    if size < 40:
        raise ValueError("truncated PE export directory")
    offset = _pe_rva(sections, rva, 40)
    row = struct.unpack("<IIHHIIIIIII", _checked(data, offset, 40))
    base, function_count, name_count, functions_rva, names_rva, ordinals_rva = row[5:]
    if function_count > MAX_ITEMS or name_count > MAX_ITEMS:
        raise ValueError("PE export count exceeds limit")
    functions = _pe_rva(sections, functions_rva, function_count * 4)
    names = _pe_rva(sections, names_rva, name_count * 4)
    ordinals = _pe_rva(sections, ordinals_rva, name_count * 2)
    for index in range(name_count):
        ordinal_index = int.from_bytes(_checked(data, ordinals + index * 2, 2), "little")
        if ordinal_index >= function_count:
            raise ValueError("PE export ordinal outside function table")
        symbol_rva = int.from_bytes(_checked(data, functions + ordinal_index * 4, 4), "little")
        name_rva = int.from_bytes(_checked(data, names + index * 4, 4), "little")
        item = {
            "name": _pe_string(data, sections, name_rva),
            "ordinal": base + ordinal_index,
            "rva": symbol_rva,
        }
        if rva <= symbol_rva < rva + size:
            item["forwarder"] = _pe_string(data, sections, symbol_rva)
        else:
            with suppress(ValueError):
                item["file_offset"] = _pe_rva(sections, symbol_rva)
        result["exports"].append(item)


def _pe_functions(
    data: Buffer,
    result: dict[str, Any],
    sections: list[dict[str, Any]],
    directories: list[tuple[int, int]],
) -> None:
    rva, size = _pe_directory(directories, 3)
    if not rva or not size:
        return
    if size % 12 or size // 12 > MAX_ITEMS:
        raise ValueError("unsupported PE exception/function table")
    offset = _pe_rva(sections, rva, size)
    for index in range(size // 12):
        start, stop, unwind = struct.unpack("<III", _checked(data, offset + index * 12, 12))
        if stop <= start:
            raise ValueError("invalid PE runtime-function range")
        result["functions"].append(
            {
                "index": index,
                "rva": start,
                "file_offset": _pe_rva(sections, start, stop - start),
                "size": stop - start,
                "unwind_rva": unwind,
                "source": "exception_directory",
            }
        )


def _pe_debug(
    data: Buffer,
    result: dict[str, Any],
    sections: list[dict[str, Any]],
    directories: list[tuple[int, int]],
) -> None:
    rva, size = _pe_directory(directories, 6)
    if not rva or not size:
        return
    if size % 28 or size // 28 > MAX_ITEMS:
        raise ValueError("invalid PE debug-directory size")
    offset = _pe_rva(sections, rva, size)
    for index in range(size // 28):
        row = struct.unpack("<IIHHIIII", _checked(data, offset + index * 28, 28))
        kind, payload_size, payload_rva, payload_offset = row[4:]
        if kind != 2 or payload_size < 24:
            continue
        if not payload_offset:
            payload_offset = _pe_rva(sections, payload_rva, payload_size)
        _validate_range(data, payload_offset, payload_size)
        payload = _checked(data, payload_offset, min(payload_size, 24 + MAX_NAME_BYTES + 1))
        if payload[:4] == b"RSDS":
            path_bytes = payload[24:]
            terminator = path_bytes.find(b"\0")
            if terminator < 0:
                raise ValueError("PE RSDS path is unterminated or exceeds limit")
            path = path_bytes[:terminator].decode("utf-8", "replace")
            result["debug_identities"].append(
                {
                    "kind": "pdb_rsds",
                    "guid": payload[4:20].hex(),
                    "age": int.from_bytes(payload[20:24], "little"),
                    "embedded_path": path,
                    "path_followed": False,
                }
            )


def _inspect_mach(data: Buffer) -> dict[str, Any]:
    magic = _checked(data, 0, 4)
    if magic in (
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    ):
        return _inspect_mach_fat(data, magic)
    result = _layout("mach_o")
    _inspect_mach_thin(data, result, 0, len(data))
    return result


def _inspect_mach_fat(data: Buffer, magic: bytes) -> dict[str, Any]:
    result = _layout("mach_o_universal")
    result.update(machine="multiple", abi="darwin-universal", byteorder="big")
    byteorder = "big" if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") else "little"
    is_64 = magic in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
    count = int.from_bytes(_checked(data, 4, 4), byteorder)
    if not 0 < count <= MAX_MACH_SLICES:
        raise ValueError("invalid Mach universal slice count")
    row_size = 32 if is_64 else 20
    slices = []
    occupied = []
    for index in range(count):
        row = _checked(data, 8 + index * row_size, row_size)
        cpu = int.from_bytes(row[:4], byteorder)
        subtype = int.from_bytes(row[4:8], byteorder)
        width = 8 if is_64 else 4
        offset = int.from_bytes(row[8 : 8 + width], byteorder)
        size = int.from_bytes(row[8 + width : 8 + width * 2], byteorder)
        _validate_range(data, offset, size)
        if any(
            offset < other_end and other_start < offset + size
            for other_start, other_end in occupied
        ):
            raise ValueError("overlapping Mach universal slices")
        occupied.append((offset, offset + size))
        child = _layout("mach_o")
        _inspect_mach_thin(data, child, offset, offset + size)
        child.update(slice_offset=offset, slice_size=size, cpu_subtype=subtype)
        if child["machine"] == "unknown":
            child["machine"] = MACH_CPUS.get(cpu, f"mach_cpu_0x{cpu:x}")
        slices.append(child)
    result["slices"] = slices
    return result


def _mach_format(magic: bytes) -> tuple[Literal["little", "big"], int]:
    formats: dict[bytes, tuple[Literal["little", "big"], int]] = {
        b"\xce\xfa\xed\xfe": ("little", 32),
        b"\xfe\xed\xfa\xce": ("big", 32),
        b"\xcf\xfa\xed\xfe": ("little", 64),
        b"\xfe\xed\xfa\xcf": ("big", 64),
    }
    try:
        return formats[magic]
    except KeyError as error:
        raise ValueError("unsupported Mach slice magic") from error


def _inspect_mach_thin(data: Buffer, result: dict[str, Any], base: int, slice_end: int) -> None:
    byteorder, bits = _mach_format(_checked(data, base, 4, slice_end))
    prefix = "<" if byteorder == "little" else ">"
    header_size = 32 if bits == 64 else 28
    header = struct.unpack(
        prefix + ("8I" if bits == 64 else "7I"), _checked(data, base, header_size, slice_end)
    )
    _, cpu, subtype, filetype, command_count, command_bytes, flags = header[:7]
    if command_count > MAX_ITEMS or command_bytes > MAX_LOAD_COMMAND_BYTES:
        raise ValueError("Mach load-command limit exceeded")
    command_start = base + header_size
    command_end = command_start + command_bytes
    _validate_range(data, command_start, command_bytes, slice_end)
    result.update(
        machine=MACH_CPUS.get(cpu, f"mach_cpu_0x{cpu:x}"),
        abi="darwin-mach-o",
        bits=bits,
        byteorder=byteorder,
        cpu_subtype=subtype,
        filetype=filetype,
        flags=flags,
    )
    cursor = command_start
    segments = []
    symtab = None
    function_starts = None
    export_trie = None
    total_sections = 0
    segment_ranges: list[tuple[int, int]] = []
    section_ranges: list[tuple[int, int]] = []
    for _ in range(command_count):
        cmd, size = struct.unpack(prefix + "II", _checked(data, cursor, 8, command_end))
        if size < 8 or size > command_end - cursor:
            raise ValueError("invalid Mach load-command size")
        raw_cmd = cmd & 0x7FFFFFFF
        if raw_cmd in (1, 0x19):
            is_64 = raw_cmd == 0x19
            fmt = prefix + ("II16sQQQQIIII" if is_64 else "II16sIIIIIIII")
            values = struct.unpack(fmt, _checked(data, cursor, struct.calcsize(fmt), cursor + size))
            name = values[2].split(b"\0", 1)[0].decode("ascii", "replace")
            vmaddr, vmsize, fileoff, filesize, _maxprot, initprot, section_count = values[3:10]
            absolute = base + fileoff
            if filesize:
                _validate_range(data, absolute, filesize, slice_end)
                if any(
                    absolute < other_end and other_start < absolute + filesize
                    for other_start, other_end in segment_ranges
                ):
                    raise ValueError("overlapping Mach segment file ranges")
                segment_ranges.append((absolute, absolute + filesize))
            segment = {
                "name": name,
                "vmaddr": vmaddr,
                "vmsize": vmsize,
                "file_offset": absolute,
                "size": filesize,
                "initprot": initprot,
            }
            segments.append(segment)
            segment_item = None
            if filesize:
                segment_item = _range(absolute, filesize, name=name, vmaddr=vmaddr)
                result["ranges"]["mapped"].append(segment_item)
            section_size = 80 if is_64 else 68
            total_sections += section_count
            if total_sections > MAX_SECTIONS:
                raise ValueError("Mach section count exceeds limit")
            _validate_range(
                data, cursor + struct.calcsize(fmt), section_count * section_size, cursor + size
            )
            if not section_count and segment_item is not None:
                if initprot & 4:
                    result["ranges"]["executable"].append(segment_item)
                elif name != "__LINKEDIT":
                    result["ranges"]["data"].append(segment_item)
            section_cursor = cursor + struct.calcsize(fmt)
            for _ in range(section_count):
                section_raw = _checked(data, section_cursor, section_size, cursor + size)
                section_cursor += section_size
                if is_64:
                    section_values = struct.unpack(prefix + "16s16sQQIIIIIIII", section_raw)
                else:
                    section_values = struct.unpack(prefix + "16s16sIIIIIIIII", section_raw)
                section_name = section_values[0].split(b"\0", 1)[0].decode("ascii", "replace")
                section_segment = section_values[1].split(b"\0", 1)[0].decode("ascii", "replace")
                section_address, section_bytes, section_offset = section_values[2:5]
                section_flags = section_values[8]
                if section_flags & 0xFF in (1, 0x0C, 0x12) or not section_bytes:
                    continue
                if (
                    section_offset < fileoff
                    or section_offset - fileoff > filesize
                    or section_bytes > filesize - (section_offset - fileoff)
                ):
                    raise ValueError("Mach section file range is outside its segment")
                absolute_section = base + section_offset
                _validate_range(data, absolute_section, section_bytes, slice_end)
                if any(
                    absolute_section < other_end and other_start < absolute_section + section_bytes
                    for other_start, other_end in section_ranges
                ):
                    raise ValueError("overlapping Mach section file ranges")
                section_ranges.append((absolute_section, absolute_section + section_bytes))
                section_item = _range(
                    absolute_section,
                    section_bytes,
                    name=section_name,
                    segment=section_segment,
                    vmaddr=section_address,
                )
                if section_flags & (0x80000000 | 0x00000400):
                    result["ranges"]["executable"].append(section_item)
                else:
                    result["ranges"]["data"].append(section_item)
        elif raw_cmd in (0xC, 0x18, 0x1F, 0x20, 0x23):
            name_offset = int.from_bytes(_checked(data, cursor + 8, 4, cursor + size), byteorder)
            dependency = _cstring(data, cursor + name_offset, cursor + size)
            result["dependencies"].append(dependency)
        elif raw_cmd == 0x1B:
            result["debug_identities"].append(
                {"kind": "mach_uuid", "uuid": _checked(data, cursor + 8, 16, cursor + size).hex()}
            )
        elif raw_cmd == 2:
            symtab = struct.unpack(prefix + "IIII", _checked(data, cursor + 8, 16, cursor + size))
        elif raw_cmd == 0x26:
            function_starts = struct.unpack(
                prefix + "II", _checked(data, cursor + 8, 8, cursor + size)
            )
        elif raw_cmd == 0x33:
            export_trie = struct.unpack(prefix + "II", _checked(data, cursor + 8, 8, cursor + size))
        elif raw_cmd == 0x22 and size >= 48:
            export_trie = struct.unpack(
                prefix + "II", _checked(data, cursor + 40, 8, cursor + size)
            )
        elif raw_cmd == 0x34:
            _gap(result, "Mach chained fixups are not decoded")
        elif raw_cmd in (0x21, 0x2C):
            cryptid_offset = 16 if raw_cmd == 0x21 else 20
            cryptid = int.from_bytes(
                _checked(data, cursor + cryptid_offset, 4, cursor + size), byteorder
            )
            if cryptid:
                _gap(result, "Mach encrypted ranges cannot be statically inspected")
        cursor += size
    if cursor != command_end:
        raise ValueError("Mach load commands do not fill declared region")
    if symtab is not None:
        _mach_symbols(data, result, base, slice_end, prefix, bits, symtab, segments)
    if export_trie is not None:
        _mach_export_trie(data, result, base, slice_end, export_trie, segments)
    if function_starts is not None:
        _mach_functions(data, result, base, slice_end, function_starts, segments)
    if result["machine"] == "aarch64" and subtype & 0xFFFFFF == 2:
        _gap(result, "Mach arm64e fixups and pointer authentication are unsupported")


def _mach_vm_to_file(segments: list[dict[str, Any]], address: int) -> int:
    for segment in segments:
        if segment["vmaddr"] <= address < segment["vmaddr"] + segment["size"]:
            return segment["file_offset"] + address - segment["vmaddr"]
    raise ValueError("Mach virtual address is not file-backed")


def _mach_symbols(
    data: Buffer,
    result: dict[str, Any],
    base: int,
    slice_end: int,
    prefix: str,
    bits: int,
    symtab: tuple[int, int, int, int],
    segments: list[dict[str, Any]],
) -> None:
    symbol_offset, symbol_count, string_offset, string_size = symtab
    if symbol_count > MAX_ITEMS or string_size > MAX_LOAD_COMMAND_BYTES:
        raise ValueError("Mach symbol/string table limit exceeded")
    symbol_offset += base
    string_offset += base
    _validate_range(data, string_offset, string_size, slice_end)
    parser = struct.Struct(prefix + ("IBBHQ" if bits == 64 else "IBBHI"))
    _validate_range(data, symbol_offset, symbol_count * parser.size, slice_end)
    for index in range(symbol_count):
        string_index, kind, section, description, value = parser.unpack(
            _checked(data, symbol_offset + index * parser.size, parser.size, slice_end)
        )
        del section, description
        if kind & 0xE0 or string_index >= string_size:
            continue
        name = _cstring(data, string_offset + string_index, string_offset + string_size)
        item = {"name": name, "value": value, "source": "symbol_table"}
        if kind & 0x0E == 0 and not value:
            result["imports"].append(item)
        elif kind & 1:
            with suppress(ValueError):
                item["file_offset"] = _mach_vm_to_file(segments, value)
            result["exports"].append(item)


def _mach_export_trie(
    data: Buffer,
    result: dict[str, Any],
    base: int,
    slice_end: int,
    command: tuple[int, int],
    segments: list[dict[str, Any]],
) -> None:
    trie_offset, trie_size = command
    trie_offset += base
    if not trie_size:
        return
    _validate_range(data, trie_offset, trie_size, slice_end)
    trie_end = trie_offset + trie_size
    pending = [(0, "")]
    visited = set()
    while pending:
        node_offset, prefix_name = pending.pop()
        if node_offset in visited:
            continue
        visited.add(node_offset)
        if len(visited) > MAX_EXPORT_TRIE_NODES:
            raise ValueError("Mach export trie node limit reached")
        cursor = trie_offset + node_offset
        terminal_size, cursor = _uleb(data, cursor, trie_end)
        terminal_end = cursor + terminal_size
        _checked(data, cursor, terminal_size, trie_end)
        if terminal_size:
            flags, terminal = _uleb(data, cursor, terminal_end)
            item: dict[str, Any] = {
                "name": prefix_name,
                "flags": flags,
                "source": "export_trie",
            }
            if flags & 0x08:  # EXPORT_SYMBOL_FLAGS_REEXPORT
                ordinal, terminal = _uleb(data, terminal, terminal_end)
                item["reexport_ordinal"] = ordinal
                item["import_name"] = (
                    _cstring(data, terminal, terminal_end)
                    if terminal < terminal_end
                    else prefix_name
                )
            else:
                address, terminal = _uleb(data, terminal, terminal_end)
                virtual_address = (segments[0]["vmaddr"] if segments else 0) + address
                item["address"] = virtual_address
                with suppress(ValueError):
                    item["file_offset"] = _mach_vm_to_file(segments, virtual_address)
                if flags & 0x10:  # EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER
                    resolver, terminal = _uleb(data, terminal, terminal_end)
                    item["resolver"] = resolver
            if terminal > terminal_end:
                raise ValueError("Mach export trie terminal exceeds node")
            result["exports"].append(item)
        cursor = terminal_end
        child_count = _checked(data, cursor, 1, trie_end)[0]
        cursor += 1
        for _ in range(child_count):
            edge = _cstring(data, cursor, trie_end)
            cursor += len(edge.encode()) + 1
            child_offset, cursor = _uleb(data, cursor, trie_end)
            combined = prefix_name + edge
            if len(combined.encode()) > MAX_NAME_BYTES:
                raise ValueError("Mach export trie name exceeds limit")
            pending.append((child_offset, combined))


def _uleb(data: Buffer, offset: int, end: int, *, max_bits: int = 64) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range((max_bits + 6) // 7):
        byte = _checked(data, offset, 1, end)[0]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if value >= 1 << max_bits:
                break
            return value, offset
        shift += 7
    raise ValueError("invalid or overlong unsigned LEB128")


def _mach_functions(
    data: Buffer,
    result: dict[str, Any],
    base: int,
    slice_end: int,
    command: tuple[int, int],
    segments: list[dict[str, Any]],
) -> None:
    offset, size = command
    offset += base
    _validate_range(data, offset, size, slice_end)
    text = next((segment for segment in segments if segment["name"] == "__TEXT"), None)
    if text is None:
        raise ValueError("Mach function starts lack __TEXT segment")
    address = text["vmaddr"]
    starts = []
    cursor = offset
    while cursor < offset + size and len(starts) < MAX_ITEMS:
        delta, cursor = _uleb(data, cursor, offset + size)
        if not delta:
            break
        address += delta
        starts.append(address)
    if cursor >= offset + size and (not starts or data[offset + size - 1] != 0):
        raise ValueError("unterminated Mach function-start table")
    for index, start in enumerate(starts):
        stop = starts[index + 1] if index + 1 < len(starts) else text["vmaddr"] + text["size"]
        result["functions"].append(
            {
                "index": index,
                "file_offset": _mach_vm_to_file(segments, start),
                "size": max(0, stop - start),
                "source": "function_starts",
            }
        )


@dataclass
class _Cursor:
    data: Buffer
    offset: int
    end: int

    def take(self, size: int) -> bytes:
        value = _checked(self.data, self.offset, size, self.end)
        self.offset += size
        return value

    def byte(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        value, self.offset = _uleb(self.data, self.offset, self.end, max_bits=32)
        return value

    def name(self) -> str:
        size = self.u32()
        if size > MAX_NAME_BYTES:
            raise ValueError("WebAssembly name exceeds limit")
        return self.take(size).decode("utf-8")


def _wasm_vec_count(cursor: _Cursor) -> int:
    count = cursor.u32()
    if count > MAX_ITEMS:
        raise ValueError("WebAssembly vector count exceeds limit")
    return count


def _inspect_wasm(data: Buffer, result: dict[str, Any]) -> None:
    if _checked(data, 0, 8) != b"\0asm\x01\0\0\0":
        raise ValueError("unsupported WebAssembly magic or version")
    result.update(machine="wasm", abi="wasm-core-1", bits=32, byteorder="little")
    cursor = 8
    sections: dict[int, tuple[int, int]] = {}
    custom: list[tuple[str, int, int]] = []
    order = {
        1: 1,
        2: 2,
        3: 3,
        4: 4,
        5: 5,
        13: 6,
        6: 7,
        7: 8,
        8: 9,
        9: 10,
        12: 11,
        10: 12,
        11: 13,
    }
    previous_order = 0
    section_count = 0
    while cursor < len(data):
        section_count += 1
        if section_count > MAX_SECTIONS:
            raise ValueError("WebAssembly section count exceeds limit")
        section_id = _checked(data, cursor, 1)[0]
        cursor += 1
        size, cursor = _uleb(data, cursor, len(data), max_bits=32)
        start, end = cursor, cursor + size
        _validate_range(data, start, size)
        if section_id == 0:
            item = _Cursor(data, start, end)
            custom.append((item.name(), item.offset, end))
        elif section_id > 13:
            raise ValueError(f"unknown WebAssembly section id {section_id}")
        elif section_id in sections:
            raise ValueError(f"duplicate WebAssembly section {section_id}")
        else:
            current_order = order[section_id]
            if current_order < previous_order:
                raise ValueError("WebAssembly sections are out of specification order")
            previous_order = current_order
            sections[section_id] = (start, end)
        cursor = end
    types = _wasm_types(data, sections.get(1))
    imported_functions = _wasm_imports(data, result, sections.get(2), types)
    function_types = _wasm_function_types(data, sections.get(3))
    _wasm_tables(data, sections.get(4))
    _wasm_memories(data, sections.get(5))
    if any(index >= len(types) for index in function_types):
        raise ValueError("WebAssembly function references missing type")
    _wasm_exports(data, result, sections.get(7))
    _wasm_code(data, result, sections.get(10), imported_functions, function_types)
    for function in result["functions"]:
        function["type"] = types[function["type_index"]]
    function_count = imported_functions + len(function_types)
    if any(
        call >= function_count
        for function in result["functions"]
        for call in function["direct_calls"]
    ):
        raise ValueError("WebAssembly direct call index outside function space")
    if any(item["kind"] == 0 and item["index"] >= function_count for item in result["exports"]):
        raise ValueError("WebAssembly function export index outside function space")
    if 8 in sections:
        start_cursor = _Cursor(data, *sections[8])
        start_function = start_cursor.u32()
        if start_cursor.offset != start_cursor.end or start_function >= function_count:
            raise ValueError("WebAssembly start function is malformed or outside function space")
    data_count = _wasm_data(data, result, sections.get(11))
    if 12 in sections:
        count_cursor = _Cursor(data, *sections[12])
        declared = count_cursor.u32()
        if count_cursor.offset != count_cursor.end or declared != data_count:
            _gap(result, "WebAssembly data-count section does not match parsed data segments")
    _wasm_names(data, result, custom)
    for name, start, end in custom:
        if name in ("build_id", "external_debug_info", "producers") or name.startswith(".debug_"):
            result["debug_identities"].append(
                {
                    "kind": "wasm_custom_section",
                    "name": name,
                    "file_offset": start,
                    "size": end - start,
                }
            )


def _wasm_types(data: Buffer, section: tuple[int, int] | None) -> list[dict[str, Any]]:
    if section is None:
        return []
    cursor = _Cursor(data, *section)
    types = []
    type_items = 0
    for _ in range(_wasm_vec_count(cursor)):
        if cursor.byte() != 0x60:
            raise ValueError("unsupported non-function WebAssembly type form")
        parameters = list(cursor.take(_wasm_vec_count(cursor)))
        results = list(cursor.take(_wasm_vec_count(cursor)))
        type_items += len(parameters) + len(results)
        if type_items > MAX_ITEMS:
            raise ValueError("WebAssembly aggregate type element limit reached")
        if any(
            value not in (0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x70, 0x6F)
            for value in parameters + results
        ):
            raise ValueError("unsupported WebAssembly value type")
        types.append({"parameters": parameters, "results": results})
    if cursor.offset != cursor.end:
        raise ValueError("trailing WebAssembly type bytes")
    return types


def _wasm_imports(
    data: Buffer,
    result: dict[str, Any],
    section: tuple[int, int] | None,
    types: list[dict[str, Any]],
) -> int:
    if section is None:
        return 0
    cursor = _Cursor(data, *section)
    imported_functions = 0
    for _ in range(_wasm_vec_count(cursor)):
        module, name, kind = cursor.name(), cursor.name(), cursor.byte()
        item = {"module": module, "name": name, "kind": kind}
        if module not in result["dependencies"]:
            result["dependencies"].append(module)
        if kind == 0:
            item["type_index"] = cursor.u32()
            if item["type_index"] >= len(types):
                raise ValueError("WebAssembly import references missing type")
            item["type"] = types[item["type_index"]]
            imported_functions += 1
        elif kind == 1:
            _wasm_table_type(cursor)
        elif kind == 2:
            _wasm_limits(cursor)
        elif kind == 3:
            cursor.take(2)
        elif kind == 4:
            cursor.byte()
            cursor.u32()
        else:
            raise ValueError("unknown WebAssembly import kind")
        result["imports"].append(item)
    if cursor.offset != cursor.end:
        raise ValueError("trailing WebAssembly import bytes")
    return imported_functions


def _wasm_limits(cursor: _Cursor) -> None:
    flags = cursor.u32()
    if flags & 4:
        raise ValueError("WebAssembly memory64 limits are unsupported")
    if flags & 2 and not flags & 1:
        raise ValueError("WebAssembly shared memory requires a maximum")
    cursor.u32()
    if flags & 1:
        cursor.u32()
    if flags & ~0x03:
        raise ValueError("unsupported WebAssembly limits flags")


def _wasm_table_type(cursor: _Cursor) -> None:
    reference_type = cursor.byte()
    if reference_type not in (0x70, 0x6F):
        raise ValueError("unsupported WebAssembly table reference type")
    _wasm_limits(cursor)


def _wasm_tables(data: Buffer, section: tuple[int, int] | None) -> None:
    if section is None:
        return
    cursor = _Cursor(data, *section)
    for _ in range(_wasm_vec_count(cursor)):
        _wasm_table_type(cursor)
    if cursor.offset != cursor.end:
        raise ValueError("trailing WebAssembly table bytes")


def _wasm_memories(data: Buffer, section: tuple[int, int] | None) -> None:
    if section is None:
        return
    cursor = _Cursor(data, *section)
    for _ in range(_wasm_vec_count(cursor)):
        _wasm_limits(cursor)
    if cursor.offset != cursor.end:
        raise ValueError("trailing WebAssembly memory bytes")


def _wasm_function_types(data: Buffer, section: tuple[int, int] | None) -> list[int]:
    if section is None:
        return []
    cursor = _Cursor(data, *section)
    values = [cursor.u32() for _ in range(_wasm_vec_count(cursor))]
    if cursor.offset != cursor.end:
        raise ValueError("trailing WebAssembly function bytes")
    return values


def _wasm_exports(data: Buffer, result: dict[str, Any], section: tuple[int, int] | None) -> None:
    if section is None:
        return
    cursor = _Cursor(data, *section)
    for _ in range(_wasm_vec_count(cursor)):
        name, kind, index = cursor.name(), cursor.byte(), cursor.u32()
        if kind > 4:
            raise ValueError("unknown WebAssembly export kind")
        result["exports"].append({"name": name, "kind": kind, "index": index})
    if cursor.offset != cursor.end:
        raise ValueError("trailing WebAssembly export bytes")


def _sleb(cursor: _Cursor, bits: int) -> None:
    for _ in range((bits + 6) // 7):
        if not cursor.byte() & 0x80:
            return
    raise ValueError("invalid signed LEB128")


def _wasm_expr(cursor: _Cursor) -> None:
    opcode = cursor.byte()
    if opcode in (0x41, 0x42):
        _sleb(cursor, 64)
    elif opcode == 0x23:
        cursor.u32()
    elif opcode in (0x43, 0x44):
        cursor.take(4 if opcode == 0x43 else 8)
    elif opcode == 0xD0:
        cursor.byte()
    elif opcode == 0xD2:
        cursor.u32()
    else:
        raise ValueError("unsupported WebAssembly initializer expression")
    if cursor.byte() != 0x0B:
        raise ValueError("unterminated WebAssembly initializer expression")


def _wasm_code(
    data: Buffer,
    result: dict[str, Any],
    section: tuple[int, int] | None,
    imported_functions: int,
    function_types: list[int],
) -> None:
    if section is None:
        if function_types:
            raise ValueError("WebAssembly function section lacks code section")
        return
    cursor = _Cursor(data, *section)
    count = _wasm_vec_count(cursor)
    if count != len(function_types):
        raise ValueError("WebAssembly function/code counts differ")
    total_code_bytes = 0
    for ordinal in range(count):
        body_size = cursor.u32()
        if body_size > MAX_WASM_BODY_BYTES:
            raise ValueError("WebAssembly function body exceeds limit")
        total_code_bytes += body_size
        if total_code_bytes > MAX_WASM_TOTAL_CODE_BYTES:
            raise ValueError("WebAssembly aggregate code-byte limit reached")
        body_start, body_end = cursor.offset, cursor.offset + body_size
        _validate_range(data, body_start, body_size, cursor.end)
        body = _Cursor(data, body_start, body_end)
        for _ in range(_wasm_vec_count(body)):
            body.u32()
            body.byte()
        instruction_start = body.offset
        direct, indirect, complete = _wasm_calls(body)
        item = {
            "index": imported_functions + ordinal,
            "type_index": function_types[ordinal],
            "file_offset": instruction_start,
            "size": body_end - instruction_start,
            "source": "code_section",
            "direct_calls": direct,
            "indirect_calls": indirect,
            "calls_complete": complete,
        }
        result["functions"].append(item)
        result["ranges"]["code"].append(
            _range(
                instruction_start,
                body_end - instruction_start,
                function_index=imported_functions + ordinal,
            )
        )
        if not complete:
            _gap(
                result,
                f"WebAssembly function {imported_functions + ordinal} call decoding incomplete",
            )
        cursor.offset = body_end
    if cursor.offset != cursor.end:
        raise ValueError("trailing WebAssembly code bytes")


def _wasm_calls(cursor: _Cursor) -> tuple[list[int], int, bool]:
    calls = []
    indirect = 0
    depth = 1
    try:
        while cursor.offset < cursor.end and depth:
            opcode = cursor.byte()
            if opcode in (0x02, 0x03, 0x04):
                block = cursor.byte()
                if block & 0x80:
                    while block & 0x80:
                        block = cursor.byte()
                depth += 1
            elif opcode == 0x0B:
                depth -= 1
            elif opcode in (0x0C, 0x0D, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0xD2):
                cursor.u32()
            elif opcode in (0x10, 0x12):
                if len(calls) >= MAX_ITEMS:
                    return calls, indirect, False
                calls.append(cursor.u32())
            elif opcode in (0x11, 0x13):
                cursor.u32()
                cursor.u32()
                indirect += 1
            elif opcode == 0x0E:
                for _ in range(_wasm_vec_count(cursor) + 1):
                    cursor.u32()
            elif opcode == 0x1C:
                cursor.take(_wasm_vec_count(cursor))
            elif 0x28 <= opcode <= 0x3E:
                cursor.u32()
                cursor.u32()
            elif opcode in (0x3F, 0x40):
                cursor.u32()
            elif opcode == 0x41:
                _sleb(cursor, 32)
            elif opcode == 0x42:
                _sleb(cursor, 64)
            elif opcode == 0x43:
                cursor.take(4)
            elif opcode == 0x44:
                cursor.take(8)
            elif opcode == 0xD0:
                cursor.byte()
            elif opcode not in WASM_NO_IMMEDIATE:
                return calls, indirect, False
        return calls, indirect, depth == 0 and cursor.offset == cursor.end
    except ValueError:
        return calls, indirect, False


def _wasm_data(data: Buffer, result: dict[str, Any], section: tuple[int, int] | None) -> int:
    if section is None:
        return 0
    cursor = _Cursor(data, *section)
    count = _wasm_vec_count(cursor)
    for index in range(count):
        flags = cursor.u32()
        item: dict[str, Any] = {"data_index": index}
        if flags == 0:
            item.update(mode="active", memory_index=0)
            _wasm_expr(cursor)
        elif flags == 1:
            item.update(mode="passive")
        elif flags == 2:
            item.update(mode="active", memory_index=cursor.u32())
            _wasm_expr(cursor)
        else:
            raise ValueError("unsupported WebAssembly data-segment flags")
        size = cursor.u32()
        start = cursor.offset
        _validate_range(data, start, size, cursor.end)
        cursor.offset += size
        item.update(file_offset=start, size=size)
        result["ranges"]["data"].append(
            _range(
                start,
                size,
                **{key: value for key, value in item.items() if key not in ("file_offset", "size")},
            )
        )
    if cursor.offset != cursor.end:
        raise ValueError("trailing WebAssembly data bytes")
    return count


def _wasm_names(data: Buffer, result: dict[str, Any], custom: list[tuple[str, int, int]]) -> None:
    function_names = {}
    for name, start, end in custom:
        if name != "name":
            continue
        cursor = _Cursor(data, start, end)
        while cursor.offset < end:
            subsection = cursor.byte()
            size = cursor.u32()
            sub = _Cursor(data, cursor.offset, cursor.offset + size)
            _checked(data, sub.offset, size, end)
            if subsection == 1:
                for _ in range(_wasm_vec_count(sub)):
                    function_index = sub.u32()
                    if function_index not in function_names and len(function_names) >= MAX_ITEMS:
                        raise ValueError("WebAssembly aggregate function-name limit reached")
                    function_names[function_index] = sub.name()
            cursor.offset = sub.end
    for function in result["functions"]:
        if function["index"] in function_names:
            function["name"] = function_names[function["index"]]
