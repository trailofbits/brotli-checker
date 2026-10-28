# ruff: noqa: C901, EM101, PLR0912, PLR1714, PLR2004, TRY003, TRY301
"""Bounded ELF dependency declarations and supplied-scope provider candidates."""

from __future__ import annotations

import posixpath
import re
import struct
from typing import TYPE_CHECKING

from brotli_binary_match import ELFLayout, elf_header, program_headers

if TYPE_CHECKING:
    from brotli_binary_data import Buffer

MAX_DYNAMIC_ENTRIES = 16384
MAX_DYNAMIC_STRINGS = 4096
MAX_STRING_BYTES = 4096
MAX_PROVIDER_EDGES = 100000
PT_LOAD = 1
PT_DYNAMIC = 2
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29
ORIGIN_TOKEN = re.compile(r"\$(?:ORIGIN|\{ORIGIN\})(?=/|$)")


def _mapped_string_table(data: Buffer, segments: list[tuple], address: int, size: int) -> int:
    mappings = [
        start + address - virtual
        for kind, _, start, virtual, _, file_size, _, _ in segments
        if kind == PT_LOAD
        and virtual <= address
        and address + size <= virtual + file_size
        and start + file_size <= len(data)
    ]
    if len(mappings) != 1:
        raise ValueError("Dynamic string table has no unique file-backed mapping")
    return mappings[0]


def _mapped_string(data: Buffer, table_start: int, size: int, offset: int) -> str:
    if offset < 0 or offset >= size:
        raise ValueError("Dynamic string offset is outside DT_STRSZ")
    start = table_start + offset
    end = min(start + MAX_STRING_BYTES + 1, start + size - offset)
    raw = data[start:end]
    terminator = raw.find(b"\0")
    if terminator < 0:
        raise ValueError("Unterminated or oversized dynamic string")
    value = raw[:terminator].decode("utf-8", errors="strict")
    if not value or any(ord(char) < 32 for char in value):
        raise ValueError("Empty or control-containing dynamic string")
    return value


def elf_dependencies(data: Buffer) -> dict:
    result = {"needed": [], "soname": None, "rpath": [], "runpath": [], "gaps": []}
    try:
        header = elf_header(data)
        layout = ELFLayout.of(header)
        ident = header[0]
        result["identity"] = {
            "machine": header[2],
            "bits": layout.bits,
            "byteorder": layout.byteorder,
            "osabi": ident[7],
            "abi_version": ident[8],
            "abi_flags": header[7] if header[2] in (8, 40) else 0,
        }
        segments = list(program_headers(data, header))
        parser = struct.Struct(
            ("<" if layout.byteorder == "little" else ">") + ("iI" if layout.bits == 32 else "qQ")
        )
        values: dict[int, list[int]] = {}
        entries = 0
        for kind, _, start, _, _, size, _, _ in segments:
            if kind != PT_DYNAMIC:
                continue
            if start + size > len(data) or size % parser.size:
                raise ValueError("Malformed PT_DYNAMIC extent")
            terminated = False
            for position in range(start, start + size, parser.size):
                entries += 1
                if entries > MAX_DYNAMIC_ENTRIES:
                    raise ValueError("Dynamic entry budget exceeded")
                tag, value = parser.unpack(data[position : position + parser.size])
                if tag == DT_NULL:
                    terminated = True
                    break
                if tag in {DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_SONAME, DT_RPATH, DT_RUNPATH}:
                    values.setdefault(tag, []).append(value)
            if not terminated:
                raise ValueError("PT_DYNAMIC lacks a terminating DT_NULL")
        if not values:
            return result
        if len(values.get(DT_STRTAB, [])) != 1 or len(values.get(DT_STRSZ, [])) != 1:
            raise ValueError("Dynamic strings require unique DT_STRTAB and DT_STRSZ")
        address, size = values[DT_STRTAB][0], values[DT_STRSZ][0]
        string_start = _mapped_string_table(data, segments, address, size)
        for tag, key in (
            (DT_NEEDED, "needed"),
            (DT_SONAME, "soname"),
            (DT_RPATH, "rpath"),
            (DT_RUNPATH, "runpath"),
        ):
            offsets = values.get(tag, [])
            if len(offsets) > MAX_DYNAMIC_STRINGS or (tag != DT_NEEDED and len(offsets) > 1):
                raise ValueError("Dynamic string count or singleton constraint exceeded")
            strings = [_mapped_string(data, string_start, size, offset) for offset in offsets]
            result[key] = (
                strings[0]
                if tag == DT_SONAME and strings
                else None
                if tag == DT_SONAME
                else strings
            )
    except (ValueError, struct.error) as error:
        result["gaps"].append(str(error))
    return result


def _candidate_paths(importer: dict, needed: str) -> tuple[set[str] | None, list[str], str]:
    metadata = importer["loader"]
    gaps = []
    if "/" in needed or "\\" in needed:
        return (
            set(),
            ["Path-bearing DT_NEEDED requires deployment-specific resolution"],
            "unsupported",
        )
    declared = metadata.get("runpath") or metadata.get("rpath") or []
    basis = (
        "declared_runpath"
        if metadata.get("runpath")
        else "declared_rpath"
        if declared
        else "in_scope_name_only"
    )
    if not declared:
        return None, gaps, basis
    logical_path = importer["logical_path"]
    if (
        not isinstance(logical_path, str)
        or not logical_path.startswith("/")
        or "\\" in logical_path
        or "\0" in logical_path
        or posixpath.normpath(logical_path) != logical_path
    ):
        return (
            set(),
            ["Importer logical path is not a normalized absolute virtual path"],
            "unsupported",
        )
    origin = posixpath.dirname(logical_path)
    boundary = importer.get("boundary", "/")
    if (
        not isinstance(boundary, str)
        or not boundary.startswith("/")
        or "\\" in boundary
        or posixpath.normpath(boundary) != boundary
    ):
        return set(), ["Supplied-scope boundary is not a normalized absolute path"], "unsupported"
    paths = set()
    for declaration in declared:
        for component in declaration.split(":"):
            expanded = ORIGIN_TOKEN.sub(origin, component)
            if not component or "$" in expanded or "\\" in expanded:
                gaps.append("Empty, unsupported-token, or non-POSIX loader path")
                continue
            if expanded.startswith("/"):
                if (
                    not importer.get("deployment_root")
                    and "$ORIGIN" not in component
                    and "${ORIGIN}" not in component
                ):
                    gaps.append("Absolute loader path requires an explicit deployment root")
                    continue
            else:
                gaps.append("Relative loader path depends on an unverified working directory")
                continue
            normalized = posixpath.normpath(expanded)
            if (
                boundary != "/"
                and normalized != boundary
                and not normalized.startswith(boundary.rstrip("/") + "/")
            ):
                gaps.append("Loader path escapes the supplied scope")
                continue
            paths.add(posixpath.join(normalized, needed))
    return paths, gaps, basis


def provider_graph(artifacts: list[dict]) -> dict:
    """Relate declarations only to inspected candidates; never simulate the host loader."""
    providers: dict[tuple[str, str], list[dict]] = {}
    for artifact in artifacts:
        if not artifact.get("loader"):
            continue
        for name in {
            posixpath.basename(artifact["logical_path"]),
            artifact["loader"].get("soname"),
        }:
            if name:
                providers.setdefault((artifact["namespace"], name), []).append(artifact)
    edges, gaps = [], []
    for importer in artifacts:
        for needed in importer.get("loader", {}).get("needed", []):
            if len(edges) >= MAX_PROVIDER_EDGES:
                return {
                    "edges": edges,
                    "gaps": [*gaps, "Provider edge budget exceeded"],
                    "complete": False,
                }
            paths, path_gaps, basis = _candidate_paths(importer, needed)
            candidates = providers.get((importer["namespace"], needed), [])
            candidates = [
                item for item in candidates if paths is None or item["logical_path"] in paths
            ]
            compatible = {
                item["id"]: item
                for item in candidates
                if item["loader"].get("identity") == importer["loader"].get("identity")
            }
            status = (
                "unsupported_search_path"
                if paths == set() and path_gaps
                else "ambiguous_candidates"
                if len(compatible) > 1
                else "scope_unique_candidate"
                if compatible
                else "incompatible_candidates"
                if candidates
                else "missing_candidate"
            )
            edges.append(
                {
                    "source": importer["id"],
                    "needed": needed,
                    "targets": sorted(compatible),
                    "status": status,
                    "basis": basis,
                    "runtime_selection": "unknown",
                    "inherited_search_paths": "not_simulated",
                    "gaps": path_gaps,
                }
            )
            if path_gaps:
                gaps.extend(
                    f"{importer.get('path', importer.get('logical_path', '<artifact>'))}: {reason}"
                    for reason in path_gaps
                )
    return {"edges": edges, "gaps": list(dict.fromkeys(gaps)), "complete": not gaps}
