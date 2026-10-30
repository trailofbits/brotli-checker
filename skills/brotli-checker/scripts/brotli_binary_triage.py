#!/usr/bin/env python3

"""Collect bounded objdump evidence for model review of one unresolved ELF."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from brotli_binary_data import Buffer, FileData, file_data, sha256_data
from brotli_binary_match import (
    EM_ARM,
    EM_MIPS,
    TARGETS,
    ELFLayout,
    elf_header,
    executable_ranges,
    program_headers,
    section_headers,
    symbol_rows,
    target_identity,
)
from brotli_binary_metadata import MAX_SYMBOL_TABLES, MAX_SYMBOLS
from brotli_evidence_report import (
    ReproducibilityEnvelope,
    envelope_sha256,
    verify_report_envelope,
)

if TYPE_CHECKING:
    from collections.abc import Generator

DEFAULT_MAX_FILE_BYTES = None
DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024
DEFAULT_MAX_RANGE_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_MAX_SYMBOLS = 12
DEFAULT_MAX_REPORT_RANGES = 32
CHUNK_BYTES = 64 * 1024
MAX_ANALYSIS_REPORT_BYTES = 64 * 1024 * 1024
PT_LOAD = 1
PF_X = 1
SHT_STRTAB = 3
STT_FUNC = 2
SHF_EXECINSTR = 4
SHF_ALLOC = 2
MAX_TRIAGE_SYMBOL_NAME_BYTES = 128
PATCH_SYMBOL = re.compile(
    r"^(?:Safe)?Decode(Literal|Command|Distance)BlockSwitch(?:Internal)?(?:[.$].*)?$"
)
PROCESS_SYMBOL = re.compile(r"^(?:Safe)?ProcessCommands(?:Internal)?(?:[.$].*)?$")
PUBLIC_FALLBACK = "BrotliDecoderDecompressStream"
EF_MIPS_ARCH = 0xF0000000
EF_MIPS_ARCH_32R2 = 0x70000000
EF_MIPS_ARCH_64R2 = 0x80000000
EF_MIPS_ARCH_ASE = 0x0F000000
EF_MIPS_ARCH_ASE_M16 = 0x04000000
EF_MIPS_ARCH_ASE_MICROMIPS = 0x02000000
EF_MIPS_MACH = 0x00FF0000
STO_MIPS_ISA = 0xC0
STO_MIPS16 = 0xF0
STO_MICROMIPS = 0x80
REPORT_FUNCTION_METHODS = frozenset({"flirt_function"})
REPORT_ARTIFACT_KINDS = frozenset({"exact_code_region"})
REPORT_REFERENCE_KINDS = frozenset(
    {"relocation_reference", "pc_relative_reference", "absolute_reference"}
)


class TriageError(ValueError):
    """An input cannot be inspected safely within the requested scope."""


def positive(value: str) -> int:
    number = int(value, 0)
    if number <= 0:
        message = "must be positive"
        raise argparse.ArgumentTypeError(message)
    return number


def nonnegative(value: str) -> int:
    number = int(value, 0)
    if number < 0:
        message = "must be nonnegative"
        raise argparse.ArgumentTypeError(message)
    return number


def trusted_objdump(value: str | None) -> Path:
    located = value or shutil.which("objdump")
    if not located:
        message = "objdump was not found; provide an absolute trusted --objdump path"
        raise TriageError(message)
    candidate = Path(located).expanduser()
    if value and not candidate.is_absolute():
        message = "--objdump must be an absolute trusted path"
        raise TriageError(message)
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        message = f"Cannot inspect objdump: {error}"
        raise TriageError(message) from error
    if (
        not resolved.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or not os.access(resolved, os.X_OK)
    ):
        message = "objdump must resolve to an executable regular file"
        raise TriageError(message)
    return resolved


@contextmanager
def read_target(path: Path, max_file_bytes: int | None) -> Generator[FileData]:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            message = "Target symlinks and nonregular files are not inspected"
            raise TriageError(message)
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                message = "Target is not a regular file"
                raise TriageError(message)
            if max_file_bytes is not None and metadata.st_size > max_file_bytes:
                message = f"Target exceeds --max-file-bytes ({metadata.st_size} > {max_file_bytes})"
                raise TriageError(message)
            with file_data(stream, max_file_bytes) as data:
                yield data
    except (OSError, ValueError) as error:
        message = f"Cannot read stable target: {error}"
        raise TriageError(message) from error


def run_bounded(  # noqa: C901 -- Process/pipe/time bounds share one lifecycle.
    command: list[str], timeout_seconds: float, max_output_bytes: int
) -> dict:
    """Run one trusted tool command with wall-clock and combined-output bounds."""
    started = time.monotonic()
    try:
        process = subprocess.Popen(  # noqa: S603 -- Caller supplies a validated objdump path.
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError as error:
        return {
            "returncode": None,
            "output": "",
            "limited": True,
            "reason": f"Cannot start objdump: {error}",
            "elapsed_seconds": time.monotonic() - started,
        }
    assert process.stdout is not None  # noqa: S101 -- PIPE guarantees this internal invariant.
    output = bytearray()
    reason = None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = started + timeout_seconds
    try:
        while selector.get_map():
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                reason = "objdump timeout reached"
                process.kill()
                break
            for key, _ in selector.select(min(remaining_time, 0.1)):
                chunk = os.read(key.fd, min(CHUNK_BYTES, max_output_bytes - len(output) + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > max_output_bytes:
                    del output[max_output_bytes:]
                    reason = "objdump output limit reached"
                    process.kill()
                    break
            if reason is not None:
                break
        remaining_time = max(0.0, deadline - time.monotonic())
        try:
            returncode = process.wait(timeout=remaining_time)
        except subprocess.TimeoutExpired:
            reason = reason or "objdump timeout reached"
            process.kill()
            returncode = process.wait()
    finally:
        selector.close()
        process.stdout.close()
    return {
        "returncode": returncode,
        "output": output.decode("utf-8", errors="replace"),
        "limited": reason is not None,
        "reason": reason,
        "elapsed_seconds": time.monotonic() - started,
    }


def checked_range(data: Buffer, offset: int, size: int) -> tuple[int, int]:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        message = "ELF range outside file"
        raise ValueError(message)
    return offset, offset + size


def function_offset(data: Buffer, header: tuple, address: int, size: int) -> int | None:
    candidates = {
        start + address - virtual
        for kind, flags, start, virtual, _, file_size, _, _ in program_headers(data, header)
        if kind == PT_LOAD
        and flags & PF_X
        and virtual <= address < address + size <= virtual + file_size
    }
    return next(iter(candidates)) if len(candidates) == 1 else None


def require_supported_instruction_mode(  # noqa: C901 -- MIPS flags and bounded symbol modes.
    data: Buffer,
    deadline: float | None = None,
    candidate_limit: int = DEFAULT_MAX_SYMBOLS + 1,
) -> str | None:
    """Reject MIPS ISA/mode combinations not represented by the raw-binary command."""
    header = elf_header(data)
    if header[2] != EM_MIPS:
        return None
    flags = header[7]
    ase = flags & EF_MIPS_ARCH_ASE
    if ase:
        modes = []
        if ase & EF_MIPS_ARCH_ASE_M16:
            modes.append("MIPS16")
        if ase & EF_MIPS_ARCH_ASE_MICROMIPS:
            modes.append("microMIPS")
        suffix = "/".join(modes) if modes else f"ASE 0x{ase:08x}"
        message = "Unsupported MIPS instruction mode in ELF flags: " + suffix
        raise TriageError(message)
    machine = flags & EF_MIPS_MACH
    if machine:
        message = f"Unsupported MIPS vendor-machine flags 0x{machine:08x}"
        raise TriageError(message)
    actual = flags & EF_MIPS_ARCH
    architectures = {
        EF_MIPS_ARCH_32R2: "mips:isa32r2",
        EF_MIPS_ARCH_64R2: "mips:isa64r2",
    }
    if actual not in architectures:
        message = f"Unsupported MIPS ISA flags 0x{actual:08x}; raw triage supports r2 only"
        raise TriageError(message)
    if deadline is None:
        return architectures[actual]
    _, symbol_reason = relevant_symbols(data, deadline, candidate_limit)
    if unsupported_mips_symbol_reason(symbol_reason):
        raise TriageError(symbol_reason)
    allowed = {
        None,
        "No ELF section table; symbol-based triage is unavailable",
        "Relevant ELF symbol candidate limit reached",
    }
    if symbol_reason not in allowed:
        message = f"Cannot establish exact MIPS symbol instruction mode: {symbol_reason}"
        raise TriageError(message)
    return architectures[actual]


def mips_symbol_mode(other: int) -> str | None:
    """Decode GNU MIPS compressed-ISA markers from st_other."""
    if other & STO_MIPS16 == STO_MIPS16:
        return "MIPS16"
    if other & STO_MIPS_ISA == STO_MICROMIPS:
        return "microMIPS"
    if other & STO_MIPS_ISA:
        return f"reserved MIPS ISA 0x{other & STO_MIPS_ISA:02x}"
    return None


def unsupported_mips_symbol_reason(reason: str | None) -> bool:
    return reason is not None and reason.startswith("Unsupported ") and "instruction mode" in reason


def relevant_symbols(  # noqa: C901, PLR0911, PLR0912, PLR0915 -- Bounded ELF validation.
    data: Buffer, deadline: float, candidate_limit: int = DEFAULT_MAX_SYMBOLS + 1
) -> tuple[list[dict], str | None]:
    """Select relevant defined/imported functions from bounded in-file ELF tables."""
    header = elf_header(data)
    if not header[12]:
        return [], "No ELF section table; symbol-based triage is unavailable"
    if header[11] != ELFLayout.of(header).parser("section").size:
        return [], "Unsupported ELF section table"
    sections = section_headers(data, header)
    symbol = ELFLayout.of(header).parser("symbol")
    defined_symbols = []
    imported_symbols = []
    candidate_overflow = False
    scanned = 0
    tables = 0
    for table in sections:
        if table[1] not in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM.
            continue
        tables += 1
        if tables > MAX_SYMBOL_TABLES:
            return [*defined_symbols, *imported_symbols], "ELF symbol-table limit reached"
        if table[9] != symbol.size or table[5] % symbol.size or table[6] >= len(sections):
            return [*defined_symbols, *imported_symbols], "Malformed ELF symbol table"
        scanned += table[5] // symbol.size
        if scanned > MAX_SYMBOLS:
            return [*defined_symbols, *imported_symbols], "ELF symbol limit reached"
        names = sections[table[6]]
        if names[1] != SHT_STRTAB:
            return [*defined_symbols, *imported_symbols], (
                "ELF symbols do not reference a string table"
            )
        name_start, name_stop = checked_range(data, names[4], names[5])
        for name_offset, info, other, index, symbol_address, size in symbol_rows(
            data, header, table
        ):
            address = symbol_address & (~1 if header[2] == EM_ARM else -1)
            if time.monotonic() >= deadline:
                return [*defined_symbols, *imported_symbols], "ELF symbol scan timeout reached"
            if info & 0xF != STT_FUNC:
                continue
            # Instruction mode must not depend on recognizing a function's name.
            if header[2] == EM_MIPS and (mode := mips_symbol_mode(other)) is not None:
                return [*defined_symbols, *imported_symbols], (
                    f"Unsupported {mode} instruction mode for function at 0x{symbol_address:x}"
                )
            if name_offset >= names[5]:
                continue
            absolute_name = name_start + name_offset
            end = data.find(
                b"\0",
                absolute_name,
                min(absolute_name + MAX_TRIAGE_SYMBOL_NAME_BYTES, name_stop),
            )
            if end < 0:
                continue
            try:
                name = data[absolute_name:end].decode("ascii")
            except UnicodeDecodeError:
                continue
            base = name.split("@", 1)[0]
            if not (
                PATCH_SYMBOL.match(base) or PROCESS_SYMBOL.match(base) or base == PUBLIC_FALLBACK
            ):
                continue
            if index == 0:
                section = "*UND*"
                defined = False
            else:
                if index >= len(sections):
                    continue
                owner = sections[index]
                offset = function_offset(data, header, address, max(size, 1))
                if (
                    owner[1] != 1
                    or owner[2] & (SHF_ALLOC | SHF_EXECINSTR) != (SHF_ALLOC | SHF_EXECINSTR)
                    or address < owner[3]
                    or address + max(size, 1) > owner[3] + owner[5]
                    or offset != owner[4] + address - owner[3]
                ):
                    continue
                section = f"section[{index}]"
                defined = True
            item = {
                "name": name,
                "base_name": base,
                "address": address,
                "size_bytes": size,
                "section": section,
                "defined": defined,
            }
            if header[2] == EM_ARM:
                item["thumb"] = bool(symbol_address & 1)
            bucket = defined_symbols if defined else imported_symbols
            if item in bucket:
                continue
            if len(bucket) < candidate_limit:
                bucket.append(item)
            else:
                candidate_overflow = True
    symbols = [*defined_symbols, *imported_symbols]
    if len(symbols) > candidate_limit:
        candidate_overflow = True
        symbols = symbols[:candidate_limit]
    return symbols, "Relevant ELF symbol candidate limit reached" if candidate_overflow else None


def symbol_priority(symbol: dict) -> tuple[int, int, int, str]:
    name = symbol["base_name"]
    priority = 0 if PATCH_SYMBOL.match(name) else 1 if PROCESS_SYMBOL.match(name) else 2
    return 0 if symbol["defined"] else 1, priority, symbol["address"], symbol["name"]


def mapped_file_offset_address(
    data: Buffer, file_offset: int, length: int, *, executable: bool
) -> int:
    header = elf_header(data)
    candidates = {
        virtual + file_offset - start
        for kind, flags, start, virtual, _, file_size, _, _ in program_headers(data, header)
        if kind == PT_LOAD
        and (not executable or flags & PF_X)
        and start <= file_offset
        and file_offset + length <= start + file_size
    }
    if len(candidates) == 1:
        return next(iter(candidates))
    scope = "executable PT_LOAD" if executable else "PT_LOAD"
    message = f"File-offset range is not inside one file-backed {scope} segment"
    if len(candidates) > 1:
        message = f"File-offset range has ambiguous {scope} mappings"
    raise TriageError(message)


def file_offset_address(data: Buffer, file_offset: int, length: int) -> int:
    return mapped_file_offset_address(data, file_offset, length, executable=True)


def validate_address_range(data: Buffer, start: int, stop: int) -> None:
    header = elf_header(data)
    for kind, flags, _, virtual, _, file_size, _, _ in program_headers(data, header):
        if kind == PT_LOAD and flags & PF_X and virtual <= start < stop <= virtual + file_size:
            return
    message = "Address range is not inside one file-backed executable PT_LOAD segment"
    raise TriageError(message)


def _report_location(
    data: Buffer, value: object, source: str, *, executable: bool
) -> tuple[int, int, int]:
    if not isinstance(value, dict):
        msg = f"Malformed {source} range in analysis report"
        raise TriageError(msg)
    offset, size = value.get("file_offset"), value.get("size_bytes", value.get("size"))
    if type(offset) is not int or type(size) is not int or offset < 0 or size <= 0:
        msg = f"Malformed {source} range in analysis report"
        raise TriageError(msg)
    try:
        address = mapped_file_offset_address(data, offset, size, executable=executable)
    except (ValueError, TriageError) as error:
        msg = f"Analysis report {source} range is not executable: {error}"
        raise TriageError(msg) from error
    reported_address = value.get("virtual_address")
    if reported_address is not None and (
        type(reported_address) is not int or reported_address != address
    ):
        msg = f"Analysis report {source} virtual address disagrees with target bytes"
        raise TriageError(msg)
    return offset, size, address


def _report_range(data: Buffer, value: object, source: str) -> dict:
    offset, size, address = _report_location(data, value, source, executable=True)
    return {
        "file_offset": offset,
        "size_bytes": size,
        "start_address": address,
        "stop_address": address + size,
        "evidence_sources": [source],
    }


def _merge_report_range(ranges: dict[tuple[int, int], dict], selected: dict) -> None:
    key = selected["file_offset"], selected["size_bytes"]
    current = ranges.get(key)
    if current is None:
        ranges[key] = selected
        return
    current["evidence_sources"] = sorted(
        {*current["evidence_sources"], *selected["evidence_sources"]}
    )


def _graph_artifacts(data: Buffer, values: list) -> tuple[dict[str, dict], dict]:
    artifacts = {}
    ranges: dict[tuple[int, int], dict] = {}
    for artifact in values:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("identifier"), str):
            msg = "Malformed function graph artifact"
            raise TriageError(msg)
        identifier = artifact["identifier"]
        if identifier in artifacts:
            msg = "Duplicate function graph artifact identifier"
            raise TriageError(msg)
        artifacts[identifier] = artifact
        if artifact.get("kind") in REPORT_ARTIFACT_KINDS:
            _merge_report_range(ranges, _report_range(data, artifact, "graph_exact_code"))
        elif artifact.get("kind") == "decoder_table":
            _report_location(data, artifact, "graph_decoder_table", executable=False)
    return artifacts, ranges


def _graph_referenced_functions(edges: list, table_ids: set[str]) -> dict[str, list[int]]:
    referenced_functions: dict[str, list[int]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            msg = "Malformed function graph edge"
            raise TriageError(msg)
        if (
            edge.get("qualified") is True
            and edge.get("kind") in REPORT_REFERENCE_KINDS
            and edge.get("target") in table_ids
            and isinstance(edge.get("source"), str)
        ):
            instruction = edge.get("instruction_file_offset")
            if type(instruction) is not int:
                msg = "Malformed function graph instruction offset"
                raise TriageError(msg)
            referenced_functions.setdefault(edge["source"], []).append(instruction)
    return referenced_functions


def _graph_functions(
    data: Buffer,
    functions: list,
    referenced_functions: dict[str, list[int]],
    ranges: dict[tuple[int, int], dict],
) -> None:
    function_ids = set()
    for function in functions:
        if not isinstance(function, dict) or not isinstance(function.get("identifier"), str):
            msg = "Malformed function graph function"
            raise TriageError(msg)
        identifier = function["identifier"]
        methods = function.get("boundary_methods")
        if (
            identifier in function_ids
            or not isinstance(methods, list)
            or not all(isinstance(item, str) for item in methods)
        ):
            msg = "Malformed or duplicate function graph function"
            raise TriageError(msg)
        function_ids.add(identifier)
        file_offset, size = function.get("file_offset"), function.get("size")
        if identifier in referenced_functions and (
            type(file_offset) is not int
            or type(size) is not int
            or not all(
                file_offset <= instruction < file_offset + size
                for instruction in referenced_functions[identifier]
            )
        ):
            msg = "Function graph reference site is outside its source function"
            raise TriageError(msg)
        sources = _graph_function_sources(identifier, methods, referenced_functions)
        for source in sources:
            _merge_report_range(ranges, _report_range(data, function, source))
    if set(referenced_functions) - function_ids:
        msg = "Function graph table reference has no bounded source function"
        raise TriageError(msg)


def _graph_function_sources(
    identifier: str, methods: list[str], referenced_functions: dict[str, list[int]]
) -> list[str]:
    sources = []
    if REPORT_FUNCTION_METHODS.intersection(methods):
        sources.append("graph_flirt_function")
    if identifier in referenced_functions:
        sources.append("graph_table_reference")
    return sources


def _graph_report_ranges(data: Buffer, graph: object) -> tuple[list[dict], list[str]]:
    if not isinstance(graph, dict):
        msg = "Malformed function graph in analysis report"
        raise TriageError(msg)
    for field in ("artifacts", "functions", "edges", "gaps"):
        if not isinstance(graph.get(field), list):
            msg = f"Malformed function graph {field} population"
            raise TriageError(msg)
    if graph.get("patch_status") != "unknown" or not isinstance(graph.get("limited"), bool):
        msg = "Malformed function graph classification"
        raise TriageError(msg)
    artifacts, ranges = _graph_artifacts(data, graph["artifacts"])
    table_ids = {
        identifier
        for identifier, artifact in artifacts.items()
        if artifact.get("kind") == "decoder_table"
    }
    referenced_functions = _graph_referenced_functions(graph["edges"], table_ids)
    _graph_functions(data, graph["functions"], referenced_functions, ranges)
    reasons = []
    if graph["limited"] or graph["gaps"]:
        reasons.append("Analysis report function graph is incomplete; retained ranges are partial")
    return list(ranges.values()), reasons


def _finding_evidence_ranges(
    data: Buffer, evidence: dict, ranges: dict[tuple[int, int], dict]
) -> str | None:
    code_matches = evidence.get("code_matches", [])
    if not isinstance(code_matches, list):
        msg = "Malformed exact-code match population in analysis report"
        raise TriageError(msg)
    for match in code_matches:
        _merge_report_range(ranges, _report_range(data, match, "finding_exact_code"))
    flirt = evidence.get("flirt")
    if not isinstance(flirt, dict):
        return None
    matches = flirt.get("matches", [])
    if not isinstance(matches, list):
        msg = "Malformed FLIRT match population in analysis report"
        raise TriageError(msg)
    for match in matches:
        _merge_report_range(ranges, _report_range(data, match, "finding_flirt_match"))
    if flirt.get("status") == "limited" or flirt.get("gaps"):
        return "Analysis report FLIRT matching is incomplete; retained ranges are partial"
    return None


def _finding_report_ranges(
    data: Buffer, findings: object, digest: str
) -> tuple[list[dict], list[str]]:
    if not isinstance(findings, list):
        msg = "Malformed finding population in analysis report"
        raise TriageError(msg)
    ranges: dict[tuple[int, int], dict] = {}
    reasons = []
    for finding in findings:
        if not isinstance(finding, dict):
            msg = "Malformed finding in analysis report"
            raise TriageError(msg)
        evidence = finding.get("evidence", finding)
        if (
            not isinstance(evidence, dict)
            or evidence.get("sha256", finding.get("sha256")) != digest
        ):
            continue
        if reason := _finding_evidence_ranges(data, evidence, ranges):
            reasons.append(reason)
    return list(ranges.values()), reasons


def _read_verified_analysis_report(
    report_path: Path,
) -> tuple[bytes, dict, ReproducibilityEnvelope]:
    with read_target(report_path.expanduser().absolute(), MAX_ANALYSIS_REPORT_BYTES) as report_data:
        raw = report_data[:]
    try:
        stored = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        msg = "Analysis report is not valid bounded JSON"
        raise TriageError(msg) from error
    if not isinstance(stored, dict):
        msg = "Analysis report root must be an object"
        raise TriageError(msg)
    try:
        report, envelope = verify_report_envelope(stored)
    except ValueError as error:
        msg = f"Analysis report envelope is invalid: {error}"
        raise TriageError(msg) from error
    if envelope.scanner.name != "brotli-checker":
        msg = "Analysis report was not produced by brotli-checker"
        raise TriageError(msg)
    return raw, report, envelope


def _matching_function_graphs(report: dict, digest: str) -> list:
    graphs = []
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, list):
        msg = "Analysis report lacks an artifact registry"
        raise TriageError(msg)
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            msg = "Malformed artifact registry entry"
            raise TriageError(msg)
        if artifact.get("sha256") != digest:
            continue
        analysis = artifact.get("analysis")
        if isinstance(analysis, dict) and "function_graph" in analysis:
            graphs.append(analysis["function_graph"])
    if graphs:
        canonical = {json.dumps(item, sort_keys=True, separators=(",", ":")) for item in graphs}
        if len(canonical) != 1:
            msg = "Hash-matched artifacts contain conflicting function graphs"
            raise TriageError(msg)
    return graphs


def _bounded_report_ranges(
    selected: dict[tuple[int, int], dict], reasons: list[str], max_ranges: int, max_range_bytes: int
) -> list[dict]:
    ordered = sorted(selected.values(), key=lambda item: (item["file_offset"], item["size_bytes"]))
    if any(item["size_bytes"] > max_range_bytes for item in ordered):
        reasons.append("Analysis report ranges exceeded --max-range-bytes and were omitted")
    ordered = [item for item in ordered if item["size_bytes"] <= max_range_bytes]
    if len(ordered) > max_ranges:
        reasons.append("Analysis report range count exceeded --max-report-ranges")
        ordered = ordered[:max_ranges]
    if not ordered:
        reasons.append("Analysis report contains no hash-bound executable triage ranges")
    return ordered


def analysis_report_ranges(
    data: Buffer,
    report_path: Path,
    max_ranges: int,
    max_range_bytes: int,
) -> tuple[list[dict], list[str], dict]:
    """Select only hash-bound executable windows from one finalized inventory report."""
    raw, report, envelope = _read_verified_analysis_report(report_path)
    digest = sha256_data(data)
    graphs = _matching_function_graphs(report, digest)
    selected: dict[tuple[int, int], dict] = {}
    reasons = []
    if report.get("analysis_inputs_changed") is True:
        reasons.append(
            "Analysis report inputs changed during its scan; retained ranges are partial"
        )
    if graphs:
        graph_ranges, graph_reasons = _graph_report_ranges(data, graphs[0])
        reasons.extend(graph_reasons)
        for item in graph_ranges:
            _merge_report_range(selected, item)
    finding_ranges, finding_reasons = _finding_report_ranges(data, report.get("findings"), digest)
    reasons.extend(finding_reasons)
    for item in finding_ranges:
        _merge_report_range(selected, item)
    ordered = _bounded_report_ranges(selected, reasons, max_ranges, max_range_bytes)
    metadata = {
        "path": str(report_path.expanduser().absolute()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "report_sha256": envelope.report_sha256,
        "envelope_sha256": envelope_sha256(envelope),
        "target_sha256": digest,
        "selected_ranges": len(ordered),
    }
    return ordered, list(dict.fromkeys(reasons)), metadata


def base_report(path: Path, args: argparse.Namespace) -> dict:
    return {
        "schema_version": 2,
        "target": {"path": str(path), "sha256": None, "size_bytes": None},
        "tool": {"path": None, "input_mode": "code_fragments", "fragments": [], "commands": []},
        "scope": {"mode": "symbols"},
        "limits": {
            "max_file_bytes": args.max_file_bytes,
            "max_output_bytes": args.max_output_bytes,
            "max_range_bytes": args.max_range_bytes,
            "timeout_seconds": args.timeout_seconds,
            "max_symbols": args.max_symbols,
            "max_report_ranges": args.max_report_ranges,
        },
        "collection": {"status": "incomplete", "incomplete": True, "reasons": []},
        "classification": {
            "patch_status": "unknown",
            "reason": (
                "Disassembly requires model comparison with reviewed source; no automatic verdict"
            ),
        },
        "evidence": {"symbols": [], "analysis_report": None, "disassembly": []},
        "limitations": [
            "SHA-256 requires one streamed full-file pass; ELF analysis uses bounded offset reads.",
            (
                "The target is never executed or loaded; only bounded code fragments are copied "
                "for objdump and removed after use."
            ),
            "Disassembly is bounded and may omit inlined, stripped, split, or optimized code.",
            "Strings and version evidence cannot establish that the fix is present.",
            "One reviewed range cannot clear other embedded decoder copies.",
        ],
    }


def command_evidence(
    report: dict, command: list[str], scope: dict, deadline: float, remaining_output: int
) -> int:
    remaining_time = deadline - time.monotonic()
    if remaining_time <= 0 or remaining_output <= 0:
        report["collection"]["reasons"].append("Global objdump time/output budget exhausted")
        return 0
    report["tool"]["commands"].append(command)
    result = run_bounded(command, remaining_time, remaining_output)
    report["evidence"]["disassembly"].append(
        {
            "scope": scope,
            "returncode": result["returncode"],
            "limited": result["limited"],
            "reason": result["reason"],
            "text": result["output"],
        }
    )
    if result["limited"] or result["returncode"] != 0:
        report["collection"]["reasons"].append(
            result["reason"] or f"objdump exited {result['returncode']}"
        )
    return len(result["output"].encode("utf-8"))


def validate_scope(parser: argparse.ArgumentParser, args: argparse.Namespace) -> str:
    address_range = args.start_address is not None or args.stop_address is not None
    offset_range = args.file_offset is not None or args.length is not None
    report_range = args.analysis_report is not None
    if (args.start_address is None) != (args.stop_address is None):
        parser.error("--start-address and --stop-address must be supplied together")
    if (args.file_offset is None) != (args.length is None):
        parser.error("--file-offset and --length must be supplied together")
    if sum((address_range, offset_range, report_range)) > 1:
        parser.error("analysis-report, address, and file-offset scopes are mutually exclusive")
    if args.section is not None and not address_range:
        parser.error("--section requires an explicit address range")
    if args.thumb and not (address_range or offset_range):
        parser.error("--thumb requires an explicit ARM range")
    if report_range:
        return "analysis_report"
    return "address_range" if address_range else "file_offset_range" if offset_range else "symbols"


def explicit_range(data: Buffer, args: argparse.Namespace, mode: str) -> tuple[int, int]:
    if mode == "address_range":
        start, stop = args.start_address, args.stop_address
    else:
        start = file_offset_address(data, args.file_offset, args.length)
        stop = start + args.length
    if stop <= start or stop - start > args.max_range_bytes:
        message = "Requested range must be nonempty and within --max-range-bytes"
        raise TriageError(message)
    validate_address_range(data, start, stop)
    return start, stop


def require_section(data: Buffer, name: str, start: int, stop: int) -> None:
    header = elf_header(data)
    if header[11] == ELFLayout.of(header).parser("section").size and 0 < header[13] < header[12]:
        sections = section_headers(data, header)
        strings = sections[header[13]]
        checked_range(data, strings[4], strings[5])
        for section in sections:
            if section[1] != 1 or not section[2] & SHF_EXECINSTR:
                continue
            if section[0] >= strings[5]:
                continue
            offset = strings[4] + section[0]
            value = data[
                offset : min(offset + len(name.encode("utf-8")) + 1, strings[4] + strings[5])
            ]
            if (
                value == name.encode("utf-8") + b"\0"
                and section[3] <= start < stop <= section[3] + section[5]
            ):
                return
    message = "Requested section does not contain the executable address range"
    raise TriageError(message)


def fragment_command(  # noqa: PLR0913, PLR0917 -- Bound original addresses to a small tool input.
    report: dict,
    data: Buffer,
    directory: Path,
    objdump: Path,
    start: int,
    stop: int,
    *,
    thumb: bool = False,
) -> list[str]:
    header = elf_header(data)
    mode_architecture = require_supported_instruction_mode(data)
    if thumb and header[2] != EM_ARM:
        message = "--thumb requires an ARM ELF"
        raise TriageError(message)
    offset = function_offset(data, header, start, stop - start)
    if offset is None:
        message = "Code fragment is outside file-backed executable data"
        raise TriageError(message)
    code = data[offset : offset + stop - start]
    path = directory / f"code-{len(report['tool']['fragments'])}.bin"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(code)
    report["tool"]["fragments"].append(
        {
            "path": str(path),
            "sha256": hashlib.sha256(code).hexdigest(),
            "file_offset": offset,
            "start_address": start,
            "stop_address": stop,
            "size_bytes": len(code),
            "ephemeral": True,
        }
    )
    architecture = mode_architecture or TARGETS[target_identity(header)][1]
    return [
        str(objdump),
        "--disassemble-all",
        "--wide",
        "--target=binary",
        f"--architecture={architecture}",
        f"--endian={ELFLayout.of(header).byteorder}",
        *(["--disassembler-options=force-thumb"] if thumb else []),
        f"--adjust-vma=0x{start:x}",
        str(path),
    ]


def collect_ranges(  # noqa: C901, PLR0912, PLR0913, PLR0915, PLR0917 -- Bounded orchestration.
    report: dict,
    args: argparse.Namespace,
    mode: str,
    data: Buffer,
    objdump: Path,
    directory: Path,
    deadline: float,
) -> tuple[int, dict]:
    output_left = args.max_output_bytes
    if mode == "analysis_report":
        try:
            ranges, reasons, metadata = analysis_report_ranges(
                data, args.analysis_report, args.max_report_ranges, args.max_range_bytes
            )
        except TriageError as error:
            report["collection"]["reasons"].append(str(error))
            return 3, report
        report["evidence"]["analysis_report"] = metadata
        report["collection"]["reasons"].extend(reasons)
        report["scope"]["selected_ranges"] = len(ranges)
        for index, selected in enumerate(ranges):
            if output_left <= 0 or time.monotonic() >= deadline:
                report["collection"]["reasons"].append(
                    "Global objdump time/output budget exhausted; report ranges omitted"
                )
                report["collection"]["omitted_report_ranges"] = len(ranges) - index
                break
            command = fragment_command(
                report,
                data,
                directory,
                objdump,
                selected["start_address"],
                selected["stop_address"],
            )
            used = command_evidence(
                report,
                command,
                {"mode": "analysis_report", **selected},
                deadline,
                output_left,
            )
            output_left -= used
    elif mode != "symbols":
        try:
            start, stop = explicit_range(data, args, mode)
        except TriageError as error:
            report["collection"]["reasons"].append(str(error))
            return 3, report
        report["scope"].update(start_address=start, stop_address=stop)
        if mode == "file_offset_range":
            report["scope"].update(file_offset=args.file_offset, length=args.length)
        if args.section:
            require_section(data, args.section, start, stop)
            report["scope"]["section"] = args.section
        command = fragment_command(report, data, directory, objdump, start, stop, thumb=args.thumb)
        used = command_evidence(report, command, dict(report["scope"]), deadline, output_left)
        output_left -= used
    else:
        try:
            relevant, symbol_reason = relevant_symbols(data, deadline, args.max_symbols + 1)
        except ValueError as error:
            relevant, symbol_reason = [], f"Cannot inspect ELF symbols: {error}"
        relevant = sorted(relevant, key=symbol_priority)
        report["evidence"]["symbols"] = relevant[: args.max_symbols]
        if symbol_reason is not None:
            report["collection"]["reasons"].append(symbol_reason)
        if unsupported_mips_symbol_reason(symbol_reason):
            return 3, report
        if len(relevant) > args.max_symbols:
            report["collection"]["reasons"].append("Relevant symbol limit reached")
        defined = [symbol for symbol in relevant[: args.max_symbols] if symbol["defined"]]
        if not defined:
            report["collection"]["reasons"].append(
                "No defined patch-bearing symbols; use an explicit trusted address "
                "or file-offset range"
            )
        block_classes = {
            match.group(1)
            for symbol in defined
            if (match := PATCH_SYMBOL.match(symbol["base_name"])) is not None
        }
        missing_classes = sorted({"Literal", "Command", "Distance"} - block_classes)
        if missing_classes:
            report["collection"]["reasons"].append(
                "Missing defined block-switch classes: " + ", ".join(missing_classes)
            )
        if not any(PROCESS_SYMBOL.match(symbol["base_name"]) for symbol in defined):
            report["collection"]["reasons"].append(
                "No defined ProcessCommands symbol; patch-status propagation scope is incomplete"
            )
        for index, symbol in enumerate(defined):
            if output_left <= 0 or time.monotonic() >= deadline:
                report["collection"]["reasons"].append(
                    "Global objdump time/output budget exhausted; selected symbols omitted"
                )
                report["collection"]["omitted_symbols"] = [item["name"] for item in defined[index:]]
                break
            size = symbol["size_bytes"]
            if not 0 < size <= args.max_range_bytes:
                report["collection"]["reasons"].append(
                    f"Symbol {symbol['name']} has no bounded size within --max-range-bytes"
                )
                continue
            start, stop = symbol["address"], symbol["address"] + size
            try:
                validate_address_range(data, start, stop)
            except TriageError as error:
                report["collection"]["reasons"].append(f"Symbol {symbol['name']}: {error}")
                continue
            command = fragment_command(
                report, data, directory, objdump, start, stop, thumb=symbol.get("thumb", False)
            )
            used = command_evidence(
                report,
                command,
                {
                    "mode": "symbol",
                    "name": symbol["name"],
                    "start_address": start,
                    "stop_address": stop,
                    "size_bytes": size,
                },
                deadline,
                output_left,
            )
            output_left -= used
    if report["evidence"]["disassembly"] and not report["collection"]["reasons"]:
        report["collection"].update(status="evidence_collected", incomplete=False)
        return 0, report
    report["collection"]["next_request"] = (
        "Provide a trusted linker/map-derived --start-address/--stop-address, or an executable "
        "--file-offset/--length; keep the range within the reported limits."
    )
    return 3, report


def collect(args: argparse.Namespace, parser: argparse.ArgumentParser) -> tuple[int, dict]:
    path = args.target.expanduser().absolute()
    report = base_report(path, args)
    mode = validate_scope(parser, args)
    report["scope"]["mode"] = mode
    try:
        objdump = trusted_objdump(args.objdump)
        report["tool"]["path"] = str(objdump)
        with read_target(path, args.max_file_bytes) as data:
            report["target"].update(sha256=sha256_data(data), size_bytes=len(data))
            deadline = time.monotonic() + args.timeout_seconds
            try:
                executable_ranges(data)
                require_supported_instruction_mode(data, deadline, args.max_symbols + 1)
            except ValueError as error:
                report["collection"]["reasons"].append(f"Unsupported or malformed ELF: {error}")
                return 3, report
            with tempfile.TemporaryDirectory(prefix="brotli-triage-") as directory:
                code, report = collect_ranges(
                    report, args, mode, data, objdump, Path(directory), deadline
                )
    except (TriageError, OSError) as error:
        report["collection"]["reasons"].append(str(error))
        report["collection"].update(status="incomplete", incomplete=True)
        return 3, report
    else:
        return code, report


def write_new_output(path: Path, rendered: str, forbidden: list[str | None]) -> None:
    destination = path.expanduser().absolute()
    if any(
        item is not None and destination == Path(item).expanduser().absolute() for item in forbidden
    ):
        message = "--output cannot alias the target or objdump"
        raise TriageError(message)
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(rendered)
    except OSError as error:
        message = f"--output must be a new file and cannot alias the target or objdump: {error}"
        raise TriageError(message) from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path, help="one local ELF regular file (symlinks rejected)")
    parser.add_argument("--objdump", help="absolute path to trusted objdump (default: PATH lookup)")
    parser.add_argument("--output", type=Path, help="write JSON to this file instead of stdout")
    parser.add_argument("--start-address", type=nonnegative)
    parser.add_argument("--stop-address", type=nonnegative)
    parser.add_argument("--section", help="section constraint for an explicit address range")
    parser.add_argument("--file-offset", type=nonnegative)
    parser.add_argument("--length", type=positive)
    parser.add_argument(
        "--analysis-report",
        type=Path,
        help="finalized scanner JSON whose SHA-bound executable windows should be triaged",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=positive,
        default=DEFAULT_MAX_FILE_BYTES,
        help="optional file byte limit; no default size cap",
    )
    parser.add_argument("--max-output-bytes", type=positive, default=DEFAULT_MAX_OUTPUT_BYTES)
    parser.add_argument("--max-range-bytes", type=positive, default=DEFAULT_MAX_RANGE_BYTES)
    parser.add_argument("--timeout-seconds", type=positive, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--max-symbols", type=positive, default=DEFAULT_MAX_SYMBOLS)
    parser.add_argument("--max-report-ranges", type=positive, default=DEFAULT_MAX_REPORT_RANGES)
    parser.add_argument(
        "--thumb", action="store_true", help="decode an explicit ARM range as Thumb code"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        code, report = collect(args, parser)
    except TriageError as error:
        report = base_report(args.target.expanduser().absolute(), args)
        report["collection"]["reasons"].append(str(error))
        code = 3
    rendered = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    if args.output is None:
        print(rendered, end="")
    else:
        try:
            write_new_output(
                args.output,
                rendered,
                [
                    report["target"]["path"],
                    report["tool"]["path"],
                    str(args.analysis_report) if args.analysis_report is not None else None,
                ],
            )
        except TriageError as error:
            parser.error(str(error))
    return code


# gremlin: pardon[out_of_scope] CLI bootstrap guard; imports must not launch argparse.
if __name__ == "__main__":
    sys.exit(main())
