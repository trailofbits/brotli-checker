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
    EM_AARCH64,
    PROGRAM_HEADER,
    SECTION_HEADER,
    checked_slice,
    elf_header,
    executable_ranges,
)
from brotli_binary_metadata import MAX_SYMBOL_TABLES, MAX_SYMBOLS, SYMBOL

if TYPE_CHECKING:
    from collections.abc import Generator

DEFAULT_MAX_FILE_BYTES = None
DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024
DEFAULT_MAX_RANGE_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_MAX_SYMBOLS = 12
CHUNK_BYTES = 64 * 1024
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
    table = checked_slice(data, header[5], header[9] * header[10])
    for kind, flags, start, virtual, _, file_size, _, _ in PROGRAM_HEADER.iter_unpack(table):
        if (
            kind == PT_LOAD
            and flags & PF_X
            and virtual <= address < address + size <= virtual + file_size
        ):
            return start + address - virtual
    return None


def relevant_symbols(  # noqa: C901, PLR0911, PLR0912, PLR0915 -- Bounded ELF validation.
    data: Buffer, deadline: float, candidate_limit: int = DEFAULT_MAX_SYMBOLS + 1
) -> tuple[list[dict], str | None]:
    """Select relevant defined/imported functions from bounded in-file ELF tables."""
    header = elf_header(data)
    if not header[12]:
        return [], "No ELF section table; symbol-based triage is unavailable"
    if header[11] != SECTION_HEADER.size:
        return [], "Unsupported ELF section table"
    sections = list(
        SECTION_HEADER.iter_unpack(checked_slice(data, header[6], header[12] * header[11]))
    )
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
        if table[9] != SYMBOL.size or table[5] % SYMBOL.size or table[6] >= len(sections):
            return [*defined_symbols, *imported_symbols], "Malformed ELF symbol table"
        scanned += table[5] // SYMBOL.size
        if scanned > MAX_SYMBOLS:
            return [*defined_symbols, *imported_symbols], "ELF symbol limit reached"
        names = sections[table[6]]
        if names[1] != SHT_STRTAB:
            return [*defined_symbols, *imported_symbols], (
                "ELF symbols do not reference a string table"
            )
        name_start, name_stop = checked_range(data, names[4], names[5])
        entry_start, entry_stop = checked_range(data, table[4], table[5])
        entries = data[entry_start:entry_stop]
        for name_offset, info, _, index, address, size in SYMBOL.iter_unpack(entries):
            if time.monotonic() >= deadline:
                return [*defined_symbols, *imported_symbols], "ELF symbol scan timeout reached"
            if info & 0xF != STT_FUNC or name_offset >= names[5]:
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


def file_offset_address(data: Buffer, file_offset: int, length: int) -> int:
    header = elf_header(data)
    table = checked_slice(data, header[5], header[9] * header[10])
    for kind, flags, start, virtual, _, file_size, _, _ in PROGRAM_HEADER.iter_unpack(table):
        if (
            kind == PT_LOAD
            and flags & PF_X
            and start <= file_offset
            and file_offset + length <= start + file_size
        ):
            return virtual + file_offset - start
    message = "File-offset range is not inside one file-backed executable PT_LOAD segment"
    raise TriageError(message)


def validate_address_range(data: Buffer, start: int, stop: int) -> None:
    header = elf_header(data)
    table = checked_slice(data, header[5], header[9] * header[10])
    for kind, flags, _, virtual, _, file_size, _, _ in PROGRAM_HEADER.iter_unpack(table):
        if kind == PT_LOAD and flags & PF_X and virtual <= start < stop <= virtual + file_size:
            return
    message = "Address range is not inside one file-backed executable PT_LOAD segment"
    raise TriageError(message)


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
        },
        "collection": {"status": "incomplete", "incomplete": True, "reasons": []},
        "classification": {
            "patch_status": "unknown",
            "reason": (
                "Disassembly requires model comparison with reviewed source; no automatic verdict"
            ),
        },
        "evidence": {"symbols": [], "disassembly": []},
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
    if (args.start_address is None) != (args.stop_address is None):
        parser.error("--start-address and --stop-address must be supplied together")
    if (args.file_offset is None) != (args.length is None):
        parser.error("--file-offset and --length must be supplied together")
    if address_range and offset_range:
        parser.error("address and file-offset ranges are mutually exclusive")
    if args.section is not None and not address_range:
        parser.error("--section requires an explicit address range")
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
    if header[11] == SECTION_HEADER.size and 0 < header[13] < header[12]:
        sections = list(
            SECTION_HEADER.iter_unpack(checked_slice(data, header[6], header[12] * header[11]))
        )
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
    report: dict, data: Buffer, directory: Path, objdump: Path, start: int, stop: int
) -> list[str]:
    header = elf_header(data)
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
    architecture = "aarch64" if header[2] == EM_AARCH64 else "i386:x86-64"
    return [
        str(objdump),
        "--disassemble-all",
        "--wide",
        "--target=binary",
        f"--architecture={architecture}",
        "--endian=little",
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
    if mode != "symbols":
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
        command = fragment_command(report, data, directory, objdump, start, stop)
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
            command = fragment_command(report, data, directory, objdump, start, stop)
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
            try:
                executable_ranges(data)
            except ValueError as error:
                report["collection"]["reasons"].append(f"Unsupported or malformed ELF: {error}")
                return 3, report
            deadline = time.monotonic() + args.timeout_seconds
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
        "--max-file-bytes",
        type=positive,
        default=DEFAULT_MAX_FILE_BYTES,
        help="optional file byte limit; no default size cap",
    )
    parser.add_argument("--max-output-bytes", type=positive, default=DEFAULT_MAX_OUTPUT_BYTES)
    parser.add_argument("--max-range-bytes", type=positive, default=DEFAULT_MAX_RANGE_BYTES)
    parser.add_argument("--timeout-seconds", type=positive, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--max-symbols", type=positive, default=DEFAULT_MAX_SYMBOLS)
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
                [report["target"]["path"], report["tool"]["path"]],
            )
        except TriageError as error:
            parser.error(str(error))
    return code


# gremlin: pardon[out_of_scope] CLI bootstrap guard; imports must not launch argparse.
if __name__ == "__main__":
    sys.exit(main())
