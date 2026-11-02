# ruff: noqa: ANN001, C901, EM101, PERF401, PLR0911, PLR0912, TRY003, TRY004
"""Development-only differential observations for binary layout parsers."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from contextlib import contextmanager
from importlib.metadata import version
from pathlib import Path
from typing import TYPE_CHECKING

from brotli_binary_data import file_data
from brotli_binary_layout import inspect_layout
from brotli_binary_match import elf_header, executable_ranges, target_identity
from brotli_binary_triage import run_bounded

if TYPE_CHECKING:
    from collections.abc import Generator

MAX_ORACLE_OUTPUT_BYTES = 8 * 1024 * 1024
ORACLE_TIMEOUT_SECONDS = 30
COPY_CHUNK_BYTES = 1024 * 1024
PARSER_MEMORY_BYTES = 512 * 1024 * 1024


def _scanner_observation(data) -> dict:
    if data.startswith(b"\x7fELF"):
        try:
            header = elf_header(data)
            machine, bits, byteorder = target_identity(header)
            _, ranges = executable_ranges(data)
        except (IndexError, OSError, ValueError) as error:
            return {"parser": "brotli-checker", "status": "rejected", "reason": str(error)}
        return {
            "parser": "brotli-checker",
            "status": "parsed",
            "kind": "elf",
            "machine": machine,
            "bits": bits,
            "byteorder": byteorder,
            "executable_ranges": [list(item) for item in ranges],
        }
    layout = inspect_layout(data)
    if layout["kind"] == "unknown":
        return {"parser": "brotli-checker", "status": "unsupported"}
    malformed = [gap for gap in layout["gaps"] if gap.startswith("Malformed or unsupported")]
    return {
        "parser": "brotli-checker",
        "status": "rejected" if malformed else "parsed",
        "kind": layout["kind"],
        "machine": layout["machine"],
        "bits": layout["bits"],
        "byteorder": layout["byteorder"],
        "executable_ranges": [
            [item["file_offset"], item["size"]] for item in layout["ranges"]["executable"]
        ],
        "gaps": layout["gaps"],
    }


def scanner_observation(path: Path) -> dict:
    with path.open("rb") as stream, file_data(stream, None) as data:
        return _scanner_observation(data)


def lief_observation(path: Path) -> dict:
    try:
        import lief  # noqa: PLC0415 -- Development-only optional oracle.
    except ImportError as error:
        return {"parser": "lief", "status": "unavailable", "reason": str(error)}
    try:
        parsed = lief.parse(path)
    except (RuntimeError, ValueError) as error:
        return {"parser": "lief", "status": "error", "reason": str(error)}
    if parsed is None:
        return {"parser": "lief", "status": "rejected"}
    module = Path(lief.__file__).resolve(strict=True)
    identity = {
        "lief_version": version("lief"),
        "lief_module_path": str(module),
        "lief_module_sha256": _hash_path(module),
    }
    if isinstance(parsed, lief.ELF.Binary):
        return {
            "parser": "lief",
            "status": "parsed",
            "kind": "elf",
            **identity,
            "machine": parsed.header.machine_type.value,
            "bits": 64 if parsed.header.identity_class.name == "ELF64" else 32,
            "byteorder": "little" if parsed.header.identity_data.name == "LSB" else "big",
            "executable_ranges": sorted(
                [segment.file_offset, segment.physical_size]
                for segment in parsed.segments
                if segment.type == lief.ELF.Segment.TYPE.LOAD
                and int(segment.flags) & int(lief.ELF.Segment.FLAGS.X)
                and segment.physical_size
            ),
        }
    if isinstance(parsed, lief.PE.Binary):
        kind = "pe"
    elif isinstance(parsed, lief.MachO.Binary):
        kind = "mach_o"
    elif isinstance(parsed, lief.COFF.Binary):
        kind = "coff"
    else:
        kind = "unknown"
    return {"parser": "lief", "status": "parsed", "kind": kind, **identity}


def isolated_observation(path: Path, parser: str, worker: Path) -> dict:
    completed = run_bounded(
        [
            sys.executable,
            str(worker),
            parser,
            str(path),
            "--memory-bytes",
            str(PARSER_MEMORY_BYTES),
        ],
        ORACLE_TIMEOUT_SECONDS,
        MAX_ORACLE_OUTPUT_BYTES,
    )
    if completed["limited"]:
        return {"parser": parser, "status": "error", "reason": completed["reason"]}
    if completed["returncode"] != 0:
        return {
            "parser": parser,
            "status": "error",
            "reason": f"isolated worker exited {completed['returncode']}",
            "output_sha256": hashlib.sha256(completed["output"].encode()).hexdigest(),
        }
    try:
        result = json.loads(completed["output"])
    except json.JSONDecodeError:
        return {"parser": parser, "status": "error", "reason": "worker output was not JSON"}
    if not isinstance(result, dict) or result.get("parser") not in {parser, "brotli-checker"}:
        return {"parser": parser, "status": "error", "reason": "invalid worker observation"}
    result["worker_sha256"] = _hash_path(worker)
    result["oracle_module_sha256"] = _hash_path(Path(__file__))
    result["memory_bytes"] = PARSER_MEMORY_BYTES
    return result


def _trusted_tool(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("LLVM oracle path must be absolute")
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise ValueError("LLVM oracle must be an executable regular file")
    return resolved


def _llvm_scalar(value: object) -> object:
    if isinstance(value, dict):
        return value.get("Value", value.get("Name"))
    return value


def _llvm_integer(value: object) -> int | None:
    value = _llvm_scalar(value)
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _llvm_name(value: object) -> str:
    if not isinstance(value, dict):
        return str(value)
    name = value.get("Name")
    if isinstance(name, str):
        return name
    flags = value.get("Flags")
    if isinstance(flags, list):
        return " ".join(str(item.get("Name", "")) for item in flags if isinstance(item, dict))
    return ""


def _llvm_summary(document: object) -> dict:
    if isinstance(document, list) and len(document) == 1:
        document = document[0]
    if not isinstance(document, dict) or not isinstance(document.get("FileSummary"), dict):
        raise ValueError("LLVM JSON lacks one FileSummary object")
    summary = document["FileSummary"]
    output = {"kind": "elf"}
    format_name = str(_llvm_scalar(summary.get("Format", ""))).lower()
    if not format_name.startswith("elf"):
        raise ValueError("LLVM JSON is not an ELF observation")
    if "64" in format_name:
        output["bits"] = 64
    elif "32" in format_name:
        output["bits"] = 32
    if "little" in format_name:
        output["byteorder"] = "little"
    elif "big" in format_name:
        output["byteorder"] = "big"
    elf_header = document.get("ElfHeader")
    if isinstance(elf_header, dict):
        identity = elf_header.get("Ident")
        if isinstance(identity, dict):
            elf_class = _llvm_integer(identity.get("Class"))
            encoding = _llvm_integer(identity.get("DataEncoding"))
            if elf_class in (1, 2):
                output["bits"] = 32 if elf_class == 1 else 64
            if encoding in (1, 2):
                output["byteorder"] = "little" if encoding == 1 else "big"
        machine = _llvm_integer(elf_header.get("Machine"))
        if machine is not None:
            output["machine"] = machine
    ranges = []
    headers = document.get("ProgramHeaders")
    if isinstance(headers, list):
        for header in headers:
            if not isinstance(header, dict):
                continue
            row = (
                header["ProgramHeader"] if isinstance(header.get("ProgramHeader"), dict) else header
            )
            kind = _llvm_name(row.get("Type", "")).upper()
            kind_value = _llvm_integer(row.get("Type"))
            flags = row.get("Flags")
            flag_name = _llvm_name(flags).upper()
            flag_value = _llvm_integer(flags)
            if not ("LOAD" in kind or kind_value == 1) or not (
                "X" in flag_name or (flag_value is not None and flag_value & 1)
            ):
                continue
            offset = _llvm_integer(row.get("Offset"))
            size = _llvm_integer(row.get("FileSize"))
            if offset is not None and size is not None and size > 0:
                ranges.append([offset, size])
        output["executable_ranges"] = sorted(ranges)
    return output


def llvm_observation(path: Path, llvm_readobj: Path | None) -> dict:
    if llvm_readobj is None:
        return {"parser": "llvm-readobj", "status": "unavailable"}
    tool = _trusted_tool(llvm_readobj)
    tool_sha256 = _hash_path(tool)
    version = run_bounded([str(tool), "--version"], ORACLE_TIMEOUT_SECONDS, MAX_ORACLE_OUTPUT_BYTES)
    if version["limited"] or version["returncode"] != 0:
        return {
            "parser": "llvm-readobj",
            "status": "error",
            "reason": "Cannot identify LLVM oracle version",
        }
    version_line = next(
        (line.strip() for line in version["output"].splitlines() if "LLVM version" in line),
        "",
    )
    if not version_line:
        return {
            "parser": "llvm-readobj",
            "status": "error",
            "reason": "LLVM oracle version output was unrecognized",
        }
    completed = run_bounded(
        [
            str(tool),
            "--elf-output-style=JSON",
            "--file-headers",
            "--program-headers",
            "--sections",
            str(path),
        ],
        ORACLE_TIMEOUT_SECONDS,
        MAX_ORACLE_OUTPUT_BYTES,
    )
    result = {
        "parser": "llvm-readobj",
        "tool_path": str(tool),
        "tool_sha256": tool_sha256,
        "tool_version": version_line,
        "tool_version_output_sha256": hashlib.sha256(version["output"].encode()).hexdigest(),
        "returncode": completed["returncode"],
        "output_sha256": hashlib.sha256(completed["output"].encode()).hexdigest(),
    }
    if _hash_path(tool) != tool_sha256:
        return {**result, "status": "error", "reason": "LLVM oracle changed during execution"}
    if completed["limited"]:
        return {**result, "status": "error", "reason": completed["reason"]}
    if completed["returncode"] != 0:
        return {**result, "status": "rejected", "reason": completed["output"].strip()}
    try:
        fields = _llvm_summary(json.loads(completed["output"]))
    except (json.JSONDecodeError, ValueError) as error:
        return {**result, "status": "error", "reason": str(error)}
    return {**result, "status": "parsed", **fields}


def compare_observations(scanner: dict, *oracles: dict) -> list[dict]:
    differences = []
    for oracle in oracles:
        if oracle["status"] in {"unavailable", "error"}:
            differences.append(
                {
                    "kind": "oracle_inconclusive",
                    "oracle": oracle["parser"],
                    "status": oracle["status"],
                }
            )
            continue
        if scanner["status"] == "unsupported" and oracle["status"] == "parsed":
            differences.append({"kind": "scanner_coverage_gap", "oracle": oracle["parser"]})
            continue
        scanner_accepts = scanner["status"] == "parsed"
        oracle_accepts = oracle["status"] == "parsed"
        if scanner_accepts != oracle_accepts:
            differences.append(
                {
                    "kind": "acceptance_disagreement",
                    "oracle": oracle["parser"],
                    "scanner_status": scanner["status"],
                    "oracle_status": oracle["status"],
                }
            )
            continue
        if not scanner_accepts or "kind" not in oracle:
            continue
        if scanner["kind"] != oracle["kind"]:
            differences.append(
                {
                    "kind": "format_disagreement",
                    "oracle": oracle["parser"],
                    "scanner_value": scanner["kind"],
                    "oracle_value": oracle["kind"],
                }
            )
        for field in ("machine", "bits", "byteorder", "executable_ranges"):
            if field in oracle and scanner.get(field) != oracle[field]:
                differences.append(
                    {
                        "kind": "field_disagreement",
                        "oracle": oracle["parser"],
                        "field": field,
                        "scanner_value": scanner.get(field),
                        "oracle_value": oracle[field],
                    }
                )
    return differences


def _signature(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(COPY_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def stable_snapshot(source: Path, directory: Path) -> Generator[tuple[Path, str, int], None, None]:
    source = source.expanduser().absolute()
    before = source.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("Parser fixture must be a regular non-symlink file")
    snapshot = directory / hashlib.sha256(str(source).encode()).hexdigest()
    digest = hashlib.sha256()
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if _signature(before) != _signature(opened):
            raise ValueError("Parser fixture changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as incoming, snapshot.open("xb") as output:
            while chunk := incoming.read(COPY_CHUNK_BYTES):
                output.write(chunk)
                digest.update(chunk)
        after = os.fstat(descriptor)
        if _signature(opened) != _signature(after):
            raise ValueError("Parser fixture changed while copying")
        yield snapshot, digest.hexdigest(), opened.st_size
    finally:
        os.close(descriptor)


def inspect_fixture(
    snapshot: Path,
    sha256: str,
    size: int,
    llvm_readobj: Path | None,
    worker: Path | None = None,
) -> dict:
    scanner = (
        isolated_observation(snapshot, "scanner", worker)
        if worker is not None
        else scanner_observation(snapshot)
    )
    lief = (
        isolated_observation(snapshot, "lief", worker)
        if worker is not None
        else lief_observation(snapshot)
    )
    llvm = llvm_observation(snapshot, llvm_readobj)
    differences = compare_observations(scanner, lief, llvm)
    disagreement = any(item["kind"].endswith("disagreement") for item in differences)
    return {
        "sha256": sha256,
        "size": size,
        "scanner": scanner,
        "oracles": [lief, llvm],
        "differences": differences,
        "status": "disagreement"
        if disagreement
        else "inconclusive"
        if differences
        else "agreement",
        "verdict_effect": "none_development_evidence_only",
    }
