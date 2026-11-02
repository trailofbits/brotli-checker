#!/usr/bin/env python3
# ruff: noqa: C901, EM101, PLR0913, PLR0917, TRY003, TRY301
"""Create one bounded, hash- and UUID-bound Mach dSYM function packet."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))
sys.path.insert(0, str(ROOT / "scripts"))

from brotli_binary_layout import inspect_layout  # noqa: E402
from brotli_binary_triage import run_bounded  # noqa: E402
from brotli_debug_companions import mach_companion_slices, verify_mach_debug_export  # noqa: E402
from export_pdb_symbols import (  # noqa: E402
    copy_buffer,
    sha256_buffer,
    sha256_file,
    stable_data,
    write_text_new,
)

if TYPE_CHECKING:
    from brotli_binary_data import Buffer

MAX_TOOL_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_FUNCTIONS = 100_000
MAX_VERSION_BYTES = 16 * 1024
DIE = re.compile(r"^\s*0x[0-9a-fA-F]+:\s+(DW_TAG_[A-Za-z0-9_]+)\b")
ATTRIBUTE = re.compile(r"^\s*(DW_AT_[A-Za-z0-9_]+)\s+\((.*)\)\s*$")
QUOTED = re.compile(r'^"(.*)"$')
HEX = re.compile(r"^0x([0-9a-fA-F]+)(?:\s.*)?$")
DECIMAL = re.compile(r"^(\d+)(?:\s.*)?$")
ARCH_NAMES = {"aarch64": "arm64", "x86_64": "x86_64"}


def trusted_tool(value: str) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        raise ValueError("--llvm-dwarfdump must be an absolute trusted path")
    resolved = candidate.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise ValueError("--llvm-dwarfdump must resolve to an executable regular file")
    return resolved


def sha256_range(data: Buffer, offset: int, size: int) -> str:
    digest = hashlib.sha256()
    for cursor in range(offset, offset + size, 1024 * 1024):
        digest.update(data[cursor : min(offset + size, cursor + 1024 * 1024)])
    return digest.hexdigest()


def run_tool(command: list[str], timeout: float, maximum: int) -> str:
    result = run_bounded(command, timeout, maximum)
    if result["reason"] is not None or result["returncode"] != 0:
        reason = result["reason"] or f"llvm-dwarfdump exited {result['returncode']}"
        raise ValueError(reason)
    output = result["output"]
    if not isinstance(output, str):
        raise ValueError(  # noqa: TRY004 -- One malformed bounded-runner result type.
            "llvm-dwarfdump returned a non-text result"
        )
    return output


def _attribute_value(value: str, pattern: re.Pattern[str]) -> str | None:
    match = pattern.fullmatch(value.strip())
    return match[1] if match is not None else None


def parse_subprograms(text: str, maximum: int = MAX_FUNCTIONS) -> list[dict[str, Any]]:
    """Parse resolved llvm-dwarfdump subprogram DIEs without opening source paths."""
    result = []
    current: dict[str, str] | None = None

    def finish() -> None:
        nonlocal current
        if current is None:
            return
        required = {
            "DW_AT_name",
            "DW_AT_low_pc",
            "DW_AT_high_pc",
            "DW_AT_decl_file",
            "DW_AT_decl_line",
        }
        if required <= current.keys():
            name = _attribute_value(current["DW_AT_name"], QUOTED)
            source = _attribute_value(current["DW_AT_decl_file"], QUOTED)
            low = _attribute_value(current["DW_AT_low_pc"], HEX)
            high = _attribute_value(current["DW_AT_high_pc"], HEX)
            line = _attribute_value(current["DW_AT_decl_line"], DECIMAL)
            if all(value is not None for value in (name, source, low, high, line)):
                name = cast("str", name)
                source = cast("str", source)
                low = cast("str", low)
                high = cast("str", high)
                line = cast("str", line)
                address = int(low, 16)
                high_value = int(high, 16)
                source_name = str(source).replace("\\", "/").rsplit("/", 1)[-1]
                if (
                    str(name)
                    and source_name not in ("", ".", "..")
                    and high_value > address
                    and int(line) > 0
                ):
                    item = {
                        "name": str(name),
                        "address": address,
                        "size": high_value - address,
                        "source_file": source_name,
                        "source_line": int(line),
                    }
                    if item not in result:
                        if len(result) >= maximum:
                            raise ValueError("llvm-dwarfdump function population exceeds limit")
                        result.append(item)
        current = None

    for line in text.splitlines():
        die = DIE.match(line)
        if die is not None:
            finish()
            current = {} if die[1] == "DW_TAG_subprogram" else None
            continue
        if current is None:
            continue
        attribute = ATTRIBUTE.match(line)
        if attribute is not None and attribute[1] not in current:
            current[attribute[1]] = attribute[2]
    finish()
    return sorted(result, key=lambda item: (item["address"], item["name"]))


def selected_slice(data: Buffer, machine: str) -> dict[str, Any]:
    layout = inspect_layout(data)
    values = layout.get("slices", []) if layout.get("kind") == "mach_o_universal" else [layout]
    selected = [value for value in values if value.get("machine") == machine]
    if len(selected) != 1 or selected[0].get("gaps"):
        raise ValueError("Mach architecture is unavailable, ambiguous, or incomplete")
    value = selected[0]
    identities = [
        item["uuid"]
        for item in value.get("debug_identities", [])
        if item.get("kind") == "mach_uuid"
    ]
    if len(identities) != 1:
        raise ValueError("Mach architecture lacks one UUID")
    return {
        **value,
        "uuid": identities[0],
        "slice_offset": value.get("slice_offset", 0),
        "slice_size": value.get("slice_size", len(data)),
    }


def selected_companion_slice(data: Buffer, machine: str) -> dict[str, Any]:
    selected = [value for value in mach_companion_slices(data) if value["machine"] == machine]
    if len(selected) != 1:
        raise ValueError("Mach debug companion architecture is unavailable or ambiguous")
    return selected[0]


def packet(
    artifact: Buffer,
    dsym: Buffer,
    machine: str,
    tool: Path,
    version: str,
    functions: list[dict[str, Any]],
) -> dict[str, Any]:
    artifact_slice = selected_slice(artifact, machine)
    dsym_slice = selected_companion_slice(dsym, machine)
    if (artifact_slice["uuid"], artifact_slice.get("cpu_subtype")) != (
        dsym_slice["uuid"],
        dsym_slice.get("cpu_subtype"),
    ):
        raise ValueError("Artifact and dSYM architecture identities differ")
    return {
        "schema_version": 1,
        "format": "llvm-dwarfdump-symbols-v1",
        "artifact_sha256": sha256_buffer(artifact),
        "dsym_sha256": sha256_buffer(dsym),
        "slice": {
            "uuid": artifact_slice["uuid"],
            "machine": machine,
            "cpu_subtype": artifact_slice["cpu_subtype"],
            "artifact_offset": artifact_slice["slice_offset"],
            "artifact_size": artifact_slice["slice_size"],
            "artifact_slice_sha256": sha256_range(
                artifact, artifact_slice["slice_offset"], artifact_slice["slice_size"]
            ),
            "dsym_offset": dsym_slice["slice_offset"],
            "dsym_size": dsym_slice["slice_size"],
            "dsym_slice_sha256": sha256_range(
                dsym, dsym_slice["slice_offset"], dsym_slice["slice_size"]
            ),
        },
        "generator": {
            "name": "llvm-dwarfdump",
            "version": version,
            "sha256": sha256_file(tool),
        },
        "functions": functions,
    }


def positive(value: str) -> float:
    result = float(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("dsym", type=Path, help="explicit dSYM DWARF Mach-O file")
    parser.add_argument("--machine", choices=sorted(ARCH_NAMES), required=True)
    parser.add_argument("--llvm-dwarfdump", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--diagnostic-output", type=Path)
    parser.add_argument("--timeout", type=positive, default=60.0)
    args = parser.parse_args()
    try:
        tool = trusted_tool(args.llvm_dwarfdump)
        with ExitStack() as stack:
            artifact = stack.enter_context(stable_data(args.artifact))
            dsym = stack.enter_context(stable_data(args.dsym))
            with tempfile.TemporaryDirectory(prefix="brotli-mach-debug-") as directory:
                copied_dsym = Path(directory) / "companion.dwarf"
                copy_buffer(dsym, copied_dsym)
                version_raw = run_tool([str(tool), "--version"], args.timeout, MAX_VERSION_BYTES)
                version = version_raw.splitlines()[0].strip()
                if not version:
                    raise ValueError("llvm-dwarfdump returned no version")
                raw = run_tool(
                    [
                        str(tool),
                        "--debug-info",
                        "--arch",
                        ARCH_NAMES[args.machine],
                        str(copied_dsym),
                    ],
                    args.timeout,
                    MAX_TOOL_OUTPUT_BYTES,
                )
                diagnostic_text = raw
                if args.diagnostic_output is not None:
                    write_text_new(args.diagnostic_output, diagnostic_text)
                functions = parse_subprograms(diagnostic_text)
                if not functions:
                    raise ValueError("llvm-dwarfdump returned no complete subprogram records")
                document = packet(artifact, dsym, args.machine, tool, version, functions)
                encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
                verified = verify_mach_debug_export(artifact, dsym, encoded)
                if verified.status != "verified":
                    reason = verified.gaps[0].reason if verified.gaps else "verification failed"
                    raise ValueError(reason)
                write_text_new(args.output, encoded.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
