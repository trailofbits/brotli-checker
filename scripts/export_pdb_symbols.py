#!/usr/bin/env python3
# ruff: noqa: EM101, PLR2004, TRY003, TRY301
"""Create a bounded, hash-bound PDB function packet with trusted llvm-pdbutil."""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import re
import stat
import sys
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))

from brotli_binary_data import Buffer, sha256_data  # noqa: E402
from brotli_binary_triage import run_bounded  # noqa: E402
from brotli_debug_companions import debug_identity, verify_pdb_symbol_export  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Generator

MAX_TOOL_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_FUNCTIONS = 100_000
MAX_VERSION_OUTPUT_BYTES = 16 * 1024
PROC = re.compile(r"\bS_(?:G|L)PROC32(?:_ID|EX)?\b.*`([^`]+)`")
ADDRESS = re.compile(r"\baddr\s*=\s*([0-9A-Fa-f]+):([0-9A-Fa-f]+),\s*code size\s*=\s*(\d+)\b")
IMAGE_SCN_MEM_EXECUTE = 0x20000000


def positive(value: str) -> int:
    result = int(value, 0)
    if result <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return result


def trusted_tool(value: str) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        raise ValueError("--llvm-pdbutil must be an absolute trusted path")
    resolved = candidate.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise ValueError("--llvm-pdbutil must resolve to an executable regular file")
    return resolved


@contextmanager
def stable_data(path: Path) -> Generator[Any]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("PE/PDB inputs must be regular non-symlink files")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        signature = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if before.st_size <= 0 or signature != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ):
            raise ValueError("PE/PDB input changed while opening")
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            yield data
        after = os.fstat(stream.fileno())
        if signature != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("PE/PDB input changed while exporting symbols")


def copy_buffer(data: Buffer, path: Path) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(descriptor, "wb") as stream:
        for offset in range(0, len(data), 1024 * 1024):
            stream.write(data[offset : min(len(data), offset + 1024 * 1024)])


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def pe_sections(data: Buffer) -> list[tuple[int, int, int, int]]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("Invalid PE input")
    pe = int.from_bytes(data[0x3C:0x40], "little")
    if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\0\0":
        raise ValueError("Invalid PE signature")
    count = int.from_bytes(data[pe + 6 : pe + 8], "little")
    optional = int.from_bytes(data[pe + 20 : pe + 22], "little")
    table = pe + 24 + optional
    if not 0 < count <= 65_536 or table + count * 40 > len(data):
        raise ValueError("Invalid PE section table")
    result = []
    for index in range(count):
        offset = table + index * 40
        virtual_size = int.from_bytes(data[offset + 8 : offset + 12], "little")
        rva = int.from_bytes(data[offset + 12 : offset + 16], "little")
        raw_size = int.from_bytes(data[offset + 16 : offset + 20], "little")
        raw_offset = int.from_bytes(data[offset + 20 : offset + 24], "little")
        flags = int.from_bytes(data[offset + 36 : offset + 40], "little")
        size = min(virtual_size, raw_size)
        if raw_offset + raw_size > len(data):
            raise ValueError("PE section exceeds supplied bytes")
        result.append((rva, raw_offset, size, flags))
    return result


def parse_symbols(text: str, sections: list[tuple[int, int, int, int]]) -> list[dict]:
    functions = []
    name = None
    for line in text.splitlines():
        if match := PROC.search(line):
            name = match[1]
            continue
        if name is None or (match := ADDRESS.search(line)) is None:
            continue
        section, offset, size = int(match[1], 16), int(match[2], 16), int(match[3], 10)
        if not 0 < section <= len(sections) or size <= 0:
            raise ValueError("llvm-pdbutil function has invalid section/size")
        rva, _, section_size, flags = sections[section - 1]
        if not flags & IMAGE_SCN_MEM_EXECUTE or offset + size > section_size:
            raise ValueError("llvm-pdbutil function is outside executable PE bytes")
        functions.append({"name": name, "rva": rva + offset, "size": size})
        if len(functions) > MAX_FUNCTIONS:
            raise ValueError("llvm-pdbutil function limit reached")
        name = None
    if not functions:
        raise ValueError("llvm-pdbutil emitted no bounded procedure records")
    return functions


def tool_output(command: list[str], timeout_seconds: int, max_bytes: int) -> str:
    result = run_bounded(command, timeout_seconds, max_bytes)
    if result["limited"] or result["returncode"] != 0:
        raise ValueError(result["reason"] or f"llvm-pdbutil exited {result['returncode']}")
    return result["output"]


def write_new(path: Path, packet: dict) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(packet, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pe", type=Path)
    parser.add_argument("pdb", type=Path)
    parser.add_argument("--llvm-pdbutil", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=positive, default=30)
    parser.add_argument("--max-output-bytes", type=positive, default=MAX_TOOL_OUTPUT_BYTES)
    args = parser.parse_args(argv)
    try:
        tool = trusted_tool(args.llvm_pdbutil)
        with ExitStack() as stack:
            pe = stack.enter_context(stable_data(args.pe))
            pdb = stack.enter_context(stable_data(args.pdb))
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="pdb-export-")))
            pdb_snapshot = directory / "companion.pdb"
            copy_buffer(pdb, pdb_snapshot)
            pe_buffer, pdb_buffer = cast("Buffer", pe), cast("Buffer", pdb)
            pe_identity = debug_identity(pe_buffer).identity
            pdb_identity = debug_identity(pdb_buffer).identity
            if (
                pe_identity is None
                or pe_identity.format != "pe"
                or pdb_identity is None
                or pdb_identity.format != "pdb"
                or (pe_identity.pdb_guid, pe_identity.pdb_age)
                != (pdb_identity.pdb_guid, pdb_identity.pdb_age)
            ):
                raise ValueError("PE and PDB identities do not match")
            version = tool_output(
                [str(tool), "--version"], args.timeout_seconds, MAX_VERSION_OUTPUT_BYTES
            ).splitlines()[0]
            if not version:
                raise ValueError("llvm-pdbutil emitted no version identity")
            symbols = tool_output(
                [str(tool), "dump", "--symbols", str(pdb_snapshot)],
                args.timeout_seconds,
                args.max_output_bytes,
            )
            packet = {
                "schema_version": 1,
                "format": "llvm-pdbutil-symbols-v1",
                "pe_sha256": sha256_data(pe_buffer),
                "pdb_sha256": sha256_data(pdb_buffer),
                "pdb_identity": {"guid": pdb_identity.pdb_guid, "age": pdb_identity.pdb_age},
                "generator": {
                    "name": "llvm-pdbutil",
                    "version": version,
                    "sha256": sha256_file(tool),
                },
                "functions": parse_symbols(symbols, pe_sections(pe_buffer)),
            }
            verified = verify_pdb_symbol_export(pe_buffer, pdb_buffer, json.dumps(packet).encode())
            if verified.status != "verified":
                raise ValueError(verified.gaps[0].reason)
        write_new(args.output.expanduser().absolute(), packet)
    except (OSError, ValueError, IndexError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    sys.exit(main())
