#!/usr/bin/env python3
# ruff: noqa: EM101, PLR2004, TRY003, TRY301
"""Create a bounded, hash-bound PDB function packet with trusted llvm-pdbutil."""

from __future__ import annotations

import argparse
import ctypes
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

from brotli_binary_triage import run_bounded  # noqa: E402
from brotli_debug_companions import debug_identity, verify_pdb_symbol_export  # noqa: E402

if TYPE_CHECKING:
    from collections.abc import Generator

    from brotli_binary_data import Buffer

MAX_TOOL_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_FUNCTIONS = 100_000
MAX_VERSION_OUTPUT_BYTES = 16 * 1024
PROC = re.compile(r"\bS_(?:G|L)PROC32(?:_ID|EX)?\b.*`([^`]+)`")
ADDRESS = re.compile(r"\baddr\s*=\s*([0-9A-Fa-f]+):([0-9A-Fa-f]+),\s*code size\s*=\s*(\d+)\b")
IMAGE_SCN_MEM_EXECUTE = 0x20000000
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_SHARE_ALL = 0x00000007
OPEN_EXISTING = 3


class MappedBuffer:
    """Minimal bytes-compatible sparse view over one read-only mmap."""

    def __init__(self, data: mmap.mmap) -> None:
        self.data = data
        self.position = 0

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, key: int | slice) -> int | bytes:
        return self.data[key]

    def startswith(self, prefix: bytes, start: int = 0, end: int | None = None) -> bool:
        stop = len(self) if end is None else min(end, len(self))
        return self.data[start : start + len(prefix)] == prefix and start + len(prefix) <= stop

    def find(self, sub: bytes, start: int = 0, end: int | None = None) -> int:
        return self.data.find(sub, start, len(self) if end is None else end)

    def tell(self) -> int:
        return self.position

    def seek(self, offset: int) -> int:
        self.position = offset
        return offset

    def read(self, size: int = -1) -> bytes:
        stop = len(self) if size < 0 else min(len(self), self.position + size)
        result = self.data[self.position : stop]
        self.position = stop
        return result


def _windows_handle_identity(handle: int) -> tuple[int, int]:
    from ctypes import wintypes  # noqa: PLC0415 -- Windows-only ABI types.

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation_time", wintypes.FILETIME),
            ("access_time", wintypes.FILETIME),
            ("write_time", wintypes.FILETIME),
            ("volume_serial", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    value = ByHandleFileInformation()
    kernel32 = cast("Any", ctypes).windll.kernel32
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(ByHandleFileInformation)]
    get_information.restype = wintypes.BOOL
    if not get_information(handle, ctypes.byref(value)):
        error = cast("Any", ctypes).WinError()
        raise error
    if value.attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("PE/PDB input path is a Windows reparse point")
    return value.volume_serial, value.file_index_high << 32 | value.file_index_low


def opened_file_identity(descriptor: int) -> tuple[int, int]:
    if os.name == "nt":
        import msvcrt  # noqa: PLC0415 -- Windows-only descriptor bridge.

        return _windows_handle_identity(msvcrt.get_osfhandle(descriptor))
    metadata = os.fstat(descriptor)
    return metadata.st_dev, metadata.st_ino


def path_identity_no_follow(path: Path) -> tuple[int, int]:
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            return opened_file_identity(descriptor)
        finally:
            os.close(descriptor)
    from ctypes import wintypes  # noqa: PLC0415 -- Windows-only ABI types.

    kernel32 = cast("Any", ctypes).windll.kernel32
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0,
        FILE_SHARE_ALL,
        None,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        error = cast("Any", ctypes).WinError()
        raise error
    try:
        return _windows_handle_identity(handle)
    finally:
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        close_handle(handle)


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
    if (
        stat.S_ISLNK(metadata.st_mode)
        or getattr(metadata, "st_reparse_tag", 0)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise ValueError("PE/PDB inputs must be regular non-symlink files")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        handle_identity = opened_file_identity(stream.fileno())
        path_identity = path_identity_no_follow(path)
        if before.st_size <= 0 or handle_identity != path_identity:
            message = (
                "PE/PDB input identity changed while opening: "
                f"path={path_identity!r}, handle={handle_identity!r}"
            )
            raise ValueError(message)
        signature = (handle_identity, before.st_size, before.st_mtime_ns)
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            yield MappedBuffer(data)
        after = os.fstat(stream.fileno())
        if signature != (
            opened_file_identity(stream.fileno()),
            after.st_size,
            after.st_mtime_ns,
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


def sha256_buffer(data: Buffer) -> str:
    digest = hashlib.sha256()
    for offset in range(0, len(data), 1024 * 1024):
        digest.update(data[offset : min(len(data), offset + 1024 * 1024)])
    return digest.hexdigest()


def pe_sections(data: Buffer) -> list[tuple[int, int, int, int, int, str]]:
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
        name = data[offset : offset + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size = int.from_bytes(data[offset + 8 : offset + 12], "little")
        rva = int.from_bytes(data[offset + 12 : offset + 16], "little")
        raw_size = int.from_bytes(data[offset + 16 : offset + 20], "little")
        raw_offset = int.from_bytes(data[offset + 20 : offset + 24], "little")
        flags = int.from_bytes(data[offset + 36 : offset + 40], "little")
        if raw_offset + raw_size > len(data):
            raise ValueError("PE section exceeds supplied bytes")
        result.append((rva, raw_offset, virtual_size, raw_size, flags, name))
    return result


def parse_symbols(text: str, sections: list[tuple[int, int, int, int, int, str]]) -> list[dict]:
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
            message = (
                "llvm-pdbutil function has invalid section/size: "
                f"name={name!r}, section=0x{section:x}, offset=0x{offset:x}, "
                f"code_size={size}, section_count={len(sections)}"
            )
            raise ValueError(message)
        rva, _, virtual_size, raw_size, flags, section_name = sections[section - 1]
        file_backed_size = min(virtual_size, raw_size)
        if not flags & IMAGE_SCN_MEM_EXECUTE or offset + size > file_backed_size:
            message = (
                "llvm-pdbutil function is outside executable PE bytes: "
                f"name={name!r}, section=0x{section:x} ({section_name!r}), "
                f"offset=0x{offset:x}, code_size={size}, rva=0x{rva:x}, "
                f"virtual_size=0x{virtual_size:x}, raw_size=0x{raw_size:x}, "
                f"flags=0x{flags:08x}"
            )
            raise ValueError(message)
        functions.append({"name": name, "rva": rva + offset, "size": size})
        if len(functions) > MAX_FUNCTIONS:
            raise ValueError("llvm-pdbutil function limit reached")
        name = None
    if not functions:
        raise ValueError("llvm-pdbutil emitted no bounded procedure records")
    return functions


def tool_output(
    command: list[str],
    timeout_seconds: int,
    max_bytes: int,
    diagnostic_output: Path | None = None,
) -> str:
    result = run_bounded(command, timeout_seconds, max_bytes)
    if diagnostic_output is not None:
        write_text_new(diagnostic_output, result["output"])
    if result["limited"] or result["returncode"] != 0:
        raise ValueError(result["reason"] or f"llvm-pdbutil exited {result['returncode']}")
    return result["output"]


def write_text_new(path: Path, text: str) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        for offset in range(0, len(text), 1024 * 1024):
            stream.write(text[offset : offset + 1024 * 1024])


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
    parser.add_argument("--diagnostic-output", type=Path)
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
                None
                if args.diagnostic_output is None
                else args.diagnostic_output.expanduser().absolute(),
            )
            pe_sha256 = sha256_buffer(pe_buffer)
            pdb_sha256 = sha256_buffer(pdb_buffer)
            packet = {
                "schema_version": 1,
                "format": "llvm-pdbutil-symbols-v1",
                "pe_sha256": pe_sha256,
                "pdb_sha256": pdb_sha256,
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
            if pe_sha256 != sha256_buffer(pe_buffer) or pdb_sha256 != sha256_buffer(pdb_buffer):
                raise ValueError("PE/PDB input bytes changed while exporting symbols")
        write_new(args.output.expanduser().absolute(), packet)
    except (OSError, ValueError, IndexError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    sys.exit(main())
