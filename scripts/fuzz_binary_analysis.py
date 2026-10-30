#!/usr/bin/env python3
# ruff: noqa: E402
"""Development fuzz entry point for native layouts, payloads, graphs, and debug data.

Run a retained corpus without external tools or target execution:

    uv run python scripts/fuzz_binary_analysis.py corpus/*

Write deterministic, structurally valid starting inputs with ``--write-seeds``.
Coverage-guided runners can import ``fuzz_one`` and pass arbitrary bytes. The
first byte selects a parser. Expected malformed-input ``ValueError`` and text
decoding failures are ignored; every other exception escapes as a finding.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import sys
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))

from brotli_binary_graph import GraphLimits, build_elf_graph
from brotli_binary_layout import inspect_layout
from brotli_binary_match import ELF_HEADER, EM_AARCH64, PROGRAM_HEADER
from brotli_debug_companions import (
    DebugLimits,
    SuppliedCompanion,
    debug_identity,
    verify_debug_companions,
)
from brotli_payloads import (
    NotOciImageError,
    PayloadError,
    PayloadLimits,
    iter_payload_members,
    open_oci_filesystems,
    payload_kind,
)

MAX_FUZZ_INPUT_BYTES = 16 * 1024 * 1024
MAX_OBSERVED_MEMBER_BYTES = 4096
PAIR_LENGTH_BYTES = 4
FUZZ_PAYLOAD_LIMITS = PayloadLimits(
    max_members=256,
    max_member_bytes=4 * 1024 * 1024,
    max_total_bytes=16 * 1024 * 1024,
)
FUZZ_GRAPH_LIMITS = GraphLimits(
    max_seeds=64,
    max_functions=4096,
    max_edges=4096,
    max_gaps=64,
    max_instructions=50_000,
    max_decode_bytes=2 * 1024 * 1024,
    max_relocations=4096,
    max_objdump_bytes=64 * 1024,
    max_objdump_line_bytes=1024,
)
FUZZ_DEBUG_LIMITS = DebugLimits(
    max_companions=4,
    max_identity_bytes=4 * 1024 * 1024,
    max_commands=4096,
    max_symbols=4096,
    max_function_hints=1024,
    max_pdb_directory_bytes=4 * 1024 * 1024,
    max_pdb_blocks=8192,
    max_line_entries=4096,
)


def _layout(data: bytes) -> object:
    return inspect_layout(data)


def _payload(data: bytes) -> object:
    kind = payload_kind(data, "fuzz.bin", FUZZ_PAYLOAD_LIMITS)
    if kind is None:
        return None
    observations = []
    for member in iter_payload_members(data, kind, FUZZ_PAYLOAD_LIMITS):
        with member.open() as stream:
            prefix = stream.read(min(member.size, MAX_OBSERVED_MEMBER_BYTES))
        observations.append((member.name, member.size, len(prefix)))
    return kind, tuple(observations)


def _oci(data: bytes) -> object:
    try:
        with open_oci_filesystems(data, FUZZ_PAYLOAD_LIMITS) as images:
            return tuple(
                (
                    image.manifest,
                    tuple((member.name, member.size) for member in image.members),
                    len(image.history),
                    image.gaps,
                )
                for image in images
            )
    except NotOciImageError:
        return None


def _graph(data: bytes) -> object:
    return build_elf_graph(
        data,
        limits=FUZZ_GRAPH_LIMITS,
        auto_capstone=False,
    ).as_dict()


def _debug_identity(data: bytes) -> object:
    return asdict(debug_identity(data, FUZZ_DEBUG_LIMITS))


def _debug_pair(data: bytes) -> object:
    if len(data) < PAIR_LENGTH_BYTES:
        return None
    artifact_size = int.from_bytes(data[:PAIR_LENGTH_BYTES], "little")
    if artifact_size > len(data) - PAIR_LENGTH_BYTES:
        return None
    artifact = data[PAIR_LENGTH_BYTES : PAIR_LENGTH_BYTES + artifact_size]
    companion = data[PAIR_LENGTH_BYTES + artifact_size :]
    return verify_debug_companions(
        artifact,
        (SuppliedCompanion("fuzz.debug", companion),),
        FUZZ_DEBUG_LIMITS,
        auto_pyelftools=False,
    ).as_dict()


@dataclass(frozen=True)
class FuzzTarget:
    name: str
    callback: Callable[[bytes], object]
    expected_rejections: tuple[type[BaseException], ...] = ()


FUZZ_TARGETS = (
    FuzzTarget("layout", _layout),
    FuzzTarget("payload", _payload, (PayloadError,)),
    FuzzTarget("oci", _oci, (PayloadError,)),
    FuzzTarget("graph", _graph, (ValueError,)),
    FuzzTarget("debug-identity", _debug_identity),
    FuzzTarget("debug-pair", _debug_pair),
)


def exercise_one(data: bytes) -> object:
    if not data or len(data) > MAX_FUZZ_INPUT_BYTES:
        return None
    selector, payload = data[0] % len(FUZZ_TARGETS), data[1:]
    return FUZZ_TARGETS[selector].callback(payload)


def fuzz_one(data: bytes) -> None:
    if not data or len(data) > MAX_FUZZ_INPUT_BYTES:
        return
    target = FUZZ_TARGETS[data[0] % len(FUZZ_TARGETS)]
    try:
        target.callback(data[1:])
    except target.expected_rejections:
        return


def _pe_seed() -> bytes:
    result = bytearray(0x220)
    result[:2] = b"MZ"
    result[0x3C:0x40] = (0x80).to_bytes(4, "little")
    result[0x80:0x84] = b"PE\0\0"
    optional_size = 0xF0
    result[0x84:0x98] = struct.pack("<HHIIIHH", 0xAA64, 1, 0, 0, 0, optional_size, 0x2)
    optional = 0x98
    result[optional : optional + 2] = (0x20B).to_bytes(2, "little")
    result[optional + 60 : optional + 64] = (0x200).to_bytes(4, "little")
    result[optional + 108 : optional + 112] = (0).to_bytes(4, "little")
    section = optional + optional_size
    result[section : section + 8] = b".data\0\0\0"
    result[section + 8 : section + 24] = struct.pack("<IIII", 0x20, 0x1000, 0x20, 0x200)
    result[section + 36 : section + 40] = (0x40000040).to_bytes(4, "little")
    result[0x200:0x220] = bytes(range(0x20))
    return bytes(result)


def _macho_seed() -> bytes:
    command = struct.pack("<II16s", 0x1B, 24, bytes(range(16)))
    header = struct.pack("<iiIIIII", 0x0100000C, 0, 2, 1, len(command), 0, 0)
    return b"\xcf\xfa\xed\xfe" + header + command


def _wasm_seed() -> bytes:
    return b"\0asm\x01\0\0\0"


def _ar_seed() -> bytes:
    content = b"brotli-fuzz-seed"
    header = (
        b"seed.bin/       "
        b"0           "
        b"0     "
        b"0     "
        b"100644  " + f"{len(content):<10}".encode() + b"`\n"
    )
    return b"!<arch>\n" + header + content + (b"\n" if len(content) % 2 else b"")


def _tar(entries: tuple[tuple[str, bytes], ...]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def _oci_seed() -> bytes:
    layer = _tar((("app/decoder", b"seed"),))
    manifest = json.dumps(
        [{"Config": "config.json", "RepoTags": [], "Layers": ["layer.tar"]}],
        separators=(",", ":"),
    ).encode()
    return _tar((("manifest.json", manifest), ("config.json", b"{}"), ("layer.tar", layer)))


def _elf_seed(*, note: bytes | None = None) -> bytes:
    if note is None:
        code = struct.pack("<I", 0xD65F03C0)
        offset = ELF_HEADER.size + PROGRAM_HEADER.size
        header = ELF_HEADER.pack(
            b"\x7fELF\x02\x01\x01" + bytes(9),
            3,
            EM_AARCH64,
            1,
            0,
            ELF_HEADER.size,
            0,
            0,
            ELF_HEADER.size,
            PROGRAM_HEADER.size,
            1,
            0,
            0,
            0,
        )
        load = PROGRAM_HEADER.pack(1, 5, offset, 0x401000, 0x401000, len(code), len(code), 4)
        return header + load + code
    offset = ELF_HEADER.size + PROGRAM_HEADER.size
    header = ELF_HEADER.pack(
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3,
        EM_AARCH64,
        1,
        0,
        ELF_HEADER.size,
        0,
        0,
        ELF_HEADER.size,
        PROGRAM_HEADER.size,
        1,
        0,
        0,
        0,
    )
    program = PROGRAM_HEADER.pack(4, 4, offset, 0, 0, len(note), len(note), 4)
    return header + program + note


def _debug_seed() -> bytes:
    name, build_id = b"GNU\0", bytes.fromhex("0102030405060708")
    note = struct.pack("<III", len(name), len(build_id), 3)
    note += name + build_id + bytes((-len(build_id)) % 4)
    return _elf_seed(note=note)


def seed_corpus() -> dict[str, bytes]:
    debug = _debug_seed()
    pair = len(debug).to_bytes(4, "little") + debug + debug
    seeds = {
        "layout-pe": bytes((0,)) + _pe_seed(),
        "layout-mach-o": bytes((0,)) + _macho_seed(),
        "layout-wasm": bytes((0,)) + _wasm_seed(),
        "payload-ar": bytes((1,)) + _ar_seed(),
        "oci-docker-save": bytes((2,)) + _oci_seed(),
        "graph-aarch64": bytes((3,)) + _elf_seed(),
        "debug-elf": bytes((4,)) + debug,
        "debug-pair": bytes((5,)) + pair,
    }
    if any(len(value) > MAX_FUZZ_INPUT_BYTES for value in seeds.values()):
        msg = "generated fuzz seed exceeds the input limit"
        raise ValueError(msg)
    return seeds


def _write_seeds(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=False)
    manifest = []
    for name, data in sorted(seed_corpus().items()):
        path = directory / name
        path.write_bytes(data)
        manifest.append(
            {"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        )
    (directory / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "seeds": manifest}, indent=2) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", type=Path)
    parser.add_argument("--write-seeds", type=Path)
    args = parser.parse_args(argv)
    if (args.write_seeds is None) == (not args.inputs):
        parser.error("provide corpus inputs or exactly one --write-seeds directory")
    if args.write_seeds is not None:
        _write_seeds(args.write_seeds)
        return 0
    for path in args.inputs:
        with path.open("rb") as stream:
            data = stream.read(MAX_FUZZ_INPUT_BYTES + 1)
        if len(data) > MAX_FUZZ_INPUT_BYTES:
            parser.error(f"fuzz input exceeds limit: {path}")
        fuzz_one(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
