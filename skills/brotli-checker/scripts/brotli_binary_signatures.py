"""Compiler-independent decoder data recognition, not patch or execution proof.

Tables derived from Google Brotli v1.2.1 c/dec/decode.c and c/dec/prefix.c.
See references/BROTLI-LICENSE and references/binary-signatures.md.
"""

from __future__ import annotations

import re
import struct
from bisect import bisect_right
from typing import TYPE_CHECKING

from brotli_binary_data import normalize_ranges
from brotli_binary_match import elf_header, file_backed_ranges, program_headers

if TYPE_CHECKING:
    from brotli_binary_data import Buffer

CHUNK_BYTES = 1024 * 1024
ANCHOR_BYTES = 64
MAX_CANDIDATES = 4096
IMPLICIT_DISTANCE_COMMANDS = 128
CODE_LENGTH_TABLES = {
    "code_length_order": bytes((1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15)),
    "code_length_lengths": bytes((2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4)),
    "code_length_values": bytes((0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5)),
}
OTHER_BINARY_MAGICS = (
    b"MZ",
    b"\0asm",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
)


def command_table(byteorder: str) -> bytes:
    insert_bits = (0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24)
    copy_bits = (0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24)
    cells = (0, 1, 0, 1, 8, 9, 2, 16, 10, 17, 18)
    insert_offsets, copy_offsets = [0], [2]
    for index in range(23):
        insert_offsets.append(insert_offsets[-1] + (1 << insert_bits[index]))
        copy_offsets.append(copy_offsets[-1] + (1 << copy_bits[index]))
    rows = []
    for symbol in range(704):
        cell = cells[symbol >> 6]
        copy = ((cell << 3) & 24) + (symbol & 7)
        insert = (cell & 24) + ((symbol >> 3) & 7)
        rows.append(
            struct.pack(
                byteorder + "BBbBHH",
                insert_bits[insert],
                copy_bits[copy],
                -1 if symbol >= IMPLICIT_DISTANCE_COMMANDS else 0,
                min(copy_offsets[copy] - 2, 3),
                insert_offsets[insert],
                copy_offsets[copy],
            )
        )
    return b"".join(rows)


SIGNATURES = {
    **CODE_LENGTH_TABLES,
    "command_lut_le": command_table("<"),
    "command_lut_be": command_table(">"),
}
ANCHORS = re.compile(
    b"|".join(
        b"(?P<" + name.encode() + b">" + re.escape(value[:ANCHOR_BYTES]) + b")"
        for name, value in SIGNATURES.items()
    )
)


def scan_tables(data: Buffer, ranges: list[tuple[int, int]]) -> tuple[dict, bool]:
    found = {}
    candidates = 0
    union, starts, coverage_ends = normalize_ranges(ranges)
    for start, end in union:
        for position in range(start, end, CHUNK_BYTES):
            chunk = data[position : min(end, position + CHUNK_BYTES + ANCHOR_BYTES - 1)]
            for match in ANCHORS.finditer(chunk):
                if match.start() >= CHUNK_BYTES:
                    continue
                name = match.lastgroup or ""
                if name in found:
                    continue
                candidates += 1
                if candidates > MAX_CANDIDATES:
                    return found, True
                signature = SIGNATURES[name]
                offset = position + match.start()
                owner = bisect_right(starts, offset) - 1
                if (
                    owner >= 0
                    and offset + len(signature) <= coverage_ends[owner]
                    and data[offset : offset + len(signature)] == signature
                ):
                    found[name] = {"id": name, "file_offset": offset, "size_bytes": len(signature)}
    return found, False


def recognize_decoder_data(data: Buffer) -> dict:
    result = {"status": "not_detected", "scope": "none", "matches": [], "limited": False}
    if data.startswith(b"\x7fELF"):
        try:
            _, ranges = file_backed_ranges(data)
        except (ValueError, struct.error):
            return {
                **result,
                "limited": True,
                "reason": "Cannot scope decoder signatures to ELF load segments.",
            }
        result["scope"] = "elf_load_segments"
    elif data.startswith(OTHER_BINARY_MAGICS):
        ranges = [(0, len(data))]
        result["scope"] = "file_bytes_not_loader_validated"
    else:
        return result
    found, limited = scan_tables(data, ranges)
    accepted = [value for name, value in found.items() if name.startswith("command_lut_")]
    if CODE_LENGTH_TABLES.keys() <= found.keys():
        accepted.extend(found[name] for name in CODE_LENGTH_TABLES)
    if result["scope"] == "elf_load_segments" and accepted:
        segments = list(program_headers(data, elf_header(data)))
        for row in accepted:
            row["virtual_addresses"] = sorted(
                {
                    virtual + row["file_offset"] - start
                    for kind, _, start, virtual, _, size, _, _ in segments
                    if kind == 1
                    and start <= row["file_offset"]
                    and row["file_offset"] + row["size_bytes"] <= start + size
                }
            )
    return {
        **result,
        "status": "decoder_tables_detected" if accepted else "not_detected",
        "matches": accepted,
        "limited": limited,
        "reason": "Decoder table signatures identify data, not patch state or executable use."
        if not limited
        else "Decoder signature candidate limit reached; recognition is incomplete.",
    }
