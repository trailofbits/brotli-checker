"""Conservative ELF code identity matching; never executes the inspected artifact."""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

REFERENCES = Path(__file__).resolve().parent.parent / "references/binary-fingerprints.json"
ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
RELOCATION = struct.Struct("<QQq")
EM_X86_64 = 62
EM_AARCH64 = 183
SHT_RELA = 4
PN_XNUM = 0xFFFF
MACHINES = {EM_X86_64: "x86_64", EM_AARCH64: "aarch64"}
MIN_CODE_BYTES = 256
MIN_ANCHOR_BYTES = 32
MAX_REFERENCE_BYTES = 16 * 1024 * 1024
MAX_MATCHES = 128
MAX_CANDIDATES = 4096


def checked_slice(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        msg = "ELF range outside file"
        raise ValueError(msg)
    return data[offset : offset + size]


def elf_header(data: bytes) -> tuple:
    header = ELF_HEADER.unpack(checked_slice(data, 0, ELF_HEADER.size))
    ident, _, machine, version = header[:4]
    if (
        ident[:7] != b"\x7fELF\x02\x01\x01"
        or machine not in MACHINES
        or version != 1
        or header[8] != ELF_HEADER.size
    ):
        msg = "Only little-endian ELF64 x86_64 and AArch64 are supported"
        raise ValueError(msg)
    return header


def executable_ranges(data: bytes) -> tuple[int, list[tuple[int, int]]]:
    header = elf_header(data)
    if header[1] not in (2, 3):
        msg = "Code matching requires a linked ELF executable or shared object"
        raise ValueError(msg)
    offset, entry_size, count = header[5], header[9], header[10]
    if entry_size != PROGRAM_HEADER.size or not 0 < count < PN_XNUM:
        msg = "Unsupported ELF program header table"
        raise ValueError(msg)
    table = checked_slice(data, offset, count * entry_size)
    ranges = []
    for kind, flags, start, _, _, size, memory_size, _ in PROGRAM_HEADER.iter_unpack(table):
        if kind == 1:
            checked_slice(data, start, size)
            if size > memory_size:
                msg = "ELF segment file size exceeds memory size"
                raise ValueError(msg)
            if flags & 1 and size:
                ranges.append((start, size))
    if not ranges:
        msg = "No file-backed executable ELF load segment"
        raise ValueError(msg)
    return header[2], sorted(set(ranges))


def validate_metadata(entry: dict) -> None:
    for field in ("id", "source_sha256", "object_sha256", "source", "compiler", "flags"):
        if not isinstance(entry.get(field), str) or not entry[field].strip():
            msg = f"Invalid code reference {field}"
            raise ValueError(msg)
    for field in ("source_sha256", "object_sha256"):
        value = entry[field]
        if len(value) != hashlib.sha256().digest_size * 2 or any(
            c not in "0123456789abcdef" for c in value
        ):
            msg = f"Invalid code reference {field}"
            raise ValueError(msg)
    if (
        entry.get("state") not in ("fixed", "vulnerable")
        or not isinstance(entry.get("machine"), int)
        or entry["machine"] not in MACHINES
    ):
        msg = "Invalid code reference state or machine"
        raise ValueError(msg)


@dataclass(frozen=True)
class CodeReference:
    metadata: dict
    code: bytes
    mask: bytes
    anchor_offset: int
    anchor: bytes

    @classmethod
    def from_json(cls, entry: object) -> CodeReference:
        if not isinstance(entry, dict):
            msg = "Code reference must be an object"
            raise ValueError(msg)  # noqa: TRY004 -- Malformed catalog is a CLI value error.
        validate_metadata(entry)
        try:
            code = bytes.fromhex(entry["code"])
            mask = bytes.fromhex(entry["mask"])
        except (KeyError, TypeError, ValueError) as error:
            msg = "Invalid code reference bytes"
            raise ValueError(msg) from error
        if len(code) < MIN_CODE_BYTES or len(code) != len(mask):
            msg = "Code reference must contain equal code/mask lengths of at least 256 bytes"
            raise ValueError(msg)
        # An exact run anchors the search; every other unmasked bit is also checked.
        if (
            b"\xff" * MIN_ANCHOR_BYTES not in mask
            or sum(byte.bit_count() for byte in mask) < len(mask) * 6
        ):
            msg = "Code reference masks too much code or has no 32-byte exact anchor"
            raise ValueError(msg)
        anchor_offset = mask.index(b"\xff" * MIN_ANCHOR_BYTES)
        metadata = {key: value for key, value in entry.items() if key not in ("code", "mask")}
        return cls(metadata, code, mask, anchor_offset, code[anchor_offset : anchor_offset + 32])


def load_references(path: Path) -> list[CodeReference]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_REFERENCE_BYTES + 1)
    if len(raw) > MAX_REFERENCE_BYTES:
        msg = "Code reference catalog exceeds 16 MiB"
        raise ValueError(msg)
    catalog = json.loads(raw)
    if (
        not isinstance(catalog, dict)
        or catalog.get("schema_version") != 1
        or not isinstance(catalog.get("references"), list)
        or not catalog["references"]
    ):
        msg = "Expected schema_version 1 and nonempty references list"
        raise ValueError(msg)
    references = [CodeReference.from_json(entry) for entry in catalog["references"]]
    ids = [reference.metadata["id"] for reference in references]
    if len(ids) != len(set(ids)):
        msg = "Duplicate code reference id"
        raise ValueError(msg)
    return references


def candidate_offsets(
    data: bytes, reference: CodeReference, start: int, size: int
) -> Iterator[int]:
    end = start + size
    cursor = start + reference.anchor_offset
    while cursor < end:
        found = data.find(reference.anchor, cursor, end)
        if found < 0:
            return
        cursor = found + 1
        offset = found - reference.anchor_offset
        if offset + len(reference.code) <= end:
            yield offset


@dataclass(frozen=True)
class CodeAssessment:
    matches: list[dict]
    reason: str
    limited: bool = False

    @property
    def patch_status(self) -> str:
        states = {match["state"] for match in self.matches}
        if len(states) > 1:
            return "mixed_code_matches"
        if states:
            return f"{next(iter(states))}_code_match"
        return "unknown"


def match_code(  # noqa: C901 -- Bounded reference/segment/candidate search with explicit limits.
    data: bytes, references: list[CodeReference]
) -> CodeAssessment:
    try:
        machine, ranges = executable_ranges(data)
    except ValueError as error:
        return CodeAssessment([], str(error))
    matches = []
    candidates = 0
    for reference in references:
        if reference.metadata["machine"] != machine:
            continue
        expected = int.from_bytes(reference.code, "little")
        mask = int.from_bytes(reference.mask, "little")
        for start, size in ranges:
            for offset in candidate_offsets(data, reference, start, size):
                candidates += 1
                if candidates > MAX_CANDIDATES:
                    return CodeAssessment(
                        matches,
                        "Code candidate limit reached; additional copies not assessed",
                        limited=True,
                    )
                actual = int.from_bytes(data[offset : offset + len(reference.code)], "little")
                if (actual ^ expected) & mask:
                    continue
                matches.append(
                    {
                        **reference.metadata,
                        "file_offset": offset,
                        "size_bytes": len(reference.code),
                        "method": "relocation_masked_decoder_text",
                    }
                )
                if len(matches) >= MAX_MATCHES:
                    return CodeAssessment(
                        matches,
                        "Code match limit reached; additional copies not assessed",
                        limited=True,
                    )
    return CodeAssessment(
        matches,
        "Matched reference code only; other copies remain unassessed"
        if matches
        else "No supported compiled decoder reference matched; patch status unknown",
    )


def relocation_mask(machine: int, kind: int) -> bytes:
    if machine == EM_X86_64:
        widths = {1: 8, 2: 4, 4: 4, 10: 4, 11: 4}
        if kind in widths:
            return bytes(widths[kind])
    if machine == EM_AARCH64:
        masks = {
            274: 0x9F00001F,
            275: 0x9F00001F,
            276: 0x9F00001F,
            277: 0xFFC003FF,
            278: 0xFFC003FF,
            282: 0xFC000000,
            283: 0xFC000000,
            284: 0xFFC003FF,
            285: 0xFFC003FF,
            286: 0xFFC003FF,
            299: 0xFFC003FF,
            311: 0x9F00001F,
            312: 0xFFC003FF,
        }
        if kind in masks:
            return masks[kind].to_bytes(4, "little")
    msg = f"Unsupported executable relocation: machine={machine}, type={kind}"
    raise ValueError(msg)


def apply_relocations(  # noqa: PLR0913 -- ELF section context and output mask.
    data: bytes, sections: list[tuple], index: int, code: bytes, mask: bytearray, *, machine: int
) -> None:
    for relocation in sections:
        if relocation[1] not in (4, 9) or relocation[7] != index:
            continue
        if relocation[1] != SHT_RELA or relocation[9] != RELOCATION.size:
            msg = "Only ELF64 RELA executable relocations are supported"
            raise ValueError(msg)
        entries = checked_slice(data, relocation[4], relocation[5])
        if len(entries) % RELOCATION.size:
            msg = "Malformed relocation table"
            raise ValueError(msg)
        for offset, info, _ in RELOCATION.iter_unpack(entries):
            field_mask = relocation_mask(machine, info & 0xFFFFFFFF)
            checked_slice(code, offset, len(field_mask))
            for i, value in enumerate(field_mask):
                mask[offset + i] &= value


def reference_from_object(data: bytes, metadata: dict) -> dict:
    """Build a complete decoder .text signature, rejecting unsupported object layouts."""
    header = elf_header(data)
    if header[1] != 1 or header[11] != SECTION_HEADER.size or not header[12]:
        msg = "Expected ELF64 relocatable object with section headers"
        raise ValueError(msg)
    table = checked_slice(data, header[6], header[12] * SECTION_HEADER.size)
    sections = list(SECTION_HEADER.iter_unpack(table))
    code_sections = [
        (i, section) for i, section in enumerate(sections) if section[2] & 4 and section[5]
    ]
    if len(code_sections) != 1:
        msg = "Expected one complete executable section; split functions/LTO are unsupported"
        raise ValueError(msg)
    index, section = code_sections[0]
    code = checked_slice(data, section[4], section[5])
    mask = bytearray(b"\xff" * len(code))
    apply_relocations(data, sections, index, code, mask, machine=header[2])
    entry = {
        **metadata,
        "machine": header[2],
        "object_sha256": hashlib.sha256(data).hexdigest(),
        "code": code.hex(),
        "mask": mask.hex(),
    }
    CodeReference.from_json(entry)
    return entry
