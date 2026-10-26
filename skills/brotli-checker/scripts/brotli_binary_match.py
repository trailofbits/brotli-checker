"""Conservative ELF code identity matching; never executes the inspected artifact."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from brotli_binary_data import Buffer, sha256_data

if TYPE_CHECKING:
    from collections.abc import Iterator

REFERENCES = Path(__file__).resolve().parent.parent / "references/binary-fingerprints.json.gz"
RELOCATION_MASKS = json.loads((REFERENCES.parent / "elf-relocations.json").read_text())["machines"]
ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
RELOCATION = struct.Struct("<QQq")
EM_X86_64 = 62
EM_AARCH64 = 183
EM_386 = 3
EM_MIPS = 8
EM_PPC64 = 21
EM_S390 = 22
EM_ARM = 40
EM_RISCV = 243
EM_LOONGARCH = 258
SHT_RELA = 4
PN_XNUM = 0xFFFF
# ELF machine, word size, and byte order are separate parts of reference identity.
TARGETS = {
    (EM_386, 32, "little"): ("i386", "i386"),
    (EM_X86_64, 64, "little"): ("x86_64", "i386:x86-64"),
    (EM_ARM, 32, "little"): ("arm", "arm"),
    (EM_AARCH64, 64, "little"): ("aarch64", "aarch64"),
    (EM_PPC64, 64, "little"): ("ppc64le", "powerpc:common64"),
    (EM_PPC64, 64, "big"): ("ppc64", "powerpc:common64"),
    (EM_S390, 64, "big"): ("s390x", "s390:64-bit"),
    (EM_RISCV, 32, "little"): ("riscv32", "riscv:rv32"),
    (EM_RISCV, 64, "little"): ("riscv64", "riscv:rv64"),
    (EM_MIPS, 32, "little"): ("mipsel", "mips:isa32r2"),
    (EM_MIPS, 32, "big"): ("mips", "mips:isa32r2"),
    (EM_MIPS, 64, "little"): ("mips64el", "mips:isa64r2"),
    (EM_MIPS, 64, "big"): ("mips64", "mips:isa64r2"),
    (EM_LOONGARCH, 64, "little"): ("loongarch64", "loongarch64"),
}
MIN_CODE_BYTES = 256
MIN_ANCHOR_BYTES = 32
MAX_REFERENCE_BYTES = 64 * 1024 * 1024
MAX_MATCHES = 128
MAX_CANDIDATES = 4096
MAX_CODE_SECTIONS = 16
MAX_REFERENCE_SYMBOLS = 1_000_000
MAX_REFERENCE_SYMBOL_NAME_BYTES = 256
STRUCT_BATCH_BYTES = 1024 * 1024
ELF32_BITS = 32
ELF64_BITS = 64
GOT_OPCODE_BYTES = 2
X86_GOT_OPCODES = (0x8B, 0x03, 0x0B, 0x13, 0x1B, 0x23, 0x2B, 0x33, 0x3B, 0x85, 0xFF)
X86_GOT_RELOCATIONS = {EM_386: (43,), EM_X86_64: (41, 42)}
R_X86_64_REX_GOTPCRELX = 42
R_390_GOTENT = 26
R_MIPS_GPREL16 = 7
R_PPC64_REL24 = 10
R_PPC64_GOT16_LO_DS = 59
R_PPC64_TOC16_LO_DS = 64
R_PPC64_REL16_HA = 252
SHT_SYMTAB = 2
SHT_DYNSYM = 11
SHT_STRTAB = 3
SHT_PROGBITS = 1
STT_FUNC = 2
SHF_ALLOC = 2
SHF_EXECINSTR = 4
REFERENCE_SCOPE_COMPLETE = "complete_decoder_text"
REFERENCE_SCOPE_PATCH = "patch_bearing_sections_v1"
PATCH_ROLE_PATTERNS = {
    "literal": re.compile(r"^DecodeLiteralBlockSwitch(?:Internal)?(?:[.$].*)?$"),
    "command": re.compile(r"^DecodeCommandBlockSwitch(?:Internal)?(?:[.$].*)?$"),
    "distance": re.compile(r"^DecodeDistanceBlockSwitch(?:Internal)?(?:[.$].*)?$"),
    "safe_literal": re.compile(r"^SafeDecodeLiteralBlockSwitch(?:Internal)?(?:[.$].*)?$"),
    "safe_command": re.compile(r"^SafeDecodeCommandBlockSwitch(?:Internal)?(?:[.$].*)?$"),
    "safe_distance": re.compile(r"^SafeDecodeDistanceBlockSwitch(?:Internal)?(?:[.$].*)?$"),
    "process": re.compile(r"^ProcessCommands(?:Internal)?(?:[.$].*)?$"),
    "safe_process": re.compile(r"^SafeProcessCommands(?:Internal)?(?:[.$].*)?$"),
}
PATCH_HELPER_PATTERN = re.compile(r"^(?:Safe)?DecodeBlockTypeAndLength(?:Internal)?(?:[.$].*)?$")


@dataclass(frozen=True)
class ELFLayout:
    bits: int
    byteorder: Literal["little", "big"]

    @classmethod
    def of(cls, header: tuple) -> ELFLayout:
        return cls(32 if header[0][4] == 1 else 64, "little" if header[0][5] == 1 else "big")

    def parser(self, kind: str) -> struct.Struct:
        formats = {
            "header": ("16sHHIIIIIHHHHHH", "16sHHIQQQIHHHHHH"),
            "program": ("IIIIIIII", "IIQQQQQQ"),
            "section": ("IIIIIIIIII", "IIQQQQIIQQ"),
            "symbol": ("IIIBBH", "IBBHQQ"),
            "rel": ("II", "QQ"),
            "rela": ("IIi", "QQq"),
        }
        return struct.Struct(
            ("<" if self.byteorder == "little" else ">") + formats[kind][self.bits == ELF64_BITS]
        )


@dataclass(frozen=True)
class PatchSectionScope:
    functions: dict[str, list[str]]
    section_functions: dict[int, list[str]]


def target_identity(header: tuple) -> tuple[int, int, str]:
    layout = ELFLayout.of(header)
    return header[2], layout.bits, layout.byteorder


def program_headers(data: Buffer, header: tuple) -> Iterator[tuple]:
    layout = ELFLayout.of(header)
    parser = layout.parser("program")
    if header[9] != parser.size or not 0 < header[10] < PN_XNUM:
        msg = "Unsupported ELF program header table"
        raise ValueError(msg)
    for row in iter_structs(data, parser, header[5], header[9] * header[10]):
        if layout.bits == ELF32_BITS:
            kind, offset, virtual, physical, size, memory, flags, alignment = row
            yield (kind, flags, offset, virtual, physical, size, memory, alignment)
        else:
            yield row


def section_headers(data: Buffer, header: tuple) -> list[tuple]:
    parser = ELFLayout.of(header).parser("section")
    if header[11] != parser.size:
        msg = "Unsupported ELF section table"
        raise ValueError(msg)
    return list(iter_structs(data, parser, header[6], header[11] * header[12]))


def symbol_rows(data: Buffer, header: tuple, section: tuple) -> Iterator[tuple]:
    layout = ELFLayout.of(header)
    for row in iter_structs(data, layout.parser("symbol"), section[4], section[5]):
        if layout.bits == ELF32_BITS:
            name, address, size, info, other, index = row
            yield (name, info, other, index, address, size)
        else:
            yield row


def checked_range(data: Buffer, offset: int, size: int) -> tuple[int, int]:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        msg = "ELF range outside file"
        raise ValueError(msg)
    return offset, offset + size


def checked_slice(data: Buffer, offset: int, size: int) -> bytes:
    start, end = checked_range(data, offset, size)
    return data[start:end]


def iter_structs(data: Buffer, parser: struct.Struct, offset: int, size: int) -> Iterator[tuple]:
    checked_range(data, offset, size)
    if size % parser.size:
        msg = "ELF structure table has a partial entry"
        raise ValueError(msg)
    batch_size = max(parser.size, STRUCT_BATCH_BYTES // parser.size * parser.size)
    end = offset + size
    for start in range(offset, end, batch_size):
        yield from parser.iter_unpack(checked_slice(data, start, min(batch_size, end - start)))


def elf_header(data: Buffer) -> tuple:
    ident = checked_slice(data, 0, 16)
    if ident[:4] != b"\x7fELF" or ident[4] not in (1, 2) or ident[5] not in (1, 2) or ident[6] != 1:
        msg = "Expected ELF32/ELF64 with a supported byte order"
        raise ValueError(msg)
    layout = ELFLayout.of((ident,))
    parser = layout.parser("header")
    header = parser.unpack(checked_slice(data, 0, parser.size))
    ident, _, machine, version = header[:4]
    if (
        (machine, layout.bits, layout.byteorder) not in TARGETS
        or version != 1
        or header[8] != parser.size
    ):
        msg = "Unsupported ELF architecture, word size, byte order, or header version"
        raise ValueError(msg)
    return header


def _file_backed_load_segments(data: Buffer) -> tuple[int, list[tuple[int, int, int]]]:
    header = elf_header(data)
    if header[1] not in (2, 3):
        msg = "Code matching requires a linked ELF executable or shared object"
        raise ValueError(msg)
    segments = []
    for kind, flags, start, _, _, size, memory_size, _ in program_headers(data, header):
        if kind == 1:
            checked_range(data, start, size)
            if size > memory_size:
                msg = "ELF segment file size exceeds memory size"
                raise ValueError(msg)
            if size:
                segments.append((start, size, flags))
    return header[2], sorted(set(segments))


def file_backed_ranges(data: Buffer) -> tuple[int, list[tuple[int, int]]]:
    machine, segments = _file_backed_load_segments(data)
    ranges = sorted({(start, size) for start, size, _ in segments})
    if not ranges:
        msg = "No file-backed ELF load segment"
        raise ValueError(msg)
    return machine, ranges


def executable_ranges(data: Buffer) -> tuple[int, list[tuple[int, int]]]:
    machine, segments = _file_backed_load_segments(data)
    ranges = sorted({(start, size) for start, size, flags in segments if flags & 1})
    if not ranges:
        msg = "No file-backed executable ELF load segment"
        raise ValueError(msg)
    return machine, ranges


def valid_patch_functions(functions: object) -> bool:
    if not isinstance(functions, dict) or set(functions) != {*PATCH_ROLE_PATTERNS, "helpers"}:
        return False
    for role, names in functions.items():
        if (
            not isinstance(names, list)
            or (role != "helpers" and not names)
            or any(not isinstance(name, str) or not name for name in names)
        ):
            return False
        pattern = PATCH_HELPER_PATTERN if role == "helpers" else PATCH_ROLE_PATTERNS[role]
        if any(pattern.fullmatch(name) is None for name in names):
            return False
    return True


def valid_patch_section_population(entry: dict, functions: dict) -> bool:
    extra = entry.get("additional_sections", [])
    section_functions = entry.get("section_functions")
    return (
        isinstance(extra, list)
        and isinstance(section_functions, list)
        and len(section_functions) == 1 + len(extra)
        and all(
            isinstance(names, list)
            and names
            and all(isinstance(name, str) and name for name in names)
            for names in section_functions
        )
        and {name for names in section_functions for name in names}
        == {name for names in functions.values() for name in names}
    )


def validate_reference_scope(entry: dict, *, fragment: bool) -> None:
    scope = entry.get("code_scope", REFERENCE_SCOPE_COMPLETE)
    if scope not in (REFERENCE_SCOPE_COMPLETE, REFERENCE_SCOPE_PATCH):
        msg = "Invalid code reference scope"
        raise ValueError(msg)
    if scope != REFERENCE_SCOPE_PATCH:
        return
    functions = entry.get("patch_functions")
    if not isinstance(functions, dict) or not valid_patch_functions(functions):
        msg = "Invalid patch-bearing function scope"
        raise ValueError(msg)
    if not fragment and not valid_patch_section_population(entry, functions):
        msg = "Invalid patch-bearing section population"
        raise ValueError(msg)


def validate_metadata(entry: dict, *, fragment: bool = False) -> None:
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
        or type(entry.get("machine")) is not int
        or type(entry.get("elf_class", 64)) is not int
        or not isinstance(entry.get("byteorder", "little"), str)
        or (entry["machine"], entry.get("elf_class", 64), entry.get("byteorder", "little"))
        not in TARGETS
    ):
        msg = "Invalid code reference state or machine"
        raise ValueError(msg)
    validate_reference_scope(entry, fragment=fragment)


@dataclass(frozen=True)
class CodeReference:
    metadata: dict
    code: bytes
    mask: bytes
    anchor_offset: int
    anchor: bytes
    additional_sections: tuple[CodeReference, ...] = ()

    @classmethod
    def from_json(cls, entry: object, *, fragment: bool = False) -> CodeReference:
        if not isinstance(entry, dict):
            msg = "Code reference must be an object"
            raise ValueError(msg)  # noqa: TRY004 -- Malformed catalog is a CLI value error.
        validate_metadata(entry, fragment=fragment)
        try:
            code = bytes.fromhex(entry["code"])
            mask = bytes.fromhex(entry["mask"])
        except (KeyError, TypeError, ValueError) as error:
            msg = "Invalid code reference bytes"
            raise ValueError(msg) from error
        if len(code) < (1 if fragment else MIN_CODE_BYTES) or len(code) != len(mask):
            msg = "Code reference must contain equal code/mask lengths of at least 256 bytes"
            raise ValueError(msg)
        # An exact run anchors the search; every other unmasked bit is also checked.
        if not fragment and (
            b"\xff" * MIN_ANCHOR_BYTES not in mask
            or int.from_bytes(mask).bit_count() < len(mask) * 6
        ):
            msg = "Code reference masks too much code or has no 32-byte exact anchor"
            raise ValueError(msg)
        runs = list(re.finditer(b"\xff+", mask))
        if not runs:
            msg = "Code section has no exact anchor"
            raise ValueError(msg)
        run = max(runs, key=lambda match: match.end() - match.start())
        anchor_offset = run.start()
        anchor_size = min(MIN_ANCHOR_BYTES, run.end() - run.start())
        metadata = {
            key: value
            for key, value in entry.items()
            if key not in ("code", "mask", "additional_sections")
        }
        extra = entry.get("additional_sections", [])
        if (
            not isinstance(extra, list)
            or len(extra) >= MAX_CODE_SECTIONS
            or (fragment and extra)
            or any(not isinstance(part, dict) or set(part) != {"code", "mask"} for part in extra)
        ):
            msg = "Invalid additional executable sections"
            raise ValueError(msg)
        sections = tuple(cls.from_json({**metadata, **part}, fragment=True) for part in extra)
        return cls(
            metadata,
            code,
            mask,
            anchor_offset,
            code[anchor_offset : anchor_offset + anchor_size],
            sections,
        )

    def to_json(self) -> dict:
        entry = {**self.metadata, "code": self.code.hex(), "mask": self.mask.hex()}
        if self.additional_sections:
            entry["additional_sections"] = [
                {"code": part.code.hex(), "mask": part.mask.hex()}
                for part in self.additional_sections
            ]
        return entry


def load_references(path: Path) -> list[CodeReference]:
    with path.open("rb") as stream:
        compressed = stream.peek(2)[:2] == b"\x1f\x8b"
        if compressed:
            try:
                with gzip.GzipFile(fileobj=stream) as decoded:
                    raw = decoded.read(MAX_REFERENCE_BYTES + 1)
            except (EOFError, zlib.error) as error:
                msg = "Invalid compressed catalog"
                raise ValueError(msg) from error
        else:
            raw = stream.read(MAX_REFERENCE_BYTES + 1)
    if len(raw) > MAX_REFERENCE_BYTES:
        msg = "Code reference catalog exceeds the uncompressed byte limit"
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
    data: Buffer, reference: CodeReference, start: int, size: int
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


class CodeMatchLimitError(ValueError):
    """The shared candidate budget was exhausted."""


def matching_offsets(
    data: Buffer, reference: CodeReference, ranges: list[tuple[int, int]], budget: list[int]
) -> Iterator[int]:
    expected = int.from_bytes(reference.code, "little")
    mask = int.from_bytes(reference.mask, "little")
    for start, size in ranges:
        for offset in candidate_offsets(data, reference, start, size):
            budget[0] -= 1
            if budget[0] < 0:
                msg = "Code candidate limit reached; additional copies not assessed"
                raise CodeMatchLimitError(msg)
            actual = int.from_bytes(data[offset : offset + len(reference.code)], "little")
            if not (actual ^ expected) & mask:
                yield offset


def match_code(  # noqa: C901 -- Bounded reference/segment/candidate search with explicit limits.
    data: Buffer, references: list[CodeReference]
) -> CodeAssessment:
    try:
        header = elf_header(data)
        _, ranges = executable_ranges(data)
    except ValueError as error:
        return CodeAssessment([], str(error))
    matches = []
    budget = [MAX_CANDIDATES]
    identity = target_identity(header)
    compatible = [
        reference
        for reference in references
        if (
            reference.metadata["machine"],
            reference.metadata.get("elf_class", 64),
            reference.metadata.get("byteorder", "little"),
        )
        == identity
    ]
    if not compatible:
        return CodeAssessment(
            [],
            f"No compiled references for {TARGETS[identity][0]}; patch status unknown",
            limited=True,
        )
    try:
        for reference in compatible:
            extra_offsets = None
            for offset in matching_offsets(data, reference, ranges, budget):
                if extra_offsets is None:
                    extra_offsets = [
                        next(matching_offsets(data, part, ranges, budget), None)
                        for part in reference.additional_sections
                    ]
                if None in extra_offsets:
                    break
                matches.append(
                    {
                        **reference.metadata,
                        "file_offset": offset,
                        "size_bytes": len(reference.code),
                        "method": (
                            "relocation_masked_patch_sections"
                            if reference.metadata.get("code_scope") == REFERENCE_SCOPE_PATCH
                            else "relocation_masked_decoder_text"
                        ),
                        "additional_section_offsets": extra_offsets,
                    }
                )
                if len(matches) >= MAX_MATCHES:
                    return CodeAssessment(
                        matches,
                        "Code match limit reached; additional copies not assessed",
                        limited=True,
                    )
    except CodeMatchLimitError as error:
        return CodeAssessment(matches, str(error), limited=True)
    return CodeAssessment(
        matches,
        "Matched reference code only; other copies remain unassessed"
        if matches
        else "No supported compiled decoder reference matched; patch status unknown",
    )


def relocation_mask(
    machine: int, kind: int, byteorder: Literal["little", "big"] = "little"
) -> bytes:
    """Mask only psABI relocation fields; reject types outside the reviewed table."""
    try:
        field = bytes.fromhex(RELOCATION_MASKS[str(machine)][str(kind)])
    except KeyError as error:
        msg = f"Unsupported executable relocation: machine={machine}, type={kind}"
        raise ValueError(msg) from error
    return field if byteorder == "big" else field[::-1]


def apply_relocations(  # noqa: C901, PLR0913 -- Bounded ELF relocation walk and ABI rewrites.
    data: Buffer, sections: list[tuple], index: int, code: bytes, mask: bytearray, *, machine: int
) -> None:
    header = elf_header(data)
    layout = ELFLayout.of(header)
    for relocation in sections:
        if relocation[1] not in (4, 9) or relocation[7] != index:
            continue
        parser = layout.parser("rela" if relocation[1] == SHT_RELA else "rel")
        if relocation[9] != parser.size:
            msg = "Unsupported REL/RELA executable relocation entry size"
            raise ValueError(msg)
        entries = checked_slice(data, relocation[4], relocation[5])
        if len(entries) % parser.size:
            msg = "Malformed relocation table"
            raise ValueError(msg)
        for row in parser.iter_unpack(entries):
            offset, info = row[:2]
            kind = info & (0xFF if layout.bits == ELF32_BITS else 0xFFFFFFFF)
            if machine == EM_MIPS and layout.bits == ELF64_BITS:
                kind = mips64_relocation(info, layout.byteorder)
            field_mask = relocation_mask(machine, kind, layout.byteorder)
            checked_slice(code, offset, len(field_mask))
            if (
                kind in X86_GOT_RELOCATIONS.get(machine, ())
                and offset >= GOT_OPCODE_BYTES
                and code[offset - 2] in X86_GOT_OPCODES
            ):
                # GOT relaxations rewrite opcode/ModRM and sometimes the REX register bits.
                size = 3 if kind == R_X86_64_REX_GOTPCRELX else 2
                checked_slice(code, offset - size, size)
                mask[offset - size : offset] = bytes(size)
            if machine == EM_S390 and kind == R_390_GOTENT and offset >= GOT_OPCODE_BYTES:
                # LGRL C4x8 becomes LARL C0x0; keep register and other opcode bits.
                mask[offset - 2] &= 0xFB
                mask[offset - 1] &= 0xF7
            if machine == EM_PPC64:
                ppc64_linker_masks(code, mask, offset, kind, layout.byteorder)
            for i, value in enumerate(field_mask):
                mask[offset + i] &= value


def ppc64_linker_masks(
    code: bytes, mask: bytearray, offset: int, kind: int, byteorder: Literal["little", "big"]
) -> None:
    """Account for the ELFv2 TOC and call-slot rewrites permitted by the linker."""
    word = offset if byteorder == "little" else offset - 2
    if kind in (17, 50):  # GOT16_HA / TOC16_HA: ADDIS can become NOP.
        checked_slice(code, word, 4)
        mask[word : word + 4] = bytes(4)
    if kind in (R_PPC64_GOT16_LO_DS, R_PPC64_TOC16_LO_DS):
        checked_slice(code, word, 4)
        # A TOC/GOT load can become ADDI: opcode and the full immediate change.
        mask[offset : offset + 2] = bytes(2)
        mask[word + (3 if byteorder == "little" else 0)] &= 3
    if kind in (48, R_PPC64_GOT16_LO_DS, R_PPC64_TOC16_LO_DS, R_PPC64_REL16_HA):
        checked_slice(code, word, 4)
        mask[word + (2 if byteorder == "little" else 1)] &= 0xE0
    if kind == R_PPC64_REL24 and code[offset + 4 : offset + 8] == (0x60000000).to_bytes(
        4, byteorder
    ):
        mask[offset + 4 : offset + 8] = bytes(4)


def mips64_relocation(info: int, byteorder: Literal["little", "big"]) -> int:
    # MIPS64 uses a symbol word followed by ssym, type3, type2, type1 bytes.
    packed = info.to_bytes(8, byteorder)
    special, third, second, first = packed[4:]
    if (
        special
        or (second, third) not in ((0, 0), (24, 5), (24, 6))
        or (second and first != R_MIPS_GPREL16)
    ):
        msg = "Unsupported compound MIPS64 relocation"
        raise ValueError(msg)
    return third or first


def reference_symbol_tables(
    data: Buffer, header: tuple, sections: list[tuple]
) -> list[tuple[tuple, tuple, int, int]]:
    symbol_parser = ELFLayout.of(header).parser("symbol")
    tables: list[tuple[tuple, tuple, int, int]] = []
    symbols_seen = 0
    for table in sections:
        if table[1] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if table[9] != symbol_parser.size or table[5] % symbol_parser.size:
            msg = "Malformed ELF symbol table"
            raise ValueError(msg)
        if table[6] >= len(sections) or sections[table[6]][1] != SHT_STRTAB:
            msg = "ELF symbols do not reference a string table"
            raise ValueError(msg)
        strings = sections[table[6]]
        string_start, string_end = checked_range(data, strings[4], strings[5])
        symbols_seen += table[5] // symbol_parser.size
        if symbols_seen > MAX_REFERENCE_SYMBOLS:
            msg = "Reference symbol limit reached"
            raise ValueError(msg)
        tables.append((table, strings, string_start, string_end))
    return tables


def valid_reference_function_owner(owner: tuple, address: int, size: int) -> bool:
    return (
        owner[1] == SHT_PROGBITS
        and owner[2] & (SHF_ALLOC | SHF_EXECINSTR) == (SHF_ALLOC | SHF_EXECINSTR)
        and bool(size)
        and address >= owner[3]
        and address + size <= owner[3] + owner[5]
    )


def reference_symbol_name(
    data: Buffer, name_offset: int, strings: tuple, string_start: int, string_end: int
) -> str | None:
    if name_offset >= strings[5]:
        return None
    start = string_start + name_offset
    end = data.find(b"\0", start, min(start + MAX_REFERENCE_SYMBOL_NAME_BYTES, string_end))
    if end < 0:
        return None
    try:
        return data[start:end].decode("ascii")
    except UnicodeDecodeError:
        return None


def reference_function_symbols(
    data: Buffer, header: tuple, sections: list[tuple]
) -> Iterator[tuple[str, int]]:
    for table, strings, string_start, string_end in reference_symbol_tables(data, header, sections):
        for name_offset, info, _, index, symbol_address, size in symbol_rows(data, header, table):
            if info & 0xF != STT_FUNC or index == 0 or index >= len(sections):
                continue
            address = symbol_address & (~1 if header[2] == EM_ARM else -1)
            if not valid_reference_function_owner(sections[index], address, size):
                continue
            name = reference_symbol_name(data, name_offset, strings, string_start, string_end)
            if name is not None:
                yield name, index


def patch_section_scope(data: Buffer, header: tuple, sections: list[tuple]) -> PatchSectionScope:
    role_sections = {role: set() for role in PATCH_ROLE_PATTERNS}
    role_functions = {role: set() for role in PATCH_ROLE_PATTERNS}
    helper_sections = set()
    helper_functions = set()
    section_functions: dict[int, set[str]] = {}
    for name, index in reference_function_symbols(data, header, sections):
        for role, pattern in PATCH_ROLE_PATTERNS.items():
            if pattern.fullmatch(name):
                role_sections[role].add(index)
                role_functions[role].add(name)
                section_functions.setdefault(index, set()).add(name)
                break
        if PATCH_HELPER_PATTERN.fullmatch(name):
            helper_sections.add(index)
            helper_functions.add(name)
            section_functions.setdefault(index, set()).add(name)
    missing = sorted(role for role, indices in role_sections.items() if not indices)
    if missing:
        msg = "Cannot establish required patch-bearing functions: " + ", ".join(missing)
        raise ValueError(msg)
    selected = helper_sections.union(*(indices for indices in role_sections.values()))
    return PatchSectionScope(
        functions={
            **{role: sorted(role_functions[role]) for role in PATCH_ROLE_PATTERNS},
            "helpers": sorted(helper_functions),
        },
        section_functions={index: sorted(section_functions[index]) for index in selected},
    )


def selected_code_sections(
    data: Buffer,
    header: tuple,
    sections: list[tuple],
    section_scope: Literal["complete", "auto", "patch"],
) -> tuple[list[tuple[int, tuple]], PatchSectionScope | None]:
    code_sections = [
        (i, section) for i, section in enumerate(sections) if section[2] & 4 and section[5]
    ]
    if not code_sections:
        msg = (
            "Expected one complete executable section or bounded code sections; LTO is unsupported"
        )
        raise ValueError(msg)
    if section_scope == "complete":
        if len(code_sections) > MAX_CODE_SECTIONS:
            msg = "Complete executable section population exceeds the reference limit"
            raise ValueError(msg)
        return code_sections, None
    if section_scope not in ("auto", "patch"):
        msg = f"Unsupported reference section scope: {section_scope}"
        raise ValueError(msg)
    if section_scope == "auto" and len(code_sections) == 1:
        return code_sections, None
    patch_scope = patch_section_scope(data, header, sections)
    selected = set(patch_scope.section_functions)
    if section_scope == "auto" and len(selected) == 1 and len(code_sections) <= MAX_CODE_SECTIONS:
        return code_sections, None
    if not selected or len(selected) > MAX_CODE_SECTIONS:
        msg = "Patch-bearing executable section population exceeds the reference limit"
        raise ValueError(msg)
    return [(index, sections[index]) for index in sorted(selected)], patch_scope


def reference_from_object(
    data: Buffer,
    metadata: dict,
    *,
    section_scope: Literal["complete", "auto", "patch"] = "complete",
) -> dict:
    """Build a bounded complete or patch-bearing decoder code signature."""
    header = elf_header(data)
    if header[1] != 1 or not header[12]:
        msg = "Expected ELF relocatable object with section headers"
        raise ValueError(msg)
    sections = section_headers(data, header)
    code_sections, patch_scope = selected_code_sections(data, header, sections, section_scope)
    code_sections.sort(key=lambda pair: (-pair[1][5], pair[0]))
    index, section = code_sections[0]
    code = checked_slice(data, section[4], section[5])
    mask = bytearray(b"\xff" * len(code))
    apply_relocations(data, sections, index, code, mask, machine=header[2])
    entry: dict = {
        **metadata,
        "machine": header[2],
        "elf_class": ELFLayout.of(header).bits,
        "byteorder": ELFLayout.of(header).byteorder,
        "object_sha256": sha256_data(data),
        "code": code.hex(),
        "mask": mask.hex(),
    }
    if patch_scope is not None:
        entry["code_scope"] = REFERENCE_SCOPE_PATCH
        entry["patch_functions"] = patch_scope.functions
        entry["section_functions"] = [
            patch_scope.section_functions[section_index] for section_index, _ in code_sections
        ]
    if len(code_sections) > 1:
        entry["additional_sections"] = []
        for index, section in code_sections[1:]:
            part = checked_slice(data, section[4], section[5])
            part_mask = bytearray(b"\xff" * len(part))
            apply_relocations(data, sections, index, part, part_mask, machine=header[2])
            entry["additional_sections"].append({"code": part.hex(), "mask": part_mask.hex()})
    CodeReference.from_json(entry)
    return entry
