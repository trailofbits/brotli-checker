"""Bounded ELF function/xref evidence graph; never assigns patch state."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import re
import struct
from bisect import bisect_right, insort
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

from brotli_binary_match import (
    ELF32_BITS,
    ELF64_BITS,
    EM_AARCH64,
    EM_RISCV,
    EM_X86_64,
    SHT_DYNSYM,
    SHT_STRTAB,
    SHT_SYMTAB,
    STT_FUNC,
    ELFLayout,
    checked_range,
    checked_slice,
    elf_header,
    program_headers,
    section_headers,
    symbol_rows,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from brotli_binary_data import Buffer

PT_LOAD = 1
PT_GNU_EH_FRAME = 0x6474E550
PF_X = 1
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
SHN_UNDEF = 0
SHF_ALLOC = 2
DW_EH_PE_OMIT = 0xFF
DW_EH_PE_PCREL = 0x10
DW_EH_PE_DATAREL = 0x30
DW_EH_PE_INDIRECT = 0x80
MAX_NAME_BYTES = 256
PINNED_CAPSTONE_VERSION = "5.0.9"
OBJDUMP_PREFIX = re.compile(r"^\s*([0-9A-Fa-f]+):\s*(.*?)\s*$")
HEX_BYTE = re.compile(r"[0-9A-Fa-f]{2}")
X86_COMMENT_TARGET = re.compile(r"#\s*(?:0x)?([0-9A-Fa-f]+)\b")
X86_RIP_MNEMONICS = frozenset(
    {"lea", "leaq", "mov", "movq", "movl", "movzbl", "movslq", "cmp", "cmpq"}
)
X86_CALLS = frozenset({"call", "callq"})
X86_JUMPS = frozenset({"jmp", "jmpq"})
AARCH64_BR = 0xD61F0000
AARCH64_BLR = 0xD63F0000
AARCH64_ADRP = 0x90000000
AARCH64_ADR = 0x10000000
AARCH64_ADD_IMMEDIATE = 0x11000000
AARCH64_LDR_LITERAL = 0x18000000
AARCH64_BL = 0x94000000
X86_CALL_REL32 = 0xE8
X86_JUMP_REL32 = 0xE9
X86_JUMP_REL8 = 0xEB
X86_REL32_INSTRUCTION_BYTES = 5
X86_RIP_MODRM = 0x05
EH_FRAME_HEADER_BYTES = 4
AARCH64_CHUNK_BYTES = 64 * 1024
RISCV_CHUNK_BYTES = 64 * 1024
EF_RISCV_RVC = 0x0001
RISCV_OPCODE_LOAD = 0x03
RISCV_OPCODE_AUIPC = 0x17
RISCV_OPCODE_LUI = 0x37
RISCV_OPCODE_OP_IMM = 0x13
RISCV_OPCODE_JALR = 0x67
RISCV_OPCODE_JAL = 0x6F
RISCV_LONG_INSTRUCTION_MASK = 0x3
RISCV_COMPRESSED_INSTRUCTION_BYTES = 2
RISCV_COMPRESSED_JUMP = 0xA001
DERIVED_FUNCTION_METHODS = frozenset(
    {"elf_symbol", "eh_frame_hdr", "direct_branch_target", "reference_site_only"}
)
RELOCATION_WIDTHS = {
    EM_X86_64: {2: 4, 4: 4, 9: 4, 10: 4, 11: 4, 41: 4, 42: 4},
    EM_AARCH64: {
        257: 8,
        260: 8,
        261: 4,
        275: 4,
        277: 4,
        282: 4,
        283: 4,
        311: 4,
        312: 4,
        313: 4,
        314: 4,
    },
}


@dataclass(frozen=True)
class GraphLimits:
    max_seeds: int = 4096
    max_functions: int = 100_000
    max_edges: int = 100_000
    max_gaps: int = 256
    max_instructions: int = 1_000_000
    max_decode_bytes: int = 64 * 1024 * 1024
    max_relocations: int = 100_000
    max_objdump_bytes: int = 4 * 1024 * 1024
    max_objdump_line_bytes: int = 4096


DEFAULT_GRAPH_LIMITS = GraphLimits()


class _CapstoneRow(Protocol):
    address: int
    bytes: bytes
    mnemonic: str
    op_str: str


class _CapstoneDecoder(Protocol):
    detail: bool

    def disasm(self, code: bytes, address: int) -> Iterable[_CapstoneRow]: ...


class _CapstoneModule(Protocol):
    __name__: str
    __version__: str
    CS_ARCH_X86: int
    CS_MODE_64: int

    def Cs(self, architecture: int, mode: int, /) -> _CapstoneDecoder: ...  # noqa: N802


@dataclass(frozen=True)
class GraphSeed:
    identifier: str
    kind: str
    file_offset: int
    size: int
    name: str | None = None
    is_function: bool = False


@dataclass(frozen=True)
class ArtifactNode:
    identifier: str
    kind: str
    file_offset: int
    virtual_address: int | None
    size: int
    name: str | None


@dataclass(frozen=True)
class FunctionNode:
    identifier: str
    file_offset: int
    virtual_address: int
    size: int
    names: tuple[str, ...]
    boundary_methods: tuple[str, ...]


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    kind: Literal[
        "relocation_reference",
        "pc_relative_reference",
        "absolute_reference",
        "direct_call",
        "tail_call",
    ]
    instruction_file_offset: int
    qualified: bool


@dataclass(frozen=True)
class GraphGap:
    code: str
    reason: str
    file_offset: int | None = None


@dataclass(frozen=True)
class DecodedInstruction:
    address: int
    raw: bytes
    mnemonic: str
    operands: str
    pc_relative_targets: tuple[int, ...] = ()
    absolute_targets: tuple[int, ...] = ()


@dataclass(frozen=True)
class InstructionPacket:
    instructions: tuple[DecodedInstruction, ...]
    gaps: tuple[GraphGap, ...]
    limited: bool


@dataclass(frozen=True)
class EvidenceGraph:
    machine: int
    artifacts: tuple[ArtifactNode, ...]
    functions: tuple[FunctionNode, ...]
    edges: tuple[GraphEdge, ...]
    gaps: tuple[GraphGap, ...]
    limited: bool
    patch_status: Literal["unknown"] = "unknown"

    def as_dict(self) -> dict[str, Any]:
        """Return canonical JSON-compatible graph evidence."""
        return json.loads(json.dumps(asdict(self), sort_keys=True))


@dataclass
class _FunctionBuilder:
    file_offset: int
    virtual_address: int
    size: int
    names: set[str]
    methods: set[str]


@dataclass(frozen=True)
class _DecodeRange:
    file_offset: int
    virtual_address: int
    size: int
    priority: bool


class _GapCollector:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.values: list[GraphGap] = []
        self.keys: set[tuple[str, str, int | None]] = set()
        self.limited = False

    def add(self, code: str, reason: str, file_offset: int | None = None) -> None:
        key = code, reason, file_offset
        if key in self.keys:
            return
        self.keys.add(key)
        if len(self.values) < self.limit:
            self.values.append(GraphGap(code, reason, file_offset))
        else:
            self.limited = True


def _function_id(offset: int) -> str:
    return f"function:0x{offset:x}"


def _validate_limits(limits: GraphLimits) -> None:
    if any(value <= 0 for value in asdict(limits).values()):
        msg = "Graph limits must be positive"
        raise ValueError(msg)


class _GraphBuilder:
    def __init__(self, data: Buffer, limits: GraphLimits) -> None:
        self.data = data
        self.limits = limits
        self.header = elf_header(data)
        if self.header[1] not in (2, 3):
            msg = "Function graph requires a linked ELF executable or shared object"
            raise ValueError(msg)
        self.layout = ELFLayout.of(self.header)
        self.machine = self.header[2]
        self.gaps = _GapCollector(limits.max_gaps)
        self.segments = []
        for kind, flags, offset, virtual, _, size, memory_size, _ in program_headers(
            data, self.header
        ):
            if kind != PT_LOAD or not size:
                continue
            try:
                checked_range(data, offset, size)
            except ValueError:
                self.gaps.add(
                    "malformed_load_segment",
                    "PT_LOAD file range is outside the supplied artifact",
                    offset,
                )
                continue
            if size > memory_size:
                self.gaps.add(
                    "malformed_load_segment",
                    "PT_LOAD file size exceeds its memory size",
                    offset,
                )
                continue
            self.segments.append((offset, virtual, size, flags))
        self.functions: dict[int, _FunctionBuilder] = {}
        self.function_starts: list[int] = []
        self.function_owner_ranges: list[tuple[int, int, int]] = []
        self.function_owner_starts: list[int] = []
        self.function_covered_ranges: list[tuple[int, int]] = []
        self.function_covered_starts: list[int] = []
        self.function_bounds_finalized = False
        self.artifacts: dict[str, ArtifactNode] = {}
        self.edges: set[GraphEdge] = set()
        self.instructions_seen = 0
        self.decode_bytes = 0

    def _unique_mapping(
        self,
        candidates: set[int],
        *,
        file_offset: int | None = None,
    ) -> int | None:
        if len(candidates) == 1:
            return next(iter(candidates))
        if len(candidates) > 1:
            self.gaps.add(
                "ambiguous_load_mapping",
                "ELF range has multiple conflicting PT_LOAD mappings",
                file_offset,
            )
        return None

    def address_to_offset(
        self, address: int, size: int = 1, *, executable: bool = False
    ) -> int | None:
        candidates = {
            offset + address - virtual
            for offset, virtual, file_size, flags in self.segments
            if (not executable or flags & PF_X)
            and virtual <= address
            and address + size <= virtual + file_size
        }
        return self._unique_mapping(candidates)

    def offset_to_address(self, offset: int, size: int = 1) -> int | None:
        candidates = {
            virtual + offset - segment_offset
            for segment_offset, virtual, file_size, _ in self.segments
            if segment_offset <= offset and offset + size <= segment_offset + file_size
        }
        return self._unique_mapping(candidates, file_offset=offset)

    def executable_end(self, offset: int) -> int | None:
        candidates = {
            segment_offset + file_size
            for segment_offset, _, file_size, flags in self.segments
            if flags & PF_X and segment_offset <= offset < segment_offset + file_size
        }
        return self._unique_mapping(candidates, file_offset=offset)

    def add_function(
        self,
        offset: int,
        address: int,
        size: int,
        *,
        name: str | None,
        method: str,
    ) -> str | None:
        if offset not in self.functions and len(self.functions) >= self.limits.max_functions:
            self.gaps.add("function_limit", "Function-node limit reached")
            return None
        value = self.functions.get(offset)
        if value is None:
            if self.function_bounds_finalized and self._range_overlaps_functions(
                offset, offset + max(size, 1)
            ):
                self.gaps.add(
                    "ambiguous_function_bounds",
                    "Derived function bounds overlap an existing distinct function",
                    offset,
                )
                return None
            value = _FunctionBuilder(offset, address, max(size, 1), set(), set())
            self.functions[offset] = value
            insort(self.function_starts, offset)
            if self.function_bounds_finalized:
                insort(self.function_owner_ranges, (offset, offset + value.size, offset))
                insort(self.function_owner_starts, offset)
                insort(self.function_covered_ranges, (offset, offset + value.size))
                insort(self.function_covered_starts, offset)
        previous_size = value.size
        value.size = max(value.size, size, 1)
        if name:
            value.names.add(name)
        value.methods.add(method)
        if self.function_bounds_finalized and value.size != previous_size:
            self.finalize_function_bounds()
        return _function_id(offset)

    def finalize_function_bounds(self) -> None:  # noqa: C901, PLR0912 -- Interval sweep.
        events: dict[int, list[tuple[bool, int]]] = {}
        for value in self.functions.values():
            events.setdefault(value.file_offset, []).append((True, value.file_offset))
            events.setdefault(value.file_offset + value.size, []).append((False, value.file_offset))
        owners: list[tuple[int, int, int]] = []
        covered: list[tuple[int, int]] = []
        ambiguous: list[tuple[int, int]] = []
        active: set[int] = set()
        previous: int | None = None
        for position in sorted(events):
            if previous is not None and previous < position and active:
                if covered and covered[-1][1] == previous:
                    covered[-1] = (covered[-1][0], position)
                else:
                    covered.append((previous, position))
                if len(active) == 1:
                    owner = next(iter(active))
                    if owners and owners[-1][1:] == (previous, owner):
                        owners[-1] = (owners[-1][0], position, owner)
                    else:
                        owners.append((previous, position, owner))
                elif ambiguous and ambiguous[-1][1] == previous:
                    ambiguous[-1] = (ambiguous[-1][0], position)
                else:
                    ambiguous.append((previous, position))
            for starting, owner in events[position]:
                if starting:
                    active.add(owner)
                else:
                    active.discard(owner)
            previous = position
        self.function_owner_ranges = owners
        self.function_owner_starts = [item[0] for item in owners]
        self.function_covered_ranges = covered
        self.function_covered_starts = [item[0] for item in covered]
        self.function_bounds_finalized = True
        for start, _ in ambiguous:
            self.gaps.add(
                "ambiguous_function_bounds",
                "Distinct function starts have overlapping bounds; ownership is unresolved",
                start,
            )

    def _range_overlaps_functions(self, start: int, end: int) -> bool:
        if not self.function_covered_ranges or end <= start:
            return False
        index = bisect_right(self.function_covered_starts, start) - 1
        if index >= 0 and self.function_covered_ranges[index][1] > start:
            return True
        next_index = index + 1
        return (
            next_index < len(self.function_covered_ranges)
            and self.function_covered_ranges[next_index][0] < end
        )

    def add_artifact(self, seed: GraphSeed) -> ArtifactNode:
        node = ArtifactNode(
            seed.identifier,
            seed.kind,
            seed.file_offset,
            self.offset_to_address(seed.file_offset, seed.size),
            seed.size,
            seed.name,
        )
        self.artifacts[node.identifier] = node
        return node

    def function_at(self, offset: int, size: int = 1) -> _FunctionBuilder | None:
        if not self.function_bounds_finalized:
            self.finalize_function_bounds()
        if not self.function_owner_ranges:
            return None
        index = bisect_right(self.function_owner_starts, offset) - 1
        if index < 0:
            return None
        start, end, owner = self.function_owner_ranges[index]
        if start <= offset and offset + size <= end:
            return self.functions[owner]
        if self._range_overlaps_functions(offset, offset + size):
            self.gaps.add(
                "ambiguous_function_bounds",
                "Instruction range does not have unique function ownership",
                offset,
            )
        return None

    def source_function(self, offset: int, address: int, size: int) -> str | None:
        value = self.function_at(offset, size)
        if value is not None:
            return _function_id(value.file_offset)
        if self._range_overlaps_functions(offset, offset + size):
            return None
        self.gaps.add(
            "function_bounds_unavailable",
            "Reference site has no symbol, unwind, or supplied function bounds",
            offset,
        )
        return self.add_function(offset, address, size, name=None, method="reference_site_only")

    def artifact_for_offset(self, offset: int) -> ArtifactNode | None:
        candidates = [
            artifact
            for artifact in self.artifacts.values()
            if artifact.file_offset <= offset < artifact.file_offset + artifact.size
        ]
        if len(candidates) > 1:
            self.gaps.add(
                "ambiguous_artifact_ownership",
                "Reference target belongs to multiple supplied artifact seeds",
                offset,
            )
            return None
        return candidates[0] if candidates else None

    def target_function(self, offset: int, address: int) -> str | None:
        value = self.function_at(offset)
        if value is not None:
            return _function_id(value.file_offset)
        return self.add_function(offset, address, 1, name=None, method="direct_branch_target")

    def add_edge(self, edge: GraphEdge) -> None:
        if edge in self.edges:
            return
        if len(self.edges) >= self.limits.max_edges:
            self.gaps.add("edge_limit", "Graph edge limit reached")
            return
        self.edges.add(edge)

    def freeze(self) -> EvidenceGraph:
        functions = tuple(
            FunctionNode(
                _function_id(value.file_offset),
                value.file_offset,
                value.virtual_address,
                value.size,
                tuple(sorted(value.names)),
                tuple(sorted(value.methods)),
            )
            for value in sorted(self.functions.values(), key=lambda item: item.file_offset)
        )
        return EvidenceGraph(
            self.machine,
            tuple(sorted(self.artifacts.values(), key=lambda item: item.identifier)),
            functions,
            tuple(
                sorted(
                    self.edges,
                    key=lambda edge: (
                        edge.instruction_file_offset,
                        edge.kind,
                        edge.source,
                        edge.target,
                    ),
                )
            ),
            tuple(self.gaps.values),
            self.gaps.limited or any(gap.code.endswith("_limit") for gap in self.gaps.values),
        )


def seeds_from_assessment(  # noqa: C901
    assessment: dict[str, Any], max_seeds: int = 4096
) -> tuple[GraphSeed, ...]:
    """Derive graph seeds from the canonical binary assessment without changing verdicts."""
    seeds = []
    for match in assessment.get("code_matches", []):
        if isinstance(match, dict):
            seeds.append(
                GraphSeed(
                    f"exact:{match.get('id', len(seeds))}:{match.get('file_offset', -1)}",
                    "exact_code_region",
                    match.get("file_offset", -1),
                    match.get("size_bytes", 0),
                )
            )
    flirt = assessment.get("flirt", {})
    if isinstance(flirt, dict):
        for match in flirt.get("matches", []):
            if isinstance(match, dict):
                seeds.append(
                    GraphSeed(
                        "flirt:"
                        f"{match.get('signature_id', len(seeds))}:"
                        f"{match.get('file_offset', -1)}",
                        "flirt_function",
                        match.get("file_offset", -1),
                        match.get("size_bytes", 0),
                        match.get("definitive_name"),
                        is_function=True,
                    )
                )
    recognition = assessment.get("recognition", {})
    if isinstance(recognition, dict):
        for match in recognition.get("matches", []):
            if isinstance(match, dict):
                seeds.append(
                    GraphSeed(
                        f"table:{match.get('id', len(seeds))}:{match.get('file_offset', -1)}",
                        "decoder_table",
                        match.get("file_offset", -1),
                        match.get("size_bytes", 0),
                        match.get("id"),
                    )
                )
    if len(seeds) > max_seeds:
        msg = "Assessment graph seed limit reached"
        raise ValueError(msg)
    return tuple(seeds)


def _validate_seeds(builder: _GraphBuilder, seeds: Iterable[GraphSeed]) -> None:
    seen = set()
    for count, seed in enumerate(seeds, 1):
        if count > builder.limits.max_seeds:
            builder.gaps.add("seed_limit", "Graph seed limit reached")
            return
        if (
            not seed.identifier
            or seed.identifier in seen
            or type(seed.file_offset) is not int
            or type(seed.size) is not int
            or seed.file_offset < 0
            or seed.size <= 0
            or seed.file_offset > len(builder.data)
            or seed.size > len(builder.data) - seed.file_offset
        ):
            msg = "Invalid or duplicate graph seed"
            raise ValueError(msg)
        seen.add(seed.identifier)
        address = builder.offset_to_address(seed.file_offset, seed.size)
        if address is None:
            builder.gaps.add(
                "seed_not_mapped", "Seed is not wholly file-backed by one PT_LOAD", seed.file_offset
            )
            continue
        if seed.is_function:
            if builder.address_to_offset(address, seed.size, executable=True) != seed.file_offset:
                builder.gaps.add(
                    "function_seed_not_executable",
                    "Function seed is not wholly file-backed by one executable PT_LOAD",
                    seed.file_offset,
                )
                continue
            builder.add_function(
                seed.file_offset,
                address,
                seed.size,
                name=seed.name,
                method=seed.kind,
            )
        else:
            builder.add_artifact(seed)


def _owned_symbol_offset(  # noqa: PLR0913 -- Complete ownership query.
    builder: _GraphBuilder,
    sections: list[tuple],
    section_index: int,
    address: int,
    size: int,
    *,
    executable: bool,
    gap_code: str,
    subject: str,
) -> int | None:
    if section_index >= len(sections):
        builder.gaps.add(gap_code, f"{subject} has no valid owning section")
        return None
    owner = sections[section_index]
    required_flags = SHF_ALLOC | (PF_X if executable else 0)
    span = max(size, 1)
    if (
        owner[1] == SHT_NOBITS
        or owner[2] & required_flags != required_flags
        or address < owner[3]
        or address + span > owner[3] + owner[5]
    ):
        builder.gaps.add(gap_code, f"{subject} is outside its allocated file-backed section")
        return None
    try:
        checked_range(builder.data, owner[4], owner[5])
    except ValueError:
        builder.gaps.add(gap_code, f"{subject} section is outside the supplied artifact")
        return None
    expected = owner[4] + address - owner[3]
    mapped = builder.address_to_offset(address, span, executable=executable)
    if mapped != expected:
        builder.gaps.add(
            gap_code,
            f"{subject} section disagrees with its PT_LOAD mapping",
            expected,
        )
        return None
    return mapped


def _read_symbol_functions_checked(builder: _GraphBuilder) -> None:  # noqa: C901
    if not builder.header[12]:
        return
    sections = section_headers(builder.data, builder.header)
    parser = builder.layout.parser("symbol")
    symbols_seen = 0
    for table in sections:
        if table[1] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if table[9] != parser.size or table[5] % parser.size or table[6] >= len(sections):
            builder.gaps.add("malformed_symbols", "Malformed ELF symbol table")
            return
        strings = sections[table[6]]
        if strings[1] != SHT_STRTAB:
            builder.gaps.add("malformed_symbols", "ELF symbol table lacks a string table")
            return
        string_start, string_end = checked_range(builder.data, strings[4], strings[5])
        symbols_seen += table[5] // parser.size
        if symbols_seen > builder.limits.max_functions * 4:
            builder.gaps.add("symbol_limit", "Symbol inspection limit reached")
            return
        for name_offset, info, _, index, address, size in symbol_rows(
            builder.data, builder.header, table
        ):
            if info & 0xF != STT_FUNC or index == SHN_UNDEF:
                continue
            offset = _owned_symbol_offset(
                builder,
                sections,
                index,
                address,
                size,
                executable=True,
                gap_code="inconsistent_function_symbol",
                subject="Function symbol",
            )
            if offset is None:
                continue
            name = _string(builder.data, string_start, string_end, name_offset)
            builder.add_function(offset, address, max(size, 1), name=name, method="elf_symbol")


def _read_symbol_functions(builder: _GraphBuilder) -> None:
    try:
        _read_symbol_functions_checked(builder)
    except (ValueError, struct.error) as error:
        builder.gaps.add("malformed_symbols", f"Cannot parse ELF function symbols: {error}")


def _string(data: Buffer, start: int, end: int, offset: int) -> str | None:
    if offset < 0 or start + offset >= end:
        return None
    value_start = start + offset
    value_end = data.find(b"\0", value_start, min(value_start + MAX_NAME_BYTES, end))
    if value_end < 0:
        return None
    try:
        return data[value_start:value_end].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _read_eh_frame_starts(builder: _GraphBuilder) -> None:
    found = False
    for kind, _, offset, virtual, _, size, _, _ in program_headers(builder.data, builder.header):
        if kind != PT_GNU_EH_FRAME or not size:
            continue
        found = True
        try:
            _parse_eh_frame_header(builder, offset, virtual, size)
        except ValueError as error:
            builder.gaps.add("unsupported_unwind", str(error), offset)
    if not found and not builder.functions and builder.artifacts:
        builder.gaps.add(
            "function_starts_unavailable",
            "No ELF symbols, supplied function seeds, or PT_GNU_EH_FRAME function starts",
        )


def _parse_eh_frame_header(builder: _GraphBuilder, offset: int, virtual: int, size: int) -> None:
    raw = checked_slice(builder.data, offset, size)
    if len(raw) < EH_FRAME_HEADER_BYTES or raw[0] != 1:
        msg = "Unsupported .eh_frame_hdr version"
        raise ValueError(msg)
    cursor = 4
    _, cursor = _encoded_value(
        raw, cursor, raw[1], virtual, virtual, builder.layout.bits, builder.layout.byteorder
    )
    count, cursor = _encoded_value(
        raw, cursor, raw[2], virtual, virtual, builder.layout.bits, builder.layout.byteorder
    )
    if count < 0 or count > builder.limits.max_functions:
        msg = ".eh_frame_hdr function count exceeds the graph limit"
        raise ValueError(msg)
    starts = []
    for _ in range(count):
        address, cursor = _encoded_value(
            raw, cursor, raw[3], virtual, virtual, builder.layout.bits, builder.layout.byteorder
        )
        _, cursor = _encoded_value(
            raw, cursor, raw[3], virtual, virtual, builder.layout.bits, builder.layout.byteorder
        )
        file_offset = builder.address_to_offset(address, 1, executable=True)
        if file_offset is not None:
            starts.append((file_offset, address))
    ordered = sorted(set(starts))
    for index, (file_offset, address) in enumerate(ordered):
        segment_end = builder.executable_end(file_offset) or file_offset + 1
        next_offset = ordered[index + 1][0] if index + 1 < len(ordered) else segment_end
        next_offset = min(next_offset, segment_end)
        builder.add_function(
            file_offset,
            address,
            max(1, next_offset - file_offset),
            name=None,
            method="eh_frame_hdr",
        )


def _encoded_value(  # noqa: PLR0913, PLR0917
    data: bytes,
    cursor: int,
    encoding: int,
    section_address: int,
    datarel_base: int,
    bits: int,
    byteorder: Literal["little", "big"] = "little",
) -> tuple[int, int]:
    if encoding == DW_EH_PE_OMIT or encoding & DW_EH_PE_INDIRECT:
        msg = "Unsupported omitted/indirect .eh_frame_hdr encoding"
        raise ValueError(msg)
    formats = {
        0x00: (bits // 8, False),
        0x02: (2, False),
        0x03: (4, False),
        0x04: (8, False),
        0x0A: (2, True),
        0x0B: (4, True),
        0x0C: (8, True),
    }
    if encoding & 0x0F not in formats:
        msg = "Unsupported variable-length .eh_frame_hdr encoding"
        raise ValueError(msg)
    size, signed = formats[encoding & 0x0F]
    if cursor + size > len(data):
        msg = "Truncated .eh_frame_hdr table"
        raise ValueError(msg)
    value = int.from_bytes(data[cursor : cursor + size], byteorder, signed=signed)
    application = encoding & 0x70
    if application == DW_EH_PE_PCREL:
        value += section_address + cursor
    elif application == DW_EH_PE_DATAREL:
        value += datarel_base
    elif application:
        msg = "Unsupported relative .eh_frame_hdr encoding"
        raise ValueError(msg)
    return value, cursor + size


def parse_objdump_instructions(  # noqa: C901
    text: str, limits: GraphLimits = DEFAULT_GRAPH_LIMITS
) -> InstructionPacket:
    """Parse bounded GNU-style x86 instruction rows from trusted objdump output."""
    _validate_limits(limits)
    if len(text.encode("utf-8")) > limits.max_objdump_bytes:
        gap = GraphGap("objdump_output_limit", "Objdump evidence exceeds the byte limit")
        return InstructionPacket((), (gap,), limited=True)
    instructions = []
    gaps = _GapCollector(limits.max_gaps)
    for line in text.splitlines():
        if len(line.encode("utf-8")) > limits.max_objdump_line_bytes:
            gaps.add("objdump_line_limit", "Objdump line exceeds the byte limit")
            continue
        match = OBJDUMP_PREFIX.fullmatch(line)
        if match is None:
            continue
        if len(instructions) >= limits.max_instructions:
            gaps.add("instruction_limit", "Decoded-instruction limit reached")
            break
        try:
            tokens = match[2].split()
            raw_tokens = []
            while tokens and HEX_BYTE.fullmatch(tokens[0]):
                raw_tokens.append(tokens.pop(0))
            if not raw_tokens or not tokens:
                continue
            raw = bytes.fromhex("".join(raw_tokens))
            address = int(match[1], 16)
            mnemonic = tokens.pop(0).lower()
            operands = " ".join(tokens)
        except ValueError:
            gaps.add("malformed_objdump", "Malformed objdump instruction row")
            continue
        if raw:
            instructions.append(DecodedInstruction(address, raw, mnemonic, operands))
    return InstructionPacket(
        tuple(instructions), tuple(gaps.values), gaps.limited or bool(gaps.values)
    )


def _merge_decode_ranges(ranges: Iterable[_DecodeRange]) -> list[_DecodeRange]:
    merged = []
    for value in sorted(ranges, key=lambda item: (item.file_offset, item.virtual_address)):
        if not value.size:
            continue
        if (
            merged
            and merged[-1].priority == value.priority
            and merged[-1].file_offset + merged[-1].size >= value.file_offset
            and merged[-1].virtual_address - merged[-1].file_offset
            == value.virtual_address - value.file_offset
        ):
            previous = merged[-1]
            end = max(previous.file_offset + previous.size, value.file_offset + value.size)
            merged[-1] = _DecodeRange(
                previous.file_offset,
                previous.virtual_address,
                end - previous.file_offset,
                previous.priority,
            )
        else:
            merged.append(value)
    return merged


def _subtract_priority(value: _DecodeRange, priority: list[_DecodeRange]) -> list[_DecodeRange]:
    pieces = [value]
    for selected in priority:
        updated = []
        selected_end = selected.file_offset + selected.size
        for piece in pieces:
            piece_end = piece.file_offset + piece.size
            if selected_end <= piece.file_offset or piece_end <= selected.file_offset:
                updated.append(piece)
                continue
            if piece.file_offset < selected.file_offset:
                updated.append(
                    _DecodeRange(
                        piece.file_offset,
                        piece.virtual_address,
                        selected.file_offset - piece.file_offset,
                        priority=False,
                    )
                )
            if selected_end < piece_end:
                updated.append(
                    _DecodeRange(
                        selected_end,
                        piece.virtual_address + selected_end - piece.file_offset,
                        piece_end - selected_end,
                        priority=False,
                    )
                )
        pieces = updated
    return pieces


def _decode_ranges(
    builder: _GraphBuilder,
    remaining: Iterable[_DecodeRange],
    *,
    alignment: int,
) -> tuple[_DecodeRange, ...]:
    """Prioritize supplied code windows, deduplicate overlap, and apply one byte budget."""
    priority = [
        _DecodeRange(
            function.file_offset,
            function.virtual_address,
            function.size,
            priority=True,
        )
        for function in builder.functions.values()
        if function.methods - DERIVED_FUNCTION_METHODS
    ]
    priority.extend(
        _DecodeRange(
            artifact.file_offset,
            artifact.virtual_address,
            artifact.size,
            priority=True,
        )
        for artifact in builder.artifacts.values()
        if (
            artifact.kind == "exact_code_region"
            and artifact.virtual_address is not None
            and builder.address_to_offset(artifact.virtual_address, artifact.size, executable=True)
            == artifact.file_offset
        )
    )
    priority = _merge_decode_ranges(priority)
    residual = []
    for value in _merge_decode_ranges(remaining):
        residual.extend(_subtract_priority(value, priority))
    ordered = [*priority, *_merge_decode_ranges(residual)]
    selected = []
    left = builder.limits.max_decode_bytes
    omitted = False
    for index, value in enumerate(ordered):
        if value.priority:
            if value.size > left:
                builder.gaps.add(
                    "priority_decode_window_limit",
                    "A recognized code window exceeds the remaining decode-byte budget",
                    value.file_offset,
                )
                builder.gaps.limited = True
                omitted = True
                continue
            take = value.size
        else:
            take = min(value.size, left)
            take -= take % alignment
            omitted = omitted or take < value.size
        if take:
            selected.append(
                _DecodeRange(value.file_offset, value.virtual_address, take, value.priority)
            )
            left -= take
        if not left:
            omitted = omitted or index + 1 < len(ordered)
            break
    builder.decode_bytes = builder.limits.max_decode_bytes - left
    if omitted:
        builder.gaps.add(
            "unexamined_executable_ranges",
            "Executable ranges remain unexamined after the decode-byte budget",
        )
        builder.gaps.limited = True
    return tuple(selected)


def _capstone_instructions(  # noqa: C901, PLR0912
    builder: _GraphBuilder, module: _CapstoneModule | None
) -> InstructionPacket:
    if module is None:
        try:
            module = cast("_CapstoneModule", importlib.import_module("capstone"))
        except (ImportError, OSError) as error:
            gap = GraphGap(
                "capstone_unavailable",
                f"Optional Capstone {PINNED_CAPSTONE_VERSION} is unavailable: {error}",
            )
            return InstructionPacket((), (gap,), limited=False)
    version = getattr(module, "__version__", None)
    if getattr(module, "__name__", None) == "capstone":
        try:
            version = importlib.metadata.version("capstone")
        except importlib.metadata.PackageNotFoundError:
            version = None
    if version != PINNED_CAPSTONE_VERSION:
        gap = GraphGap(
            "capstone_version_unsupported",
            f"Expected Capstone {PINNED_CAPSTONE_VERSION}",
        )
        return InstructionPacket((), (gap,), limited=False)
    try:
        decoder = module.Cs(module.CS_ARCH_X86, module.CS_MODE_64)
        decoder.detail = True
    except (AttributeError, ValueError) as error:
        gap = GraphGap("capstone_api_unsupported", f"Cannot initialize Capstone: {error}")
        return InstructionPacket((), (gap,), limited=False)
    instructions = []
    remaining = (
        _DecodeRange(offset, virtual, size, priority=False)
        for offset, virtual, size, flags in builder.segments
        if flags & PF_X
    )
    for window in _decode_ranges(builder, remaining, alignment=1):
        code = checked_slice(builder.data, window.file_offset, window.size)
        try:
            rows = decoder.disasm(code, window.virtual_address)
            for row in rows:
                if len(instructions) >= builder.limits.max_instructions:
                    gap = GraphGap("instruction_limit", "Decoded-instruction limit reached")
                    return InstructionPacket(tuple(instructions), (gap,), limited=True)
                targets = []
                absolute_targets = []
                constants = getattr(module, "x86_const", None)
                for operand in getattr(row, "operands", ()):
                    memory = getattr(operand, "mem", None)
                    if (
                        constants is not None
                        and getattr(operand, "type", None) == getattr(constants, "X86_OP_MEM", None)
                        and memory is not None
                        and getattr(memory, "base", None) == getattr(constants, "X86_REG_RIP", None)
                    ):
                        targets.append(
                            int(row.address)
                            + len(bytes(row.bytes))
                            + int(getattr(memory, "disp", 0))
                        )
                    elif (
                        constants is not None
                        and getattr(operand, "type", None) == getattr(constants, "X86_OP_MEM", None)
                        and memory is not None
                        and getattr(memory, "base", None) == 0
                        and int(getattr(memory, "disp", 0)) > 0
                    ):
                        absolute_targets.append(int(getattr(memory, "disp", 0)))
                instructions.append(
                    DecodedInstruction(
                        int(row.address),
                        bytes(row.bytes),
                        str(row.mnemonic).lower(),
                        str(row.op_str),
                        tuple(targets),
                        tuple(absolute_targets),
                    )
                )
        except (AttributeError, ValueError) as error:
            gap = GraphGap(
                "capstone_decode_error",
                f"Cannot decode supplied function range: {error}",
                window.file_offset,
            )
            return InstructionPacket(tuple(instructions), (gap,), limited=True)
    return InstructionPacket(tuple(instructions), (), limited=False)


def _decode_aarch64(builder: _GraphBuilder) -> None:  # noqa: C901, PLR0912
    remaining = (
        _DecodeRange(offset, virtual, size, priority=False)
        for offset, virtual, size, flags in builder.segments
        if flags & PF_X
    )
    for window in _decode_ranges(builder, remaining, alignment=4):
        pending_adrp: tuple[int, int, int] | None = None
        if (window.file_offset - window.virtual_address) % 4 or window.size % 4:
            builder.gaps.add(
                "unsupported_instruction_mode",
                "AArch64 executable mapping or decode window is not instruction aligned",
                window.file_offset,
            )
            continue
        for chunk_start in range(0, window.size, AARCH64_CHUNK_BYTES):
            chunk = builder.data[
                window.file_offset + chunk_start : window.file_offset
                + min(window.size, chunk_start + AARCH64_CHUNK_BYTES)
            ]
            for chunk_offset in range(0, len(chunk), 4):
                builder.instructions_seen += 1
                if builder.instructions_seen > builder.limits.max_instructions:
                    builder.gaps.add("instruction_limit", "Decoded-instruction limit reached")
                    return
                relative = chunk_start + chunk_offset
                offset = window.file_offset + relative
                address = window.virtual_address + relative
                word = int.from_bytes(
                    chunk[chunk_offset : chunk_offset + 4], builder.layout.byteorder
                )
                if word & 0x9F000000 == AARCH64_ADRP:
                    immediate = _sign_extend(((word >> 5) & 0x7FFFF) << 2 | (word >> 29) & 3, 21)
                    pending_adrp = (
                        word & 31,
                        (address & ~0xFFF) + (immediate << 12),
                        address,
                    )
                    continue
                if word & 0x9F000000 == AARCH64_ADR:
                    immediate = _sign_extend(((word >> 5) & 0x7FFFF) << 2 | (word >> 29) & 3, 21)
                    _add_data_reference(builder, offset, address, address + immediate)
                elif (
                    pending_adrp is not None
                    and pending_adrp[2] + 4 == address
                    and word & 0x7F000000 == AARCH64_ADD_IMMEDIATE
                ):
                    rd, rn = word & 31, (word >> 5) & 31
                    if rd == rn == pending_adrp[0]:
                        immediate = (word >> 10) & 0xFFF
                        if word & (1 << 22):
                            immediate <<= 12
                        _add_data_reference(builder, offset, address, pending_adrp[1] + immediate)
                elif word & 0x3B000000 == AARCH64_LDR_LITERAL:
                    immediate = _sign_extend((word >> 5) & 0x7FFFF, 19) << 2
                    _add_data_reference(builder, offset, address, address + immediate)
                elif word & 0xFC000000 in (0x14000000, 0x94000000):
                    immediate = _sign_extend(word & 0x3FFFFFF, 26) << 2
                    _add_direct_branch(
                        builder,
                        offset,
                        4,
                        address + immediate,
                        call=word & 0xFC000000 == AARCH64_BL,
                    )
                elif word & 0xFFFFFC1F in (AARCH64_BR, AARCH64_BLR):
                    if builder.function_at(offset, 4) is not None:
                        builder.gaps.add(
                            "unresolved_indirect_transfer",
                            "AArch64 indirect branch/call target is unresolved",
                        )
                if pending_adrp is not None and pending_adrp[2] + 4 <= address:
                    pending_adrp = None


def _riscv_jal_immediate(word: int) -> int:
    value = (
        ((word >> 31) & 1) << 20
        | ((word >> 21) & 0x3FF) << 1
        | ((word >> 20) & 1) << 11
        | ((word >> 12) & 0xFF) << 12
    )
    return _sign_extend(value, 21)


def _riscv_compressed_jump_immediate(halfword: int) -> int:
    value = (
        ((halfword >> 12) & 1) << 11
        | ((halfword >> 11) & 1) << 4
        | ((halfword >> 9) & 3) << 8
        | ((halfword >> 8) & 1) << 10
        | ((halfword >> 7) & 1) << 6
        | ((halfword >> 6) & 1) << 7
        | ((halfword >> 3) & 7) << 1
        | ((halfword >> 2) & 1) << 5
    )
    return _sign_extend(value, 12)


def _decode_riscv_word(
    builder: _GraphBuilder,
    word: int,
    offset: int,
    address: int,
    pending: tuple[int, int, int, Literal["pc_relative_reference", "absolute_reference"]] | None,
) -> tuple[int, int, int, Literal["pc_relative_reference", "absolute_reference"]] | None:
    opcode = word & 0x7F
    rd, rs1 = (word >> 7) & 31, (word >> 15) & 31
    if opcode == RISCV_OPCODE_AUIPC:
        return rd, address + _sign_extend(word & 0xFFFFF000, 32), address, "pc_relative_reference"
    if opcode == RISCV_OPCODE_LUI:
        return rd, _sign_extend(word & 0xFFFFF000, 32), address, "absolute_reference"
    if opcode == RISCV_OPCODE_JAL:
        if rd in {0, 1, 5}:
            _add_direct_branch(
                builder,
                offset,
                4,
                address + _riscv_jal_immediate(word),
                call=rd in {1, 5},
            )
        return None
    if pending is not None and pending[2] + 4 == address and rs1 == pending[0]:
        _decode_riscv_pending(builder, word, offset, address, pending)
    elif opcode == RISCV_OPCODE_JALR and builder.function_at(offset, 4) is not None:
        builder.gaps.add(
            "unresolved_indirect_transfer",
            "RISC-V indirect branch/call target is unresolved",
        )
    return None


def _decode_riscv_pending(
    builder: _GraphBuilder,
    word: int,
    offset: int,
    address: int,
    pending: tuple[int, int, int, Literal["pc_relative_reference", "absolute_reference"]],
) -> None:
    opcode, rd = word & 0x7F, (word >> 7) & 31
    immediate = _sign_extend(word >> 20, 12)
    if opcode in {RISCV_OPCODE_OP_IMM, RISCV_OPCODE_LOAD} and (
        opcode == RISCV_OPCODE_LOAD or (word >> 12) & 7 == 0
    ):
        _add_data_reference(
            builder,
            offset,
            address,
            pending[1] + immediate,
            kind=pending[3],
        )
    elif opcode == RISCV_OPCODE_JALR and (word >> 12) & 7 == 0 and rd in {0, 1, 5}:
        _add_direct_branch(
            builder,
            offset,
            4,
            (pending[1] + immediate) & ~1,
            call=rd in {1, 5},
        )


def _decode_riscv_compressed(
    builder: _GraphBuilder,
    halfword: int,
    offset: int,
    address: int,
    *,
    permitted: bool,
) -> None:
    if not permitted:
        builder.gaps.add(
            "unsupported_instruction_mode",
            "RISC-V compressed instruction lacks EF_RISCV_RVC",
            offset,
        )
    elif halfword & 0xE003 == RISCV_COMPRESSED_JUMP:
        _add_direct_branch(
            builder,
            offset,
            RISCV_COMPRESSED_INSTRUCTION_BYTES,
            address + _riscv_compressed_jump_immediate(halfword),
            call=False,
        )
    elif (
        halfword & 0xF07F in {0x8002, 0x9002}
        and builder.function_at(offset, RISCV_COMPRESSED_INSTRUCTION_BYTES) is not None
    ):
        builder.gaps.add(
            "unresolved_indirect_transfer",
            "RISC-V compressed indirect transfer is unresolved",
        )


def _decode_riscv(builder: _GraphBuilder) -> None:
    remaining = (
        _DecodeRange(offset, virtual, size, priority=False)
        for offset, virtual, size, flags in builder.segments
        if flags & PF_X
    )
    permits_compressed = bool(builder.header[7] & EF_RISCV_RVC)
    for window in _decode_ranges(builder, remaining, alignment=2):
        if (window.file_offset - window.virtual_address) % 2 or window.size % 2:
            builder.gaps.add(
                "unsupported_instruction_mode",
                "RISC-V executable mapping or decode window is not halfword aligned",
                window.file_offset,
            )
            continue
        pending: (
            tuple[int, int, int, Literal["pc_relative_reference", "absolute_reference"]] | None
        ) = None
        relative = 0
        while relative < window.size:
            chunk_start = relative
            chunk_stop = min(window.size, chunk_start + RISCV_CHUNK_BYTES)
            chunk = builder.data[
                window.file_offset + chunk_start : window.file_offset
                + min(window.size, chunk_stop + 2)
            ]
            while relative < chunk_stop:
                local = relative - chunk_start
                halfword = int.from_bytes(chunk[local : local + 2], "little")
                instruction_size = (
                    RISCV_COMPRESSED_INSTRUCTION_BYTES
                    if halfword & RISCV_LONG_INSTRUCTION_MASK != RISCV_LONG_INSTRUCTION_MASK
                    else 4
                )
                offset, address = (
                    window.file_offset + relative,
                    window.virtual_address + relative,
                )
                builder.instructions_seen += 1
                if builder.instructions_seen > builder.limits.max_instructions:
                    builder.gaps.add("instruction_limit", "Decoded-instruction limit reached")
                    return
                if relative + instruction_size > window.size:
                    builder.gaps.add(
                        "unsupported_instruction_mode",
                        "RISC-V executable range ends within an instruction",
                        offset,
                    )
                    return
                if instruction_size == RISCV_COMPRESSED_INSTRUCTION_BYTES:
                    _decode_riscv_compressed(
                        builder,
                        halfword,
                        offset,
                        address,
                        permitted=permits_compressed,
                    )
                    pending = None
                else:
                    word = int.from_bytes(chunk[local : local + 4], "little")
                    pending = _decode_riscv_word(builder, word, offset, address, pending)
                relative += instruction_size


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _add_data_reference(  # noqa: PLR0913 -- Bound instruction and target evidence.
    builder: _GraphBuilder,
    instruction_offset: int,
    instruction_address: int,
    target: int,
    *,
    instruction_size: int = 4,
    kind: Literal["pc_relative_reference", "absolute_reference"] = "pc_relative_reference",
) -> None:
    target_offset = builder.address_to_offset(target)
    if target_offset is None:
        return
    artifact = builder.artifact_for_offset(target_offset)
    if artifact is None:
        return
    source = builder.source_function(instruction_offset, instruction_address, instruction_size)
    if source is not None:
        builder.add_edge(
            GraphEdge(
                source=source,
                target=artifact.identifier,
                kind=kind,
                instruction_file_offset=instruction_offset,
                qualified=True,
            )
        )


def _add_direct_branch(
    builder: _GraphBuilder,
    instruction_offset: int,
    instruction_size: int,
    target: int,
    *,
    call: bool,
) -> None:
    target_offset = builder.address_to_offset(target, executable=True)
    if target_offset is None:
        return
    source_value = builder.function_at(instruction_offset, instruction_size)
    source = _function_id(source_value.file_offset) if source_value is not None else None
    target_id = builder.target_function(target_offset, target)
    if source is not None and target_id is not None:
        builder.add_edge(
            GraphEdge(
                source=source,
                target=target_id,
                kind="direct_call" if call else "tail_call",
                instruction_file_offset=instruction_offset,
                qualified=True,
            )
        )


def _decode_x86(  # noqa: C901, PLR0912
    builder: _GraphBuilder, instructions: Iterable[DecodedInstruction]
) -> None:
    supplied = False
    for instruction in instructions:
        supplied = True
        builder.instructions_seen += 1
        if builder.instructions_seen > builder.limits.max_instructions:
            builder.gaps.add("instruction_limit", "Decoded-instruction limit reached")
            return
        if not instruction.raw:
            builder.gaps.add(
                "unbound_disassembly",
                "Decoded instruction has no bytes to bind to the executable file",
            )
            continue
        offset = builder.address_to_offset(
            instruction.address, len(instruction.raw), executable=True
        )
        if (
            offset is None
            or builder.data[offset : offset + len(instruction.raw)] != instruction.raw
        ):
            builder.gaps.add(
                "unbound_disassembly",
                "Decoded instruction bytes do not match executable file bytes",
                offset,
            )
            continue
        builder.decode_bytes += len(instruction.raw)
        if builder.decode_bytes > builder.limits.max_decode_bytes:
            builder.gaps.add("decode_byte_limit", "Executable decode-byte limit reached")
            return
        raw = instruction.raw
        mnemonic = instruction.mnemonic
        if (
            raw[0] == X86_CALL_REL32
            and len(raw) == X86_REL32_INSTRUCTION_BYTES
            and mnemonic in X86_CALLS
        ):
            target = instruction.address + len(raw) + int.from_bytes(raw[1:], "little", signed=True)
            _add_direct_branch(builder, offset, len(raw), target, call=True)
        elif raw[0] in (X86_JUMP_REL32, X86_JUMP_REL8) and mnemonic in X86_JUMPS:
            width = 4 if raw[0] == X86_JUMP_REL32 else 1
            if len(raw) == width + 1:
                target = (
                    instruction.address + len(raw) + int.from_bytes(raw[1:], "little", signed=True)
                )
                _add_direct_branch(builder, offset, len(raw), target, call=False)
        elif mnemonic in X86_CALLS | X86_JUMPS:
            if builder.function_at(offset, len(raw)) is not None:
                builder.gaps.add(
                    "unresolved_indirect_transfer",
                    "x86-64 indirect or unsupported branch target is unresolved",
                )
        if instruction.pc_relative_targets:
            for target in instruction.pc_relative_targets:
                _add_data_reference(
                    builder,
                    offset,
                    instruction.address,
                    target,
                    instruction_size=len(raw),
                )
        for target in instruction.absolute_targets:
            _add_data_reference(
                builder,
                offset,
                instruction.address,
                target,
                instruction_size=len(raw),
                kind="absolute_reference",
            )
        rip_operand = "(%rip)" in instruction.operands or "[rip" in instruction.operands
        if not instruction.pc_relative_targets and mnemonic in X86_RIP_MNEMONICS and rip_operand:
            match = X86_COMMENT_TARGET.search(instruction.operands)
            computed = (
                instruction.address + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)
            )
            if (
                len(raw) < X86_REL32_INSTRUCTION_BYTES
                or raw[-X86_REL32_INSTRUCTION_BYTES] & 0xC7 != X86_RIP_MODRM
                or (match is not None and int(match[1], 16) != computed)
            ):
                builder.gaps.add(
                    "unsupported_pc_relative_encoding",
                    "x86-64 RIP-relative operand could not be verified",
                    offset,
                )
            else:
                _add_data_reference(
                    builder,
                    offset,
                    instruction.address,
                    computed,
                    instruction_size=len(raw),
                )
    if not supplied:
        builder.gaps.add(
            "disassembly_unavailable",
            "x86-64 graph requires pinned Capstone or supplied bounded objdump instructions",
        )


def _relocation_symbol_offset(
    builder: _GraphBuilder,
    sections: list[tuple],
    section_index: int,
    address: int,
    size: int,
) -> int | None:
    return _owned_symbol_offset(
        builder,
        sections,
        section_index,
        address,
        size,
        executable=False,
        gap_code="inconsistent_relocation_symbol",
        subject="Relocation symbol",
    )


def _read_relocations_checked(builder: _GraphBuilder) -> None:  # noqa: C901, PLR0912
    if not builder.header[12]:
        return
    sections = section_headers(builder.data, builder.header)
    relocations_seen = 0
    widths = RELOCATION_WIDTHS.get(builder.machine, {})
    for relocation in sections:
        if relocation[1] not in (SHT_REL, SHT_RELA):
            continue
        if relocation[6] >= len(sections):
            builder.gaps.add("malformed_relocation", "Relocation lacks a symbol table")
            return
        table = sections[relocation[6]]
        if table[1] not in (SHT_SYMTAB, SHT_DYNSYM):
            builder.gaps.add("malformed_relocation", "Relocation link is not a symbol table")
            return
        parser = builder.layout.parser("rela" if relocation[1] == SHT_RELA else "rel")
        if relocation[9] != parser.size or relocation[5] % parser.size:
            builder.gaps.add("malformed_relocation", "Malformed relocation entry table")
            return
        symbol_parser = builder.layout.parser("symbol")
        for row in parser.iter_unpack(checked_slice(builder.data, relocation[4], relocation[5])):
            relocations_seen += 1
            if relocations_seen > builder.limits.max_relocations:
                builder.gaps.add("relocation_limit", "Relocation inspection limit reached")
                return
            site_address, info = row[:2]
            kind = info & (0xFFFFFFFF if builder.layout.bits == ELF64_BITS else 0xFF)
            if kind not in widths:
                builder.gaps.add(
                    "unsupported_relocation",
                    f"Unsupported relocation type {kind} for machine {builder.machine}",
                )
                continue
            symbol_index = info >> (ELF32_BITS if builder.layout.bits == ELF64_BITS else 8)
            count = table[5] // symbol_parser.size
            if table[9] != symbol_parser.size or symbol_index >= count:
                builder.gaps.add("malformed_relocation", "Relocation symbol is outside its table")
                continue
            symbol = symbol_parser.unpack(
                checked_slice(
                    builder.data,
                    table[4] + symbol_index * symbol_parser.size,
                    symbol_parser.size,
                )
            )
            if builder.layout.bits == ELF32_BITS:
                _, symbol_address, symbol_size, _, _, symbol_section = symbol
            else:
                _, _, _, symbol_section, symbol_address, symbol_size = symbol
            if symbol_section == SHN_UNDEF:
                builder.gaps.add(
                    "unresolved_external_relocation",
                    "Relocation target is an undefined external symbol",
                )
                continue
            width = widths[kind]
            site_offset = builder.address_to_offset(site_address, width, executable=True)
            target_offset = _relocation_symbol_offset(
                builder,
                sections,
                symbol_section,
                symbol_address,
                symbol_size,
            )
            if site_offset is None or target_offset is None:
                continue
            source = builder.source_function(site_offset, site_address, width)
            artifact = builder.artifact_for_offset(target_offset)
            target_function = builder.function_at(target_offset)
            target = (
                artifact.identifier
                if artifact is not None
                else _function_id(target_function.file_offset)
                if target_function is not None
                else None
            )
            if source is not None and target is not None:
                builder.add_edge(
                    GraphEdge(
                        source=source,
                        target=target,
                        kind="relocation_reference",
                        instruction_file_offset=site_offset,
                        qualified=True,
                    )
                )


def _read_relocations(builder: _GraphBuilder) -> None:
    try:
        _read_relocations_checked(builder)
    except (ValueError, struct.error) as error:
        builder.gaps.add("malformed_relocation", f"Cannot parse ELF relocations: {error}")


def build_elf_graph(  # noqa: C901, PLR0913
    data: Buffer,
    seeds: Iterable[GraphSeed] = (),
    instructions: InstructionPacket | Iterable[DecodedInstruction] | None = None,
    limits: GraphLimits = DEFAULT_GRAPH_LIMITS,
    *,
    capstone_module: _CapstoneModule | None = None,
    auto_capstone: bool = True,
) -> EvidenceGraph:
    """Build a bounded graph from local ELF evidence without executing the target."""
    _validate_limits(limits)
    builder = _GraphBuilder(data, limits)
    _validate_seeds(builder, seeds)
    _read_symbol_functions(builder)
    _read_eh_frame_starts(builder)
    builder.finalize_function_bounds()
    _read_relocations(builder)
    supplied: Iterable[DecodedInstruction]
    if isinstance(instructions, InstructionPacket):
        supplied = instructions.instructions
        for gap in instructions.gaps:
            builder.gaps.add(gap.code, gap.reason, gap.file_offset)
        if instructions.limited:
            builder.gaps.limited = True
    elif instructions is None and builder.machine == EM_X86_64 and auto_capstone:
        packet = _capstone_instructions(builder, capstone_module)
        supplied = packet.instructions
        for gap in packet.gaps:
            builder.gaps.add(gap.code, gap.reason, gap.file_offset)
        if packet.limited:
            builder.gaps.limited = True
    else:
        supplied = instructions or ()
    if builder.machine == EM_AARCH64:
        _decode_aarch64(builder)
    elif builder.machine == EM_X86_64:
        _decode_x86(builder, supplied)
    elif builder.machine == EM_RISCV:
        _decode_riscv(builder)
    else:
        builder.gaps.add(
            "unsupported_instruction_mode",
            f"Function graph decoding is unsupported for ELF machine {builder.machine}",
        )
    return builder.freeze()
