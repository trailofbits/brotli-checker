# ruff: noqa: C901, EM101, EM102, PLR0912, PLR0915, PLR2004, TRY003, TRY004
"""Import exact-target, bounded objdump evidence from Brotli triage reports."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from typing import TYPE_CHECKING, Any

from brotli_binary_data import sha256_data
from brotli_binary_graph import (
    DEFAULT_GRAPH_LIMITS,
    X86_CALL_REL32,
    X86_JUMP_REL8,
    X86_JUMP_REL32,
    X86_REL32_INSTRUCTION_BYTES,
    X86_RIP_MNEMONICS,
    DecodedInstruction,
    GraphGap,
    GraphLimits,
    InstructionPacket,
    parse_objdump_instructions,
)
from brotli_binary_match import (
    EM_PPC64,
    EM_X86_64,
    TARGETS,
    ELFLayout,
    elf_header,
    program_headers,
    target_identity,
)
from brotli_binary_triage import require_supported_instruction_mode

if TYPE_CHECKING:
    from brotli_binary_data import Buffer

MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_FRAGMENTS = 256
PT_LOAD = 1
PF_X = 1
EF_PPC_VLE = 0x10000000
PPC_BRANCH_OPCODE = 18
PPC_BRANCH_MASK = 0x03FFFFFC
PPC_BRANCH_SIGN = 0x02000000
PPC_BRANCH_RANGE = 0x04000000
SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class _Fragment:
    file_offset: int
    start_address: int
    stop_address: int
    size: int
    path: str

    @property
    def key(self) -> tuple[int, int, int]:
        return self.start_address, self.stop_address, self.size


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
        if len(self.values) >= self.limit:
            self.limited = True
            return
        self.keys.add(key)
        self.values.append(GraphGap(code, reason, file_offset))


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate graph-triage JSON field: {key}")
        result[key] = value
    return result


def _document(raw: bytes, maximum: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    if len(raw) > maximum:
        raise ValueError("Graph-triage document exceeds the byte limit")
    try:
        parsed = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("Graph-triage document is not valid bounded JSON") from error
    required = {
        "schema_version",
        "target",
        "tool",
        "scope",
        "limits",
        "collection",
        "classification",
        "evidence",
        "limitations",
    }
    if not isinstance(parsed, dict) or set(parsed) != required or parsed["schema_version"] != 2:
        raise ValueError("Invalid graph-triage document schema")
    return parsed


def graph_triage_target_sha256(raw: bytes) -> str:
    """Return the exact target digest for routing one captured triage document."""
    target = _document(raw).get("target")
    if not isinstance(target, dict) or set(target) != {"path", "sha256", "size_bytes"}:
        raise ValueError("Invalid graph-triage target identity")
    digest = target["sha256"]
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        raise ValueError("Invalid graph-triage target SHA-256")
    return digest


def _target_identity(data: Buffer, report: dict[str, Any]) -> tuple[tuple, int, str]:
    if not data.startswith(b"\x7fELF"):
        raise ValueError("Graph-triage packets require an ELF target")
    target = report["target"]
    if (
        not isinstance(target, dict)
        or set(target) != {"path", "sha256", "size_bytes"}
        or not isinstance(target["path"], str)
        or not target["path"]
        or not isinstance(target["sha256"], str)
        or SHA256.fullmatch(target["sha256"]) is None
        or type(target["size_bytes"]) is not int
        or target["size_bytes"] != len(data)
        or target["sha256"] != sha256_data(data)
    ):
        raise ValueError("Graph-triage target size or SHA-256 does not match the artifact")
    header = elf_header(data)
    machine = header[2]
    if machine == EM_PPC64 and header[7] & EF_PPC_VLE:
        raise ValueError("Graph-triage target uses unsupported PowerPC VLE mode")
    try:
        architecture = (
            require_supported_instruction_mode(data) or TARGETS[target_identity(header)][1]
        )
    except ValueError as error:
        raise ValueError(f"Graph-triage target instruction mode is unsupported: {error}") from error
    return header, machine, architecture


def _fragment(
    data: Buffer, header: tuple, value: object, seen: set[tuple[int, int, int]]
) -> _Fragment:
    fields = {
        "path",
        "sha256",
        "file_offset",
        "start_address",
        "stop_address",
        "size_bytes",
        "ephemeral",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Invalid graph-triage fragment schema")
    offset = value["file_offset"]
    start = value["start_address"]
    stop = value["stop_address"]
    size = value["size_bytes"]
    path = value["path"]
    digest = value["sha256"]
    if (
        type(offset) is not int
        or type(start) is not int
        or type(stop) is not int
        or type(size) is not int
        or offset < 0
        or size <= 0
        or stop - start != size
        or offset > len(data)
        or size > len(data) - offset
        or not isinstance(path, str)
        or not path
        or value["ephemeral"] is not True
        or not isinstance(digest, str)
        or SHA256.fullmatch(digest) is None
        or hashlib.sha256(data[offset : offset + size]).hexdigest() != digest
    ):
        raise ValueError("Invalid or hash-mismatched graph-triage fragment")
    owners = [
        virtual + offset - file_offset
        for kind, flags, file_offset, virtual, _, file_size, _, _ in program_headers(data, header)
        if kind == PT_LOAD
        and flags & PF_X
        and file_offset <= offset
        and offset + size <= file_offset + file_size
    ]
    if owners != [start]:
        raise ValueError("Graph-triage fragment lacks unique executable target ownership")
    key = start, stop, size
    if key in seen:
        raise ValueError("Duplicate graph-triage fragment scope")
    seen.add(key)
    return _Fragment(offset, start, stop, size, path)


def _validate_command(
    command: object,
    fragment_paths: dict[str, _Fragment],
    tool_path: str,
    architecture: str,
    byteorder: str,
) -> _Fragment:
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(item, str) for item in command)
    ):
        raise ValueError("Invalid graph-triage objdump command")
    fragment = fragment_paths.get(command[-1])
    if fragment is None:
        raise ValueError("Graph-triage command does not own one captured fragment")
    architectures = [item for item in command if item.startswith("--architecture=")]
    adjustments = [item for item in command if item.startswith("--adjust-vma=")]
    if (
        command[0] != tool_path
        or architectures != [f"--architecture={architecture}"]
        or adjustments != [f"--adjust-vma=0x{fragment.start_address:x}"]
        or "--target=binary" not in command
        or f"--endian={byteorder}" not in command
    ):
        raise ValueError("Graph-triage command architecture or address binding is invalid")
    return fragment


def _scope_fragment(scope: object, fragments: dict[tuple[int, int, int], _Fragment]) -> _Fragment:
    if not isinstance(scope, dict):
        raise ValueError("Invalid graph-triage disassembly scope")
    start = scope.get("start_address")
    stop = scope.get("stop_address")
    size = scope.get("size_bytes")
    if type(start) is not int or type(stop) is not int or type(size) is not int:
        raise ValueError("Graph-triage disassembly lacks a bounded address scope")
    fragment = fragments.get((start, stop, size))
    if fragment is None:
        raise ValueError("Graph-triage disassembly does not own a captured fragment")
    if "file_offset" in scope and scope["file_offset"] != fragment.file_offset:
        raise ValueError("Graph-triage disassembly file offset disagrees with its fragment")
    return fragment


def _verified_instructions(
    data: Buffer, fragment: _Fragment, packet: InstructionPacket
) -> tuple[DecodedInstruction, ...]:
    result = []
    for instruction in packet.instructions:
        relative = instruction.address - fragment.start_address
        if (
            relative < 0
            or relative + len(instruction.raw) > fragment.size
            or data[
                fragment.file_offset + relative : fragment.file_offset
                + relative
                + len(instruction.raw)
            ]
            != instruction.raw
        ):
            raise ValueError("Graph-triage instruction bytes disagree with the exact artifact")
        result.append(instruction)
    return tuple(result)


def _complete_fragment_coverage(
    fragment: _Fragment, instructions: tuple[DecodedInstruction, ...]
) -> bool:
    cursor = fragment.start_address
    for instruction in sorted(instructions, key=lambda item: item.address):
        if instruction.address != cursor:
            return False
        cursor += len(instruction.raw)
    return cursor == fragment.stop_address


def _sanitize_instruction_semantics(
    instruction: DecodedInstruction, machine: int, byteorder: str
) -> tuple[DecodedInstruction, str | None]:
    targets = (
        instruction.pc_relative_targets
        or instruction.absolute_targets
        or instruction.direct_call_targets
        or instruction.tail_call_targets
    )
    if machine == EM_PPC64:
        decoded = _ppc64_direct_transfer(instruction, byteorder)
        if decoded is not None:
            target, call = decoded
            verified = replace(
                instruction,
                mnemonic="bl" if call else "b",
                operands="",
                pc_relative_targets=(),
                absolute_targets=(),
                direct_call_targets=(target,) if call else (),
                tail_call_targets=() if call else (target,),
            )
            expected = (
                verified.pc_relative_targets,
                verified.absolute_targets,
                verified.direct_call_targets,
                verified.tail_call_targets,
            )
            supplied = (
                instruction.pc_relative_targets,
                instruction.absolute_targets,
                instruction.direct_call_targets,
                instruction.tail_call_targets,
            )
            return (
                verified,
                "triage_semantics_mismatch" if targets and supplied != expected else None,
            )
        return (
            replace(
                instruction,
                pc_relative_targets=(),
                absolute_targets=(),
                direct_call_targets=(),
                tail_call_targets=(),
            ),
            "triage_instruction_semantics_unknown",
        )
    if machine != EM_X86_64:
        return (
            replace(
                instruction,
                pc_relative_targets=(),
                absolute_targets=(),
                direct_call_targets=(),
                tail_call_targets=(),
            ),
            ("triage_semantics_unverified" if targets else "triage_instruction_semantics_unknown"),
        )
    raw = instruction.raw
    if raw and raw[0] == X86_CALL_REL32 and len(raw) == X86_REL32_INSTRUCTION_BYTES:
        mnemonic = "call"
    elif (
        raw
        and raw[0] in (X86_JUMP_REL32, X86_JUMP_REL8)
        and len(raw) == (X86_REL32_INSTRUCTION_BYTES if raw[0] == X86_JUMP_REL32 else 2)
    ):
        mnemonic = "jmp"
    else:
        mnemonic = ""
    claimed_reference = bool(targets) or (
        instruction.mnemonic in X86_RIP_MNEMONICS
        and ("(%rip)" in instruction.operands or "[rip" in instruction.operands)
    )
    return (
        replace(
            instruction,
            mnemonic=mnemonic,
            operands="",
            pc_relative_targets=(),
            absolute_targets=(),
            direct_call_targets=(),
            tail_call_targets=(),
        ),
        "triage_semantics_unverified" if claimed_reference else None,
    )


def _ppc64_direct_transfer(
    instruction: DecodedInstruction, byteorder: str
) -> tuple[int, bool] | None:
    raw = instruction.raw
    if len(raw) != 4 or instruction.address % 4 or byteorder not in {"little", "big"}:
        return None
    word = int.from_bytes(raw, byteorder)
    if word >> 26 != PPC_BRANCH_OPCODE:
        return None
    displacement = word & PPC_BRANCH_MASK
    if displacement & PPC_BRANCH_SIGN:
        displacement -= PPC_BRANCH_RANGE
    absolute = bool(word & 2)
    link = bool(word & 1)
    return (displacement if absolute else instruction.address + displacement), link


def instruction_packet_from_triage(
    data: Buffer,
    raw: bytes,
    limits: GraphLimits = DEFAULT_GRAPH_LIMITS,
) -> InstructionPacket:
    """Verify one triage report and return bounded instructions for ``build_elf_graph``."""
    if any(value <= 0 for value in asdict(limits).values()):
        raise ValueError("Graph packet limits must be positive")
    report = _document(raw)
    header, machine, architecture = _target_identity(data, report)
    byteorder = ELFLayout.of(header).byteorder
    tool = report["tool"]
    if (
        not isinstance(tool, dict)
        or set(tool) != {"path", "input_mode", "fragments", "commands"}
        or tool["input_mode"] != "code_fragments"
        or not isinstance(tool["path"], str)
        or not tool["path"]
        or not isinstance(tool["fragments"], list)
        or not isinstance(tool["commands"], list)
        or len(tool["fragments"]) > MAX_FRAGMENTS
        or len(tool["commands"]) > len(tool["fragments"])
    ):
        raise ValueError("Invalid or excessive graph-triage tool evidence")
    seen: set[tuple[int, int, int]] = set()
    fragments = [_fragment(data, header, value, seen) for value in tool["fragments"]]
    by_scope = {fragment.key: fragment for fragment in fragments}
    by_path = {fragment.path: fragment for fragment in fragments}
    if len(by_path) != len(fragments):
        raise ValueError("Duplicate graph-triage fragment path")
    command_scopes = set()
    for command in tool["commands"]:
        fragment = _validate_command(
            command,
            by_path,
            tool["path"],
            architecture,
            byteorder,
        )
        if fragment.key in command_scopes:
            raise ValueError("Duplicate graph-triage command scope")
        command_scopes.add(fragment.key)

    evidence = report["evidence"]
    if (
        not isinstance(evidence, dict)
        or set(evidence)
        != {
            "symbols",
            "analysis_report",
            "disassembly",
        }
        or not isinstance(evidence["disassembly"], list)
    ):
        raise ValueError("Invalid graph-triage evidence schema")
    if len(evidence["disassembly"]) > len(fragments):
        raise ValueError("Graph-triage disassembly population exceeds its fragments")
    if len(tool["commands"]) != len(evidence["disassembly"]):
        raise ValueError("Graph-triage commands and disassembly results disagree")
    collection = report["collection"]
    if (
        not isinstance(collection, dict)
        or not isinstance(collection.get("reasons"), list)
        or any(not isinstance(reason, str) or not reason for reason in collection["reasons"])
        or type(collection.get("incomplete")) is not bool
    ):
        raise ValueError("Invalid graph-triage collection status")
    classification = report["classification"]
    if not isinstance(classification, dict) or classification.get("patch_status") != "unknown":
        raise ValueError("Graph-triage evidence cannot carry a patch verdict")

    gaps = _GapCollector(limits.max_gaps)
    for reason in collection["reasons"]:
        gaps.add("triage_collection_incomplete", reason)
    instructions: dict[int, DecodedInstruction] = {}
    allowed_fragments = set()
    fragment_bytes = 0
    for fragment in fragments:
        if fragment_bytes + fragment.size <= limits.max_decode_bytes:
            allowed_fragments.add(fragment.key)
            fragment_bytes += fragment.size
        else:
            gaps.add(
                "triage_fragment_byte_limit",
                "Total graph-triage fragment byte limit reached",
                fragment.file_offset,
            )
    output_bytes = 0
    decoded_fragments: set[tuple[int, int, int]] = set()
    reported_scopes: set[tuple[int, int, int]] = set()
    limited = collection["incomplete"] or bool(collection["reasons"])
    for item in evidence["disassembly"]:
        if not isinstance(item, dict) or set(item) != {
            "scope",
            "returncode",
            "limited",
            "reason",
            "text",
        }:
            raise ValueError("Invalid graph-triage disassembly schema")
        fragment = _scope_fragment(item["scope"], by_scope)
        if fragment.key in reported_scopes:
            raise ValueError("Duplicate graph-triage disassembly scope")
        reported_scopes.add(fragment.key)
        text = item["text"]
        if (
            type(item["returncode"]) is not int
            or type(item["limited"]) is not bool
            or not isinstance(text, str)
            or (item["reason"] is not None and not isinstance(item["reason"], str))
            or item["reason"] == ""
        ):
            raise ValueError("Invalid graph-triage disassembly result")
        if fragment.key not in allowed_fragments:
            limited = True
            continue
        encoded_size = len(text.encode("utf-8"))
        if output_bytes + encoded_size > limits.max_objdump_bytes:
            gaps.add("objdump_output_limit", "Total graph-triage objdump byte limit reached")
            limited = True
            continue
        output_bytes += encoded_size
        parsed = parse_objdump_instructions(text, limits, machine=machine)
        for gap in parsed.gaps:
            gaps.add(gap.code, gap.reason, gap.file_offset)
        limited = limited or parsed.limited or item["limited"] or item["returncode"] != 0
        if item["limited"] or item["returncode"] != 0 or item["reason"] is not None:
            gaps.add(
                "triage_objdump_incomplete",
                item["reason"] or f"objdump exited {item['returncode']}",
                fragment.file_offset,
            )
        verified = _verified_instructions(data, fragment, parsed)
        if _complete_fragment_coverage(fragment, verified):
            decoded_fragments.add(fragment.key)
        else:
            gaps.add(
                "triage_instruction_coverage_incomplete",
                "Objdump rows do not cover the complete captured fragment",
                fragment.file_offset,
            )
            limited = True
        for instruction in verified:
            verified_instruction, semantics_gap = _sanitize_instruction_semantics(
                instruction, machine, byteorder
            )
            if semantics_gap is not None:
                reason = (
                    "Supplied instruction semantics disagree with byte-derived semantics"
                    if semantics_gap == "triage_semantics_mismatch"
                    else "PowerPC64 instruction is outside the byte-derived branch subset"
                    if semantics_gap == "triage_instruction_semantics_unknown"
                    else "Supplied instruction semantics were not independently decoded from bytes"
                )
                gaps.add(
                    semantics_gap,
                    reason,
                    fragment.file_offset,
                )
                limited = True
            previous = instructions.get(verified_instruction.address)
            if previous is not None and previous != verified_instruction:
                raise ValueError("Conflicting graph-triage instructions at one address")
            if previous is None:
                if len(instructions) >= limits.max_instructions:
                    gaps.add("instruction_limit", "Decoded-instruction limit reached")
                    limited = True
                    break
                instructions[verified_instruction.address] = verified_instruction
    if command_scopes != reported_scopes:
        raise ValueError("Graph-triage command and result scopes disagree")
    omitted = {fragment.key for fragment in fragments} - decoded_fragments
    if omitted:
        gaps.add("triage_fragments_unexamined", "Captured executable fragments lack disassembly")
        limited = True
    if not instructions:
        gaps.add("triage_no_instructions", "No exact-target objdump instructions were retained")
        limited = True
    if gaps.limited:
        limited = True
    return InstructionPacket(
        tuple(instructions[address] for address in sorted(instructions)),
        tuple(gaps.values),
        limited,
        machine,
    )
