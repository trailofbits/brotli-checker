import dataclasses
import struct

import brotli_binary_graph as graph
import brotli_binary_match as matcher
import pytest
from test_binary_graph import (
    BASE,
    PAYLOAD_OFFSET,
    arm_mov,
    arm_symbol_elf,
    patch_section,
    riscv_addi,
    riscv_auipc,
    riscv_elf,
)
from test_binary_match import elf


@pytest.mark.parametrize(
    "value",
    [
        graph.GraphLimits(),
        graph.GraphSeed("seed", "kind", 0, 1),
        graph.ArtifactNode("artifact", "kind", 0, 0, 1, None),
        graph.FunctionNode("function", 0, 0, 1, (), ()),
        graph.GraphEdge("source", "target", "direct_call", 0, qualified=True),
        graph.GraphGap("gap", "reason"),
        graph.DecodedInstruction(0, b"\x90", "nop", ""),
        graph.InstructionPacket((), (), limited=False),
        graph.EvidenceGraph(1, (), (), (), (), limited=False),
        graph._DecodeRange(0, 0, 1, priority=False),  # noqa: SLF001
    ],
)
def test_graph_evidence_value_objects_are_immutable(value):
    field = dataclasses.fields(value)[0].name

    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(value, field, None)


def test_graph_dictionary_is_canonically_key_ordered():
    value = graph.EvidenceGraph(1, (), (), (), (), limited=False).as_dict()

    assert list(value) == sorted(value)


@pytest.mark.parametrize(
    ("raw", "encoding", "bits", "expected"),
    [
        (b"\xff\xff", 0x02, 64, 0xFFFF),
        (b"\xff\xff\xff\xff", 0x03, 64, 0xFFFFFFFF),
        (b"\xff" * 8, 0x04, 64, 0xFFFFFFFFFFFFFFFF),
        (b"\xff\xff\xff\xff", 0x00, 32, 0xFFFFFFFF),
    ],
)
def test_unsigned_eh_frame_encodings_never_sign_extend(raw, encoding, bits, expected):
    assert graph._encoded_value(raw, 0, encoding, 0, 0, bits) == (  # noqa: SLF001
        expected,
        len(raw),
    )


def interval_builder(payload, limits=graph.DEFAULT_GRAPH_LIMITS, *, start=0x100, address=BASE):
    data = arm_symbol_elf(payload, function_symbol=False)
    builder = graph._GraphBuilder(data, limits)  # noqa: SLF001
    function = graph._FunctionBuilder(start, address, len(payload), set(), set())  # noqa: SLF001
    builder.functions[start] = function
    builder.finalize_function_bounds()
    return builder, function


@pytest.mark.parametrize(
    ("start", "address"),
    [(0x102, BASE), (0x100, BASE + 2)],
    ids=["file-offset", "virtual-address"],
)
def test_arm_interval_requires_each_arm_alignment_independently(start, address):
    builder, function = interval_builder(bytes(8), start=start, address=address)

    assert (
        graph._decode_arm_interval(  # noqa: SLF001
            builder, function, start, start + 4, "arm"
        )
        is False
    )
    assert builder.instructions_seen == 0
    assert any(gap.code == "unsupported_instruction_mode" for gap in builder.gaps.values)


def test_arm_interval_stop_result_distinguishes_truncation_limits_and_completion():
    truncated, truncated_function = interval_builder(struct.pack("<H", 0xF000))
    decode_limited, decode_function = interval_builder(
        struct.pack("<H", 0xBF00),
        dataclasses.replace(graph.DEFAULT_GRAPH_LIMITS, max_decode_bytes=1),
    )
    instruction_limited, instruction_function = interval_builder(
        struct.pack("<2H", 0xBF00, 0xBF00),
        dataclasses.replace(graph.DEFAULT_GRAPH_LIMITS, max_instructions=1),
    )
    complete, complete_function = interval_builder(struct.pack("<H", 0xBF00))

    assert (
        graph._decode_arm_interval(  # noqa: SLF001
            truncated, truncated_function, 0x100, 0x102, "thumb"
        )
        is False
    )
    assert (
        graph._decode_arm_interval(  # noqa: SLF001
            decode_limited, decode_function, 0x100, 0x102, "thumb"
        )
        is True
    )
    assert (
        graph._decode_arm_interval(  # noqa: SLF001
            instruction_limited, instruction_function, 0x100, 0x104, "thumb"
        )
        is True
    )
    assert (
        graph._decode_arm_interval(  # noqa: SLF001
            complete, complete_function, 0x100, 0x102, "thumb"
        )
        is False
    )
    assert any(gap.code == "truncated_instruction" for gap in truncated.gaps.values)
    assert any(gap.code == "decode_byte_limit" for gap in decode_limited.gaps.values)
    assert any(gap.code == "instruction_limit" for gap in instruction_limited.gaps.values)
    assert complete.instructions_seen == 1


def test_builder_mapping_defaults_and_function_lifecycle_are_explicit():
    data = elf(bytes(16), matcher.EM_X86_64, flags=4)
    builder = graph._GraphBuilder(data, graph.DEFAULT_GRAPH_LIMITS)  # noqa: SLF001
    assert builder.address_to_offset(BASE) == PAYLOAD_OFFSET
    assert builder.address_to_offset(BASE, executable=True) is None
    assert builder.executable_end(PAYLOAD_OFFSET) is None

    builder.add_function(PAYLOAD_OFFSET, BASE, 4, name=None, method="fixture")
    assert builder.function_bounds_finalized is False
    assert builder.function_at(PAYLOAD_OFFSET) is not None
    assert builder.function_bounds_finalized is True
    assert builder._range_overlaps_functions(PAYLOAD_OFFSET + 1, PAYLOAD_OFFSET + 2) is True  # noqa: SLF001
    assert builder._range_overlaps_functions(0, 0) is False  # noqa: SLF001
    assert builder._range_overlaps_functions(PAYLOAD_OFFSET + 4, PAYLOAD_OFFSET + 4) is False  # noqa: SLF001

    artifact = builder.add_artifact(graph.GraphSeed("data", "table", PAYLOAD_OFFSET + 8, 4))
    assert artifact is builder.artifacts["data"]
    source = builder.source_function(PAYLOAD_OFFSET + 4, BASE + 4, 1)
    assert source == f"function:0x{PAYLOAD_OFFSET + 4:x}"


def test_decode_ranges_prioritize_only_owned_executable_evidence_and_preserve_limits():
    data = elf(bytes(24), matcher.EM_X86_64)
    builder = graph._GraphBuilder(data, graph.DEFAULT_GRAPH_LIMITS)  # noqa: SLF001
    builder.add_function(PAYLOAD_OFFSET, BASE, 4, name=None, method="flirt_function")
    builder.add_artifact(graph.GraphSeed("exact", "exact_code_region", PAYLOAD_OFFSET + 8, 4))
    selected = graph._decode_ranges(  # noqa: SLF001
        builder,
        (graph._DecodeRange(PAYLOAD_OFFSET, BASE, 24, priority=False),),  # noqa: SLF001
        alignment=1,
    )
    assert [(item.file_offset, item.size, item.priority) for item in selected[:2]] == [
        (PAYLOAD_OFFSET, 4, True),
        (PAYLOAD_OFFSET + 8, 4, True),
    ]

    unrelated = graph._GraphBuilder(data, graph.DEFAULT_GRAPH_LIMITS)  # noqa: SLF001
    unrelated.add_artifact(graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET, 4))
    assert graph._decode_ranges(unrelated, (), alignment=1) == ()  # noqa: SLF001

    nonexec_data = elf(bytes(8), matcher.EM_X86_64, flags=4)
    nonexec = graph._GraphBuilder(nonexec_data, graph.DEFAULT_GRAPH_LIMITS)  # noqa: SLF001
    nonexec.add_artifact(graph.GraphSeed("exact", "exact_code_region", PAYLOAD_OFFSET, 4))
    assert graph._decode_ranges(nonexec, (), alignment=1) == ()  # noqa: SLF001

    limited = graph._GraphBuilder(  # noqa: SLF001
        data, dataclasses.replace(graph.DEFAULT_GRAPH_LIMITS, max_decode_bytes=3)
    )
    limited.add_function(PAYLOAD_OFFSET, BASE, 4, name=None, method="flirt_function")
    assert graph._decode_ranges(limited, (), alignment=1) == ()  # noqa: SLF001
    assert limited.gaps.limited
    assert {gap.code for gap in limited.gaps.values} == {
        "priority_decode_window_limit",
        "unexamined_executable_ranges",
    }

    residual = graph._GraphBuilder(  # noqa: SLF001
        data, dataclasses.replace(graph.DEFAULT_GRAPH_LIMITS, max_decode_bytes=5)
    )
    chosen = graph._decode_ranges(  # noqa: SLF001
        residual,
        (graph._DecodeRange(PAYLOAD_OFFSET, BASE, 8, priority=False),),  # noqa: SLF001
        alignment=2,
    )
    assert [(item.size, item.priority) for item in chosen] == [(4, False)]
    assert residual.gaps.limited
    assert any(gap.code == "unexamined_executable_ranges" for gap in residual.gaps.values)


def arm_table_result(word):
    target = BASE + 16
    payload = struct.pack("<2I", word, 0xE320F000) + bytes(8) + b"TABLE123"
    return graph.build_elf_graph(
        arm_symbol_elf(payload, marker="$a", function_size=4),
        (graph.GraphSeed("table", "decoder_table", 0x110, 8),),
    ), target


@pytest.mark.parametrize(
    "word",
    [
        0xFA000002,
        0xE49F0008,
        0xE5900008,
        0xE08F0008,
    ],
    ids=[
        "reserved-branch-condition",
        "literal-without-preindex",
        "literal-wrong-base",
        "adr-not-immediate",
    ],
)
def test_arm_partial_opcode_lookalikes_never_create_table_edges(word):
    result, _ = arm_table_result(word)

    assert not result.edges
    assert any(gap.code == "arm_table_reference_unresolved" for gap in result.gaps)


@pytest.mark.parametrize("mutation", ["typed", "unnamed", "undefined"])
def test_arm_mapping_symbols_require_notype_name_and_defined_section(mutation):
    payload = struct.pack("<4H", 0xE001, 0xBF00, 0xBF00, 0xBF00)
    data = bytearray(arm_symbol_elf(payload, marker="$t"))
    mapping = 0x100 + len(payload) + matcher.ELFLayout(32, "little").parser("symbol").size
    if mutation == "typed":
        data[mapping + 12] = matcher.STT_FUNC
    elif mutation == "unnamed":
        data[mapping : mapping + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    else:
        data[mapping + 14 : mapping + 16] = (0).to_bytes(2, "little")

    result = graph.build_elf_graph(bytes(data))
    assert not result.edges
    assert not any(
        "arm_mode:thumb_mapping_symbol" in function.boundary_methods
        for function in result.functions
    )


def test_arm_mapping_after_function_start_does_not_prove_initial_mode():
    payload = struct.pack("<4H", 0xE001, 0xBF00, 0xBF00, 0xBF00)
    result = graph.build_elf_graph(arm_symbol_elf(payload, marker=[("$t", 6)]))

    assert not result.edges
    assert any(gap.code == "arm_instruction_mode_unavailable" for gap in result.gaps)


def test_arm_symbols_require_executable_owning_section_even_when_load_is_executable():
    payload = struct.pack("<4H", 0xE001, 0xBF00, 0xBF00, 0xBF00)
    data = patch_section(arm_symbol_elf(payload, marker="$t"), 1, 2, graph.SHF_ALLOC)
    result = graph.build_elf_graph(data)

    assert result.functions == ()
    assert {gap.code for gap in result.gaps} >= {
        "inconsistent_arm_mapping_symbol",
        "inconsistent_function_symbol",
    }


def test_arm_immediate_and_mov_half_decoders_reject_partial_encodings():
    assert graph._arm_immediate(0x00000012) == 0x12  # noqa: SLF001
    assert graph._arm_immediate(0x00000112) == 0x80000004  # noqa: SLF001
    assert graph._arm_mov_half(0xE1A00000) is None  # noqa: SLF001
    assert graph._arm_mov_half(arm_mov("movw", 1, 0x1234, condition=0xF)) is None  # noqa: SLF001
    assert graph._arm_mov_half(arm_mov("movw", 1, 0x1234)) == (  # noqa: SLF001
        "movw",
        0xE,
        1,
        0x1234,
    )


def test_trusted_packet_presence_binding_and_tail_kind_are_distinct():
    payload = bytes.fromhex("0c000000") + bytes(12)
    data = elf(payload, matcher.EM_MIPS)
    seed = graph.GraphSeed("source", "trusted", PAYLOAD_OFFSET, 4, is_function=True)
    empty = graph.build_elf_graph(
        data,
        (seed,),
        graph.InstructionPacket((), (), limited=False, machine=matcher.EM_MIPS),
    )
    instruction = graph.DecodedInstruction(
        BASE, payload[:4], "j", f"{BASE + 8:x}", tail_call_targets=(BASE + 8,)
    )
    bound = graph.build_elf_graph(
        data,
        (seed,),
        graph.InstructionPacket((instruction,), (), limited=False, machine=matcher.EM_MIPS),
    )
    mismatched = dataclasses.replace(instruction, raw=b"\xff\xff\xff\xff")
    wrong_bytes = graph.build_elf_graph(
        data,
        (seed,),
        graph.InstructionPacket((mismatched,), (), limited=False, machine=matcher.EM_MIPS),
    )
    nonexec = graph.build_elf_graph(
        elf(payload, matcher.EM_MIPS, flags=4),
        (),
        graph.InstructionPacket((instruction,), (), limited=False, machine=matcher.EM_MIPS),
    )

    assert any(gap.code == "disassembly_unavailable" for gap in empty.gaps)
    assert not any(gap.code == "disassembly_unavailable" for gap in bound.gaps)
    assert [(edge.kind, edge.qualified) for edge in bound.edges] == [("tail_call", True)]
    assert any(gap.code == "unbound_disassembly" for gap in wrong_bytes.gaps)
    assert any(gap.code == "unbound_disassembly" for gap in nonexec.gaps)
    assert not wrong_bytes.edges
    assert not nonexec.edges


def test_riscv_false_transfer_and_pending_lookalikes_remain_unresolved():
    jalr = 0x67
    no_function = graph.build_elf_graph(riscv_elf(struct.pack("<I", jalr)))
    invalid_addi = riscv_addi(5, 5, 32) | (1 << 12)
    invalid_pending = graph.build_elf_graph(
        riscv_elf(struct.pack("<2I", riscv_auipc(5), invalid_addi) + bytes(24) + b"TABLE123"),
        (graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET + 32, 8),),
    )
    compressed_without_function = graph.build_elf_graph(
        riscv_elf(struct.pack("<H", 0x9002), compressed=True)
    )
    odd_window = graph.build_elf_graph(riscv_elf(b"\x01\x00\x00"))

    assert not any(gap.code == "unresolved_indirect_transfer" for gap in no_function.gaps)
    assert not invalid_pending.edges
    assert not any(
        gap.code == "unresolved_indirect_transfer" for gap in compressed_without_function.gaps
    )
    assert any(gap.code == "unsupported_instruction_mode" for gap in odd_window.gaps)
