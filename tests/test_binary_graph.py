import json
import struct
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import brotli_binary_graph as graph
import brotli_binary_match as matcher
import pytest
from test_binary_match import elf

if TYPE_CHECKING:
    from brotli_binary_data import Buffer

PAYLOAD_OFFSET = matcher.ELF_HEADER.size + matcher.PROGRAM_HEADER.size
BASE = 0x401000


class CountingBuffer:
    def __init__(self, data):
        self.data = data
        self.slice_sizes = []

    def __len__(self):
        return len(self.data)

    def __getitem__(self, key):
        value = self.data[key]
        if isinstance(key, slice):
            self.slice_sizes.append(len(value))
        return value

    def find(self, sub, start=0, end=None):
        return self.data.find(sub, start, len(self.data) if end is None else end)


def riscv_addi(rd, rs1, immediate):
    return ((immediate & 0xFFF) << 20) | (rs1 << 15) | (rd << 7) | 0x13


def riscv_auipc(rd, immediate=0):
    return (immediate & 0xFFFFF000) | (rd << 7) | 0x17


def riscv_lui(rd, immediate):
    return (immediate & 0xFFFFF000) | (rd << 7) | 0x37


def riscv_jal(rd, immediate):
    value = immediate & 0x1FFFFF
    return (
        ((value >> 20) & 1) << 31
        | ((value >> 1) & 0x3FF) << 21
        | ((value >> 11) & 1) << 20
        | ((value >> 12) & 0xFF) << 12
        | rd << 7
        | 0x6F
    )


def riscv_compressed_jump(immediate):
    value = immediate & 0xFFF
    return (
        0xA001
        | ((value >> 11) & 1) << 12
        | ((value >> 4) & 1) << 11
        | ((value >> 8) & 3) << 9
        | ((value >> 10) & 1) << 8
        | ((value >> 6) & 1) << 7
        | ((value >> 7) & 1) << 6
        | ((value >> 1) & 7) << 3
        | ((value >> 5) & 1) << 2
    )


def riscv_elf(payload, *, compressed=False):
    result = bytearray(elf(payload, matcher.EM_RISCV))
    struct.pack_into("<I", result, 48, graph.EF_RISCV_RVC if compressed else 0)
    return bytes(result)


def aarch64_adr(pc, target, register=0):
    immediate = target - pc
    return (
        graph.AARCH64_ADR | ((immediate & 3) << 29) | (((immediate >> 2) & 0x7FFFF) << 5) | register
    )


def aarch64_branch(pc, target, *, call):
    return (graph.AARCH64_BL if call else 0x14000000) | (((target - pc) >> 2) & 0x3FFFFFF)


def aarch64_fixture():
    words = [
        aarch64_adr(BASE, BASE + 32),
        aarch64_branch(BASE + 4, BASE + 16, call=True),
        graph.AARCH64_BR | (1 << 5),
        0xD503201F,
        0xD65F03C0,
        0xD503201F,
        0xD503201F,
        0xD503201F,
    ]
    return struct.pack("<8I", *words) + b"TABLE123"


def overlapping_load_fixture(payload):
    first_offset = matcher.ELF_HEADER.size + 2 * matcher.PROGRAM_HEADER.size
    second_offset = first_offset + len(payload)
    header = matcher.ELF_HEADER.pack(
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3,
        matcher.EM_AARCH64,
        1,
        0,
        matcher.ELF_HEADER.size,
        0,
        0,
        matcher.ELF_HEADER.size,
        matcher.PROGRAM_HEADER.size,
        2,
        0,
        0,
        0,
    )
    segments = b"".join(
        matcher.PROGRAM_HEADER.pack(
            1,
            5,
            offset,
            BASE,
            BASE,
            len(payload),
            len(payload),
            0x1000,
        )
        for offset in (first_offset, second_offset)
    )
    return header + segments + payload * 2, first_offset


def eh_frame_fixture(raw):
    code_offset = 0x100
    unwind_offset = 0x120
    code = struct.pack("<4I", 0xD503201F, 0xD65F03C0, 0xD503201F, 0xD503201F)
    header = matcher.ELF_HEADER.pack(
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3,
        matcher.EM_AARCH64,
        1,
        0,
        matcher.ELF_HEADER.size,
        0,
        0,
        matcher.ELF_HEADER.size,
        matcher.PROGRAM_HEADER.size,
        2,
        0,
        0,
        0,
    )
    load = matcher.PROGRAM_HEADER.pack(1, 5, code_offset, BASE, BASE, len(code), len(code), 0x1000)
    unwind = matcher.PROGRAM_HEADER.pack(
        graph.PT_GNU_EH_FRAME,
        4,
        unwind_offset,
        BASE + 0x1000,
        BASE + 0x1000,
        len(raw),
        len(raw),
        4,
    )
    result = bytearray(header + load + unwind)
    result.extend(bytes(code_offset - len(result)))
    result.extend(code)
    result.extend(bytes(unwind_offset - len(result)))
    result.extend(raw)
    return bytes(result)


def seeds():
    return (
        graph.GraphSeed(
            "decoder", "flirt_function", PAYLOAD_OFFSET, 16, "Decoder", is_function=True
        ),
        graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET + 32, 8, "command_lut"),
    )


def test_aarch64_graph_links_table_call_and_indirect_gap():
    result = graph.build_elf_graph(elf(aarch64_fixture()), seeds())

    assert result.patch_status == "unknown"
    assert {edge.kind for edge in result.edges} == {"pc_relative_reference", "direct_call"}
    assert any(edge.target == "table" for edge in result.edges)
    assert any(gap.code == "unresolved_indirect_transfer" for gap in result.gaps)
    assert json.loads(json.dumps(result.as_dict()))["patch_status"] == "unknown"


def test_aarch64_literal_tail_call_and_indirect_call_are_distinguished():
    literal = graph.AARCH64_LDR_LITERAL | (8 << 5)
    tail = aarch64_branch(BASE + 4, BASE + 16, call=False)
    words = [
        literal,
        tail,
        graph.AARCH64_BLR | (1 << 5),
        0xD503201F,
        0xD65F03C0,
        0xD503201F,
        0xD503201F,
        0xD503201F,
    ]
    supplied = (
        graph.GraphSeed("decoder", "flirt_function", PAYLOAD_OFFSET, 12, is_function=True),
        graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET + 32, 8),
    )
    result = graph.build_elf_graph(elf(struct.pack("<8I", *words) + b"TABLE123"), supplied)
    assert {edge.kind for edge in result.edges} == {"pc_relative_reference", "tail_call"}
    assert any(edge.target == "table" for edge in result.edges)
    assert any(gap.code == "unresolved_indirect_transfer" for gap in result.gaps)


def test_ambiguous_load_mapping_never_owns_a_function_seed():
    data, code_offset = overlapping_load_fixture(aarch64_fixture())
    result = graph.build_elf_graph(
        data,
        (graph.GraphSeed("decoder", "flirt_function", code_offset, 16, is_function=True),),
    )
    assert result.functions == ()
    assert result.edges == ()
    assert any(gap.code == "ambiguous_load_mapping" for gap in result.gaps)


def test_overlapping_artifact_seeds_never_create_a_qualified_edge():
    supplied = (
        graph.GraphSeed("decoder", "flirt_function", PAYLOAD_OFFSET, 16, is_function=True),
        graph.GraphSeed("table-a", "decoder_table", PAYLOAD_OFFSET + 32, 8),
        graph.GraphSeed("table-b", "decoder_table", PAYLOAD_OFFSET + 32, 8),
    )
    result = graph.build_elf_graph(elf(aarch64_fixture()), supplied)
    assert all(edge.target not in {"table-a", "table-b"} for edge in result.edges)
    assert any(gap.code == "ambiguous_artifact_ownership" for gap in result.gaps)


def test_eh_frame_header_establishes_bounded_function_starts():
    raw = (
        bytes((1, 0x03, 0x03, 0x03))
        + struct.pack("<II", 0, 2)
        + struct.pack("<IIII", BASE, 0, BASE + 8, 0)
    )
    result = graph.build_elf_graph(eh_frame_fixture(raw))
    unwind = [
        function for function in result.functions if "eh_frame_hdr" in function.boundary_methods
    ]
    assert [(function.file_offset, function.size) for function in unwind] == [
        (0x100, 8),
        (0x108, 8),
    ]
    assert all(gap.code != "unsupported_unwind" for gap in result.gaps)


def test_malformed_eh_frame_header_is_an_explicit_gap():
    for raw in (bytes((2, 0x03, 0x03, 0x03)), bytes((1, 0x03, 0x03))):
        result = graph.build_elf_graph(eh_frame_fixture(raw))
        assert result.functions == ()
        assert any(gap.code == "unsupported_unwind" for gap in result.gaps)


def test_eh_frame_encodings_cover_width_sign_and_relative_bases():
    encoded = graph._encoded_value  # noqa: SLF001 -- Unwind parser contract.
    assert encoded(b"\x34\x12", 0, 0x02, 0x1000, 0x2000, 64) == (0x1234, 2)
    assert encoded(b"\xfe\xff", 0, 0x0A, 0x1000, 0x2000, 64) == (-2, 2)
    assert encoded(struct.pack("<I", 4), 0, 0x13, 0x1000, 0x2000, 64) == (0x1004, 4)
    assert encoded(struct.pack("<I", 4), 0, 0x33, 0x1000, 0x2000, 64) == (0x2004, 4)
    assert encoded(struct.pack("<Q", 7), 0, 0x04, 0x1000, 0x2000, 64) == (7, 8)
    assert encoded(struct.pack("<I", 9), 0, 0x00, 0x1000, 0x2000, 32) == (9, 4)
    assert encoded(struct.pack("<Q", 9), 0, 0x00, 0x1000, 0x2000, 64) == (9, 8)
    assert encoded(b"\x12\x34", 0, 0x02, 0x1000, 0x2000, 64, "big") == (0x1234, 2)
    assert encoded(b"\xfc\xff\xff\xff", 0, 0x0B, 0, 0, 64) == (-4, 4)
    assert encoded(b"\xf8\xff\xff\xff\xff\xff\xff\xff", 0, 0x0C, 0, 0, 64) == (-8, 8)
    for data, encoding, reason in (
        (b"", 0x03, "Truncated"),
        (bytes(8), graph.DW_EH_PE_OMIT, "omitted/indirect"),
        (bytes(8), graph.DW_EH_PE_INDIRECT | 0x03, "omitted/indirect"),
        (bytes(8), 0x01, "variable-length"),
        (bytes(8), 0x23, "relative"),
    ):
        with pytest.raises(ValueError, match=reason):
            encoded(data, 0, encoding, 0x1000, 0x2000, 64)


def test_eh_frame_function_count_accepts_exact_limit_and_rejects_overflow():
    one = bytes((1, 0x03, 0x03, 0x03)) + struct.pack("<IIIII", 0, 1, BASE, 0, 0)
    two = (
        bytes((1, 0x03, 0x03, 0x03))
        + struct.pack("<II", 0, 2)
        + struct.pack("<IIII", BASE, 0, BASE + 8, 0)
    )
    exact = graph.build_elf_graph(eh_frame_fixture(one), limits=graph.GraphLimits(max_functions=1))
    overflow = graph.build_elf_graph(
        eh_frame_fixture(two), limits=graph.GraphLimits(max_functions=1)
    )
    assert len(exact.functions) == 1
    assert all(gap.code != "unsupported_unwind" for gap in exact.gaps)
    assert overflow.functions == ()
    assert any(gap.code == "unsupported_unwind" for gap in overflow.gaps)


def test_two_aarch64_copies_share_one_artifact_without_merging_functions():
    words = [
        aarch64_adr(BASE, BASE + 48),
        0xD65F03C0,
        0xD503201F,
        0xD503201F,
        aarch64_adr(BASE + 16, BASE + 48),
        0xD65F03C0,
        0xD503201F,
        0xD503201F,
        0xD503201F,
        0xD503201F,
        0xD503201F,
        0xD503201F,
    ]
    data = elf(struct.pack("<12I", *words) + b"TABLE123")
    supplied = (
        graph.GraphSeed("copy-a", "flirt_function", PAYLOAD_OFFSET, 8, is_function=True),
        graph.GraphSeed("copy-b", "flirt_function", PAYLOAD_OFFSET + 16, 8, is_function=True),
        graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET + 48, 8),
    )

    result = graph.build_elf_graph(data, supplied)

    table_edges = [edge for edge in result.edges if edge.target == "table"]
    assert len(table_edges) == 2
    assert len({edge.source for edge in table_edges}) == 2


def test_overlapping_distinct_function_bounds_suppress_only_ambiguous_sites():
    words = [
        aarch64_adr(BASE, BASE + 32),
        aarch64_adr(BASE + 4, BASE + 32),
        0xD503201F,
        aarch64_adr(BASE + 12, BASE + 32),
        0xD65F03C0,
        0xD503201F,
        0xD503201F,
        0xD503201F,
    ]
    supplied = (
        graph.GraphSeed("outer", "flirt_function", PAYLOAD_OFFSET, 16, "outer", is_function=True),
        graph.GraphSeed(
            "inner", "flirt_function", PAYLOAD_OFFSET + 4, 4, "inner", is_function=True
        ),
        graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET + 32, 8),
    )
    result = graph.build_elf_graph(elf(struct.pack("<8I", *words) + b"TABLE123"), supplied)
    table_edges = [edge for edge in result.edges if edge.target == "table"]
    assert [edge.instruction_file_offset for edge in table_edges] == [
        PAYLOAD_OFFSET,
        PAYLOAD_OFFSET + 12,
    ]
    assert {edge.source for edge in table_edges} == {f"function:0x{PAYLOAD_OFFSET:x}"}
    assert any(gap.code == "ambiguous_function_bounds" for gap in result.gaps)


def test_same_start_aliases_remain_one_shared_function():
    supplied = (
        graph.GraphSeed(
            "alias-a", "flirt_function", PAYLOAD_OFFSET, 8, "alias_a", is_function=True
        ),
        graph.GraphSeed(
            "alias-b", "trusted_function", PAYLOAD_OFFSET, 12, "alias_b", is_function=True
        ),
    )
    result = graph.build_elf_graph(elf(bytes(16)), supplied)
    assert len(result.functions) == 1
    assert result.functions[0].size == 12
    assert result.functions[0].names == ("alias_a", "alias_b")
    assert set(result.functions[0].boundary_methods) == {"flirt_function", "trusted_function"}
    assert all(gap.code != "ambiguous_function_bounds" for gap in result.gaps)


def test_aarch64_adrp_add_pair_resolves_seeded_table():
    words = [
        graph.AARCH64_ADRP,
        graph.AARCH64_ADD_IMMEDIATE | (32 << 10),
        0xD65F03C0,
        0xD503201F,
        0xD503201F,
        0xD503201F,
        0xD503201F,
        0xD503201F,
    ]
    data = elf(struct.pack("<8I", *words) + b"TABLE123")
    supplied = (
        graph.GraphSeed("copy", "flirt_function", PAYLOAD_OFFSET, 12, is_function=True),
        graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET + 32, 8),
    )
    result = graph.build_elf_graph(data, supplied)
    assert any(
        edge.kind == "pc_relative_reference" and edge.target == "table" for edge in result.edges
    )


def test_aarch64_adrp_requires_adjacent_add_with_matching_register():
    words = [
        graph.AARCH64_ADRP,
        0xD503201F,
        graph.AARCH64_ADD_IMMEDIATE | (32 << 10),
        graph.AARCH64_ADRP,
        graph.AARCH64_ADD_IMMEDIATE | (32 << 10) | (1 << 5) | 1,
        graph.AARCH64_ADRP,
        graph.AARCH64_ADD_IMMEDIATE | (32 << 10),
        0xD65F03C0,
    ]
    data = elf(struct.pack("<8I", *words) + b"TABLE123")
    supplied = (
        graph.GraphSeed("copy", "flirt_function", PAYLOAD_OFFSET, 32, is_function=True),
        graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET + 32, 8),
    )
    result = graph.build_elf_graph(data, supplied)
    table_edges = [edge for edge in result.edges if edge.target == "table"]
    assert [edge.instruction_file_offset for edge in table_edges] == [PAYLOAD_OFFSET + 24]


def x86_fixture():
    code = bytes.fromhex("488d0519000000e804000000ffe09090c3")
    return code + bytes(32 - len(code)) + b"TABLE123"


def x86_objdump():
    return """
  401000: 48 8d 05 19 00 00 00  lea    0x19(%rip),%rax # 401020
  401007: e8 04 00 00 00        call   401010 <callee>
  40100c: ff e0                 jmp    *%rax
  401010: c3                    ret
"""


def test_x86_objdump_packet_is_byte_bound_and_builds_edges():
    packet = graph.parse_objdump_instructions(x86_objdump())
    supplied = (
        graph.GraphSeed(
            "decoder", "flirt_function", PAYLOAD_OFFSET, 14, "Decoder", is_function=True
        ),
        graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET + 32, 8),
    )

    result = graph.build_elf_graph(
        elf(x86_fixture(), matcher.EM_X86_64),
        supplied,
        packet,
        auto_capstone=False,
    )

    assert {edge.kind for edge in result.edges} == {"pc_relative_reference", "direct_call"}
    assert any(gap.code == "unresolved_indirect_transfer" for gap in result.gaps)


def test_unbound_x86_disassembly_is_a_gap_not_an_edge():
    packet = graph.parse_objdump_instructions(x86_objdump().replace("48 8d 05 19", "48 8d 05 18"))
    result = graph.build_elf_graph(
        elf(x86_fixture(), matcher.EM_X86_64),
        seeds=(),
        instructions=packet,
        auto_capstone=False,
    )
    assert all(edge.kind != "pc_relative_reference" for edge in result.edges)
    assert any(gap.code == "unbound_disassembly" for gap in result.gaps)


def test_x86_short_tail_and_absolute_reference_are_qualified_separately():
    payload = bytes.fromhex("eb0e90") + bytes(13) + b"\xc3" + bytes(15) + b"TABLE123"
    packet = (
        graph.DecodedInstruction(BASE, bytes.fromhex("eb0e"), "jmp", "401010"),
        graph.DecodedInstruction(
            BASE + 2,
            b"\x90",
            "nop",
            "",
            absolute_targets=(BASE + 32,),
        ),
    )
    supplied = (
        graph.GraphSeed("decoder", "flirt_function", PAYLOAD_OFFSET, 3, is_function=True),
        graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET + 32, 8),
    )
    result = graph.build_elf_graph(
        elf(payload, matcher.EM_X86_64),
        supplied,
        packet,
        auto_capstone=False,
    )
    assert {edge.kind for edge in result.edges} == {"tail_call", "absolute_reference"}
    assert any(edge.target == "table" for edge in result.edges)


def test_empty_x86_instruction_is_an_unbound_gap_not_an_exception():
    result = graph.build_elf_graph(
        elf(bytes(16), matcher.EM_X86_64),
        (),
        (graph.DecodedInstruction(BASE, b"", "nop", ""),),
        auto_capstone=False,
    )
    assert result.edges == ()
    assert any(gap.code == "unbound_disassembly" for gap in result.gaps)


class FakeCapstoneDecoder:
    detail = False

    def disasm(self, _code, _address):
        return [
            SimpleNamespace(
                address=BASE,
                bytes=bytes.fromhex("488d0519000000"),
                mnemonic="lea",
                op_str="0x19(%rip),%rax # 401020",
            )
        ]


class FakeCapstone:
    __name__ = "fake_capstone"
    __version__ = graph.PINNED_CAPSTONE_VERSION
    CS_ARCH_X86 = 1
    CS_MODE_64 = 2

    def Cs(self, _architecture, _mode):  # noqa: N802
        return FakeCapstoneDecoder()


class WrongCapstone(FakeCapstone):
    __version__ = "4.0.2"


class BrokenCapstone(FakeCapstone):
    def Cs(self, _architecture, _mode):  # noqa: N802
        message = "unsupported decoder"
        raise ValueError(message)


class ThrowingCapstoneDecoder:
    detail = False

    def disasm(self, _code, _address):
        message = "decode failed"
        raise ValueError(message)


class ThrowingCapstone(FakeCapstone):
    def Cs(self, _architecture, _mode):  # noqa: N802
        return ThrowingCapstoneDecoder()


class StructuredCapstoneDecoder:
    detail = False

    def disasm(self, _code, _address):
        def memory(base, displacement):
            return SimpleNamespace(base=base, disp=displacement)

        def operand(kind, value):
            return SimpleNamespace(type=kind, mem=value)

        return [
            SimpleNamespace(
                address=BASE,
                bytes=bytes.fromhex("488d0519000000"),
                mnemonic="lea",
                op_str="[rip + 0x19]",
                operands=(
                    operand(1, memory(10, 25)),
                    operand(1, memory(0, BASE + 32)),
                    operand(1, memory(0, 0)),
                    operand(2, memory(0, BASE + 32)),
                ),
            )
        ]


class StructuredCapstone(FakeCapstone):
    x86_const = SimpleNamespace(X86_OP_MEM=1, X86_REG_RIP=10)

    def Cs(self, _architecture, _mode):  # noqa: N802
        return StructuredCapstoneDecoder()


def test_pinned_capstone_is_usable_without_manual_instruction_formatting():
    supplied = (
        graph.GraphSeed("decoder", "flirt_function", PAYLOAD_OFFSET, 14, is_function=True),
        graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET + 32, 8),
    )
    result = graph.build_elf_graph(
        elf(x86_fixture(), matcher.EM_X86_64),
        supplied,
        capstone_module=FakeCapstone(),
    )
    assert [edge.kind for edge in result.edges] == ["pc_relative_reference"]


@pytest.mark.parametrize(
    ("backend", "gap_code", "limited"),
    [
        (BrokenCapstone(), "capstone_api_unsupported", False),
        (ThrowingCapstone(), "capstone_decode_error", True),
    ],
    ids=["initialization", "decode"],
)
def test_capstone_failures_are_explicit_and_never_create_edges(backend, gap_code, limited):
    result = graph.build_elf_graph(
        elf(x86_fixture(), matcher.EM_X86_64),
        seeds(),
        capstone_module=backend,
    )
    assert result.edges == ()
    assert any(gap.code == gap_code for gap in result.gaps)
    assert result.limited is limited


def test_capstone_memory_operands_distinguish_rip_absolute_and_nonmemory_values():
    result = graph.build_elf_graph(
        elf(x86_fixture(), matcher.EM_X86_64),
        seeds(),
        capstone_module=StructuredCapstone(),
    )
    assert {(edge.kind, edge.target) for edge in result.edges} == {
        ("pc_relative_reference", "table"),
        ("absolute_reference", "table"),
    }


def test_real_pinned_capstone_decodes_x86_fixture_when_installed():
    capstone = pytest.importorskip("capstone")
    supplied = (
        graph.GraphSeed("decoder", "flirt_function", PAYLOAD_OFFSET, 14, is_function=True),
        graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET + 32, 8),
    )
    result = graph.build_elf_graph(
        elf(x86_fixture(), matcher.EM_X86_64),
        supplied,
        capstone_module=capstone,
    )
    assert {edge.kind for edge in result.edges} == {
        "pc_relative_reference",
        "direct_call",
    }


def test_real_capstone_negative_rip_absolute_indirect_and_short_tail():
    capstone = pytest.importorskip("capstone")
    table = b"TABLE123"
    code_offset = 16
    code_address = BASE + code_offset
    negative_displacement = BASE - (code_address + 7)
    code = (
        b"\x48\x8d\x05"
        + negative_displacement.to_bytes(4, "little", signed=True)
        + b"\x48\xa1"
        + BASE.to_bytes(8, "little")
        + b"\xff\xd0"
        + b"\xeb\x0b"
    )
    payload = table + bytes(code_offset - len(table)) + code
    payload += bytes(48 - len(payload)) + b"\xc3"
    supplied = (
        graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET, len(table)),
        graph.GraphSeed(
            "decoder",
            "flirt_function",
            PAYLOAD_OFFSET + code_offset,
            len(code),
            is_function=True,
        ),
    )
    result = graph.build_elf_graph(
        elf(payload, matcher.EM_X86_64),
        supplied,
        capstone_module=capstone,
    )
    table_edges = [edge for edge in result.edges if edge.target == "table"]
    assert {edge.kind for edge in table_edges} == {
        "pc_relative_reference",
        "absolute_reference",
    }
    assert any(edge.kind == "tail_call" for edge in result.edges)
    assert any(gap.code == "unresolved_indirect_transfer" for gap in result.gaps)


def test_branch_instruction_crossing_function_bound_is_not_attributed():
    packet = (
        graph.DecodedInstruction(
            BASE,
            bytes.fromhex("e80b000000"),
            "call",
            "401010",
        ),
    )
    result = graph.build_elf_graph(
        elf(bytes.fromhex("e80b000000") + bytes(11) + b"\xc3", matcher.EM_X86_64),
        (graph.GraphSeed("short", "flirt_function", PAYLOAD_OFFSET, 2, is_function=True),),
        packet,
        auto_capstone=False,
    )
    assert all(edge.kind != "direct_call" for edge in result.edges)
    assert any(gap.code == "ambiguous_function_bounds" for gap in result.gaps)


def test_missing_or_wrong_capstone_and_unsupported_isa_are_explicit():
    x86 = graph.build_elf_graph(
        elf(x86_fixture(), matcher.EM_X86_64),
        seeds(),
        capstone_module=WrongCapstone(),
    )
    arm = graph.build_elf_graph(elf(bytes(64), matcher.EM_MIPS), ())
    assert any(gap.code == "capstone_version_unsupported" for gap in x86.gaps)
    assert any(gap.code == "disassembly_unavailable" for gap in x86.gaps)
    assert any(gap.code == "unsupported_instruction_mode" for gap in arm.gaps)


def test_instruction_budget_and_objdump_text_bounds_are_gaps():
    limited = graph.build_elf_graph(
        elf(aarch64_fixture()), seeds(), limits=graph.GraphLimits(max_instructions=1)
    )
    packet = graph.parse_objdump_instructions(
        x86_objdump(), graph.GraphLimits(max_objdump_bytes=10)
    )
    assert limited.limited
    assert any(gap.code == "instruction_limit" for gap in limited.gaps)
    assert packet.limited
    assert packet.instructions == ()
    propagated = graph.build_elf_graph(
        elf(x86_fixture(), matcher.EM_X86_64),
        (),
        packet,
        auto_capstone=False,
    )
    assert propagated.limited
    assert any(gap.code == "objdump_output_limit" for gap in propagated.gaps)


def test_objdump_line_and_instruction_limits_accept_exact_population():
    line = "  401000: 90  nop"
    exact_line = graph.parse_objdump_instructions(
        line, graph.GraphLimits(max_objdump_line_bytes=len(line.encode()))
    )
    short_line = graph.parse_objdump_instructions(
        line, graph.GraphLimits(max_objdump_line_bytes=len(line.encode()) - 1)
    )
    exact_count = graph.parse_objdump_instructions(
        f"{line}\n  401001: 90  nop",
        graph.GraphLimits(max_instructions=2),
    )
    overflow = graph.parse_objdump_instructions(
        f"{line}\n  401001: 90  nop\n  401002: 90  nop",
        graph.GraphLimits(max_instructions=2),
    )
    assert len(exact_line.instructions) == 1
    assert exact_line.limited is False
    assert short_line.instructions == ()
    assert short_line.limited is True
    assert len(exact_count.instructions) == 2
    assert exact_count.limited is False
    assert len(overflow.instructions) == 2
    assert overflow.limited is True
    assert overflow.gaps[0].code == "instruction_limit"


def test_objdump_parser_ignores_rows_without_bound_instruction_bytes():
    packet = graph.parse_objdump_instructions(
        "  401000: nop\n  401001: 90\n  401002: zz  invalid\n  401003: 90  nop"
    )
    assert [(row.address, row.raw, row.mnemonic) for row in packet.instructions] == [
        (0x401003, b"\x90", "nop")
    ]
    assert packet.limited is False


def test_gap_retention_deduplicates_and_marks_exact_overflow():
    gaps = graph._GapCollector(1)  # noqa: SLF001 -- Bounded graph-output contract.
    gaps.add("one", "first", 1)
    gaps.add("one", "first", 1)
    assert gaps.values == [graph.GraphGap("one", "first", 1)]
    assert gaps.limited is False
    gaps.add("two", "second", 2)
    assert gaps.values == [graph.GraphGap("one", "first", 1)]
    assert gaps.limited is True


def test_seed_limit_and_duplicate_identity_fail_closed():
    data = elf(bytes(64))
    supplied = (
        graph.GraphSeed("one", "decoder_table", PAYLOAD_OFFSET, 4),
        graph.GraphSeed("two", "decoder_table", PAYLOAD_OFFSET + 4, 4),
    )
    limited = graph.build_elf_graph(data, supplied, limits=graph.GraphLimits(max_seeds=1))
    assert [artifact.identifier for artifact in limited.artifacts] == ["one"]
    assert limited.limited
    assert any(gap.code == "seed_limit" for gap in limited.gaps)
    with pytest.raises(ValueError, match="duplicate graph seed"):
        graph.build_elf_graph(data, (supplied[0], supplied[0]))


def test_function_and_edge_limits_accept_exact_population():
    exact = graph.build_elf_graph(
        elf(aarch64_fixture()),
        seeds(),
        limits=graph.GraphLimits(max_functions=2, max_edges=2),
    )
    function_limited = graph.build_elf_graph(
        elf(aarch64_fixture()),
        seeds(),
        limits=graph.GraphLimits(max_functions=1, max_edges=2),
    )
    edge_limited = graph.build_elf_graph(
        elf(aarch64_fixture()),
        seeds(),
        limits=graph.GraphLimits(max_functions=2, max_edges=1),
    )
    assert len(exact.functions) == 2
    assert len(exact.edges) == 2
    assert all(gap.code not in {"function_limit", "edge_limit"} for gap in exact.gaps)
    assert len(function_limited.functions) == 1
    assert any(gap.code == "function_limit" for gap in function_limited.gaps)
    assert len(edge_limited.edges) == 1
    assert any(gap.code == "edge_limit" for gap in edge_limited.gaps)


def test_invalid_load_extent_is_omitted_with_an_explicit_gap():
    data = bytearray(elf(bytes(16)))
    struct.pack_into("<Q", data, matcher.ELF_HEADER.size + 32, len(data) + 1)
    struct.pack_into("<Q", data, matcher.ELF_HEADER.size + 40, len(data) + 1)
    result = graph.build_elf_graph(bytes(data))
    assert result.functions == ()
    assert result.edges == ()
    assert any(gap.code == "malformed_load_segment" for gap in result.gaps)


def test_nonload_program_header_never_maps_seed_bytes():
    data = bytearray(elf(bytes(16)))
    row = list(matcher.PROGRAM_HEADER.unpack_from(data, matcher.ELF_HEADER.size))
    row[0] = graph.PT_GNU_EH_FRAME
    matcher.PROGRAM_HEADER.pack_into(data, matcher.ELF_HEADER.size, *row)
    result = graph.build_elf_graph(
        bytes(data),
        (graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET, 8),),
    )
    assert result.artifacts == ()
    assert any(gap.code == "seed_not_mapped" for gap in result.gaps)


@pytest.mark.parametrize("value", [0, -1], ids=["zero", "negative"])
def test_every_graph_work_limit_must_be_strictly_positive(value):
    with pytest.raises(ValueError, match="limits must be positive"):
        graph.build_elf_graph(elf(bytes(16)), limits=graph.GraphLimits(max_edges=value))


def test_load_mapping_accepts_exact_memory_extent_and_last_file_byte():
    data = elf(bytes(16))
    builder = graph._GraphBuilder(data, graph.DEFAULT_GRAPH_LIMITS)  # noqa: SLF001
    last_offset = len(data) - 1
    last_address = BASE + 15
    assert builder.address_to_offset(last_address) == last_offset
    assert builder.offset_to_address(last_offset) == last_address
    assert builder.executable_end(last_offset) == len(data)
    assert builder.address_to_offset(last_address + 1) is None
    assert builder.offset_to_address(last_offset + 1) is None

    row = list(matcher.PROGRAM_HEADER.unpack_from(data, matcher.ELF_HEADER.size))
    assert row[5] == row[6]
    result = graph.build_elf_graph(
        data,
        (graph.GraphSeed("last", "decoder_table", last_offset, 1),),
    )
    assert [artifact.identifier for artifact in result.artifacts] == ["last"]
    assert all(gap.code != "malformed_load_segment" for gap in result.gaps)

    graph._validate_seeds(  # noqa: SLF001 -- Half-open artifact ownership contract.
        builder,
        (graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET, 4),),
    )
    first = builder.artifact_for_offset(PAYLOAD_OFFSET)
    last = builder.artifact_for_offset(PAYLOAD_OFFSET + 3)
    assert first is not None
    assert first.identifier == "table"
    assert last is not None
    assert last.identifier == "table"
    assert builder.artifact_for_offset(PAYLOAD_OFFSET + 4) is None


def test_identical_overlapping_load_mappings_are_not_falsely_ambiguous():
    data = bytearray(elf(bytes(16)))
    header = list(matcher.ELF_HEADER.unpack_from(data))
    original = matcher.PROGRAM_HEADER.unpack_from(data, matcher.ELF_HEADER.size)
    header[10] = 2
    payload = bytes(data[PAYLOAD_OFFSET:])
    rebuilt = bytearray(matcher.ELF_HEADER.pack(*header))
    rebuilt.extend(matcher.PROGRAM_HEADER.pack(*original) * 2)
    rebuilt.extend(payload)
    payload_offset = matcher.ELF_HEADER.size + 2 * matcher.PROGRAM_HEADER.size
    for index in range(2):
        row = list(original)
        row[2] = payload_offset
        matcher.PROGRAM_HEADER.pack_into(
            rebuilt, matcher.ELF_HEADER.size + index * matcher.PROGRAM_HEADER.size, *row
        )
    result = graph.build_elf_graph(
        bytes(rebuilt),
        (graph.GraphSeed("table", "decoder_table", payload_offset, 16),),
    )
    assert [artifact.identifier for artifact in result.artifacts] == ["table"]
    assert all(gap.code != "ambiguous_load_mapping" for gap in result.gaps)


@pytest.mark.parametrize(
    ("offset", "size"),
    [(-1, 1), (PAYLOAD_OFFSET, 0), ("eof", 1)],
    ids=["negative-offset", "zero-size", "past-end"],
)
def test_invalid_seed_boundaries_are_rejected(offset, size):
    data = elf(bytes(16))
    actual_offset = len(data) if offset == "eof" else offset
    with pytest.raises(ValueError, match="Invalid or duplicate graph seed"):
        graph.build_elf_graph(
            data,
            (graph.GraphSeed("bad", "decoder_table", actual_offset, size),),
        )


def test_string_table_lookup_is_half_open_and_bounded():
    parse = graph._string  # noqa: SLF001 -- ELF string-table boundary contract.
    assert parse(b"\0name\0", 0, 6, 1) == "name"
    assert parse(b"\0name\0", 0, 5, 1) is None
    assert parse(b"\0name\0", 0, 6, 6) is None
    assert parse(b"\0\xff\0", 0, 3, 1) is None


def test_decode_byte_budget_fails_before_partial_code_window_edges():
    result = graph.build_elf_graph(
        elf(aarch64_fixture()),
        seeds(),
        limits=graph.GraphLimits(max_decode_bytes=1),
    )
    assert result.limited
    assert result.edges == ()
    assert any(gap.code == "priority_decode_window_limit" for gap in result.gaps)


def test_decode_range_union_and_subtraction_preserve_virtual_mapping():
    decode_range = graph._DecodeRange  # noqa: SLF001 -- Sparse decode-window contract.
    merge = graph._merge_decode_ranges  # noqa: SLF001
    subtract = graph._subtract_priority  # noqa: SLF001
    assert merge(
        [
            decode_range(0, 0x1000, 8, priority=False),
            decode_range(4, 0x1004, 8, priority=False),
            decode_range(12, 0x2000, 4, priority=False),
            decode_range(16, 0x2004, 0, priority=False),
        ]
    ) == [
        decode_range(0, 0x1000, 12, priority=False),
        decode_range(12, 0x2000, 4, priority=False),
    ]
    assert subtract(
        decode_range(0, 0x1000, 16, priority=False),
        [decode_range(4, 0x1004, 4, priority=True)],
    ) == [
        decode_range(0, 0x1000, 4, priority=False),
        decode_range(8, 0x1008, 8, priority=False),
    ]
    assert subtract(
        decode_range(4, 0x1004, 4, priority=False),
        [
            decode_range(0, 0x1000, 4, priority=True),
            decode_range(8, 0x1008, 4, priority=True),
        ],
    ) == [decode_range(4, 0x1004, 4, priority=False)]
    assert (
        subtract(
            decode_range(4, 0x1004, 4, priority=False),
            [decode_range(4, 0x1004, 4, priority=True)],
        )
        == []
    )


def test_decode_budget_exactly_consumes_aligned_range_without_omission():
    data = elf(bytes(8))
    builder = graph._GraphBuilder(  # noqa: SLF001 -- Decode budget contract.
        data, graph.GraphLimits(max_decode_bytes=8)
    )
    selected = graph._decode_ranges(  # noqa: SLF001
        builder,
        (graph._DecodeRange(PAYLOAD_OFFSET, BASE, 8, priority=False),),  # noqa: SLF001
        alignment=4,
    )
    assert selected == (graph._DecodeRange(PAYLOAD_OFFSET, BASE, 8, priority=False),)  # noqa: SLF001
    assert builder.decode_bytes == 8
    assert all(gap.code != "unexamined_executable_ranges" for gap in builder.gaps.values)


def test_recognized_function_window_near_end_is_decoded_before_large_prefix():
    prefix = struct.pack("<I", 0xD503201F) * 1024
    function_address = BASE + len(prefix)
    function = struct.pack(
        "<4I",
        aarch64_adr(function_address, function_address + 32),
        0xD65F03C0,
        0xD503201F,
        0xD503201F,
    )
    payload = prefix + function + bytes(16) + b"TABLE123"
    function_offset = PAYLOAD_OFFSET + len(prefix)
    supplied = (
        graph.GraphSeed(
            "late-function",
            "flirt_function",
            function_offset,
            len(function),
            is_function=True,
        ),
        graph.GraphSeed("late-table", "decoder_table", function_offset + 32, 8),
    )
    tracked = CountingBuffer(elf(payload))
    result = graph.build_elf_graph(
        cast("Buffer", tracked),
        supplied,
        limits=graph.GraphLimits(max_decode_bytes=64),
    )
    assert any(edge.target == "late-table" for edge in result.edges)
    assert result.limited
    assert any(gap.code == "unexamined_executable_ranges" for gap in result.gaps)
    assert all(gap.code != "priority_decode_window_limit" for gap in result.gaps)
    assert 4 not in tracked.slice_sizes


def test_riscv_pc_relative_table_reference_and_direct_call_are_qualified():
    words = [
        riscv_auipc(5),
        riscv_addi(5, 5, 32),
        riscv_jal(1, 8),
        riscv_addi(0, 0, 0),
        riscv_lui(6, BASE),
        riscv_addi(6, 6, 32),
        riscv_addi(0, 0, 0),
        riscv_addi(0, 0, 0),
        riscv_addi(0, 0, 0),
        riscv_addi(0, 0, 0),
    ]
    supplied = (
        graph.GraphSeed("source", "flirt_function", PAYLOAD_OFFSET, 12, is_function=True),
        graph.GraphSeed("callee", "flirt_function", PAYLOAD_OFFSET + 16, 12, is_function=True),
        graph.GraphSeed("table", "decoder_table", PAYLOAD_OFFSET + 32, 8),
    )
    result = graph.build_elf_graph(riscv_elf(struct.pack("<10I", *words)), supplied)
    assert any(
        edge.kind == "pc_relative_reference" and edge.target == "table" and edge.qualified
        for edge in result.edges
    )
    assert any(
        edge.kind == "absolute_reference" and edge.target == "table" and edge.qualified
        for edge in result.edges
    )
    assert any(
        edge.kind == "direct_call"
        and edge.source == f"function:0x{PAYLOAD_OFFSET:x}"
        and edge.target == f"function:0x{PAYLOAD_OFFSET + 16:x}"
        for edge in result.edges
    )
    assert all(gap.code != "unsupported_instruction_mode" for gap in result.gaps)


def test_riscv_compressed_jump_requires_elf_flag_and_preserves_indirect_gap():
    payload = struct.pack("<4H", riscv_compressed_jump(4), 0x0001, 0x0001, 0x9002)
    supplied = (
        graph.GraphSeed("source", "flirt_function", PAYLOAD_OFFSET, 2, is_function=True),
        graph.GraphSeed("callee", "flirt_function", PAYLOAD_OFFSET + 4, 4, is_function=True),
    )
    supported = graph.build_elf_graph(riscv_elf(payload, compressed=True), supplied)
    assert any(
        edge.kind == "tail_call" and edge.target == f"function:0x{PAYLOAD_OFFSET + 4:x}"
        for edge in supported.edges
    )
    assert any(gap.code == "unresolved_indirect_transfer" for gap in supported.gaps)

    unsupported = graph.build_elf_graph(riscv_elf(payload), supplied)
    assert all(edge.kind != "tail_call" for edge in unsupported.edges)
    assert any(
        gap.code == "unsupported_instruction_mode" and "EF_RISCV_RVC" in gap.reason
        for gap in unsupported.gaps
    )


def test_riscv_truncated_and_sparse_windows_are_bounded():
    tracked = CountingBuffer(riscv_elf(struct.pack("<H", 0x0003)))
    result = graph.build_elf_graph(cast("Buffer", tracked))
    assert result.edges == ()
    assert any(
        gap.code == "unsupported_instruction_mode" and "ends within" in gap.reason
        for gap in result.gaps
    )
    large = CountingBuffer(riscv_elf(struct.pack("<64I", *([riscv_addi(0, 0, 0)] * 64))))
    graph.build_elf_graph(cast("Buffer", large))
    assert 2 not in large.slice_sizes
    assert 4 not in large.slice_sizes


def test_function_seed_outside_executable_mapping_is_rejected():
    supplied = (
        graph.GraphSeed(
            "not-code",
            "trusted_function",
            PAYLOAD_OFFSET,
            16,
            is_function=True,
        ),
    )
    result = graph.build_elf_graph(
        elf(bytes(64), matcher.EM_X86_64, flags=4),
        supplied,
        instructions=(),
        auto_capstone=False,
    )
    assert result.functions == ()
    assert any(gap.code == "function_seed_not_executable" for gap in result.gaps)


def test_misaligned_aarch64_priority_window_is_not_partially_decoded():
    result = graph.build_elf_graph(
        elf(bytes(16)),
        (graph.GraphSeed("odd", "flirt_function", PAYLOAD_OFFSET, 3, is_function=True),),
    )
    assert result.edges == ()
    assert any(gap.code == "unsupported_instruction_mode" for gap in result.gaps)


def test_assessment_seed_derivation_uses_canonical_evidence():
    assessment = {
        "code_matches": [{"id": "exact", "file_offset": 10, "size_bytes": 20}],
        "flirt": {
            "matches": [
                {
                    "signature_id": "sig",
                    "file_offset": 30,
                    "size_bytes": 40,
                    "definitive_name": "Decode",
                }
            ]
        },
        "recognition": {"matches": [{"id": "command_lut_le", "file_offset": 70, "size_bytes": 80}]},
    }
    derived = graph.seeds_from_assessment(assessment)
    assert [seed.kind for seed in derived] == [
        "exact_code_region",
        "flirt_function",
        "decoder_table",
    ]
    assert derived[1].is_function


def linked_relocation_fixture(  # noqa: PLR0913 -- Malformed relocation fixture dimensions.
    relocation_kind=2,
    *,
    target_section=1,
    target_info=0x11,
    target_address=BASE + 32,
    target_size=8,
    site_address=BASE + 4,
):
    code_offset = 0x100
    code = bytes(64)
    strings = b"\0source\0table\0"
    symbol = matcher.ELFLayout(64, "little").parser("symbol")
    symbols = b"".join(
        [
            bytes(symbol.size),
            symbol.pack(1, 0x12, 0, 1, BASE, 16),
            symbol.pack(8, target_info, 0, target_section, target_address, target_size),
        ]
    )
    sym_offset = code_offset + len(code)
    str_offset = sym_offset + len(symbols)
    rela = matcher.ELFLayout(64, "little").parser("rela")
    rela_bytes = rela.pack(site_address, (2 << 32) | relocation_kind, 0)
    rela_offset = str_offset + len(strings)
    section_offset = (rela_offset + len(rela_bytes) + 7) & ~7
    sections = [
        (0,) * 10,
        (0, 1, 6, BASE, code_offset, len(code), 0, 0, 16, 0),
        (0, 3, 0, 0, str_offset, len(strings), 0, 0, 1, 0),
        (0, 2, 0, 0, sym_offset, len(symbols), 2, 1, 8, symbol.size),
        (0, 4, 0, 0, rela_offset, len(rela_bytes), 3, 1, 8, rela.size),
    ]
    header = matcher.ELF_HEADER.pack(
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3,
        matcher.EM_X86_64,
        1,
        0,
        matcher.ELF_HEADER.size,
        section_offset,
        0,
        matcher.ELF_HEADER.size,
        matcher.PROGRAM_HEADER.size,
        1,
        matcher.SECTION_HEADER.size,
        len(sections),
        0,
    )
    program = matcher.PROGRAM_HEADER.pack(
        1, 5, code_offset, BASE, BASE, len(code), len(code), 0x1000
    )
    result = bytearray(header + program)
    result.extend(bytes(code_offset - len(result)))
    result.extend(code + symbols + strings + rela_bytes)
    result.extend(bytes(section_offset - len(result)))
    result.extend(b"".join(matcher.SECTION_HEADER.pack(*row) for row in sections))
    return bytes(result)


def patch_section(data, section_index, field, value):
    result = bytearray(data)
    header = matcher.elf_header(bytes(result))
    parser = matcher.ELFLayout.of(header).parser("section")
    offset = header[6] + section_index * parser.size
    row = list(parser.unpack_from(result, offset))
    row[field] = value
    parser.pack_into(result, offset, *row)
    return bytes(result)


def test_relocation_backed_reference_is_qualified():
    supplied = (
        graph.GraphSeed("source", "trusted_function", 0x100, 16, is_function=True),
        graph.GraphSeed("table", "decoder_table", 0x120, 8),
    )
    result = graph.build_elf_graph(
        linked_relocation_fixture(), supplied, instructions=(), auto_capstone=False
    )
    assert any(
        edge.kind == "relocation_reference" and edge.target == "table" and edge.qualified
        for edge in result.edges
    )


def test_unsupported_relocation_never_creates_a_qualified_edge():
    supplied = (
        graph.GraphSeed("source", "trusted_function", 0x100, 16, is_function=True),
        graph.GraphSeed("table", "decoder_table", 0x120, 8),
    )
    result = graph.build_elf_graph(
        linked_relocation_fixture(999), supplied, instructions=(), auto_capstone=False
    )
    assert all(edge.kind != "relocation_reference" for edge in result.edges)
    assert any(gap.code == "unsupported_relocation" for gap in result.gaps)


@pytest.mark.parametrize("target_section", [2, 99], ids=["wrong-owner", "missing-owner"])
def test_relocation_symbol_requires_consistent_file_backed_section_ownership(target_section):
    supplied = (
        graph.GraphSeed("source", "trusted_function", 0x100, 16, is_function=True),
        graph.GraphSeed("table", "decoder_table", 0x120, 8),
    )
    result = graph.build_elf_graph(
        linked_relocation_fixture(target_section=target_section),
        supplied,
        instructions=(),
        auto_capstone=False,
    )
    assert all(edge.kind != "relocation_reference" for edge in result.edges)
    assert any(gap.code == "inconsistent_relocation_symbol" for gap in result.gaps)


def test_relocation_site_must_be_wholly_executable_for_its_abi_width():
    supplied = (
        graph.GraphSeed("source", "trusted_function", 0x100, 16, is_function=True),
        graph.GraphSeed("table", "decoder_table", 0x120, 8),
    )
    result = graph.build_elf_graph(
        linked_relocation_fixture(site_address=BASE + 63),
        supplied,
        instructions=(),
        auto_capstone=False,
    )
    assert all(edge.kind != "relocation_reference" for edge in result.edges)


@pytest.mark.parametrize(
    ("target_address", "target_size", "expected"),
    [(BASE + 56, 8, True), (BASE + 56, 9, False)],
    ids=["exact-section-end", "past-section-end"],
)
def test_relocation_symbol_range_must_fit_its_allocated_section(
    target_address, target_size, expected
):
    target_offset = 0x100 + target_address - BASE
    supplied = (
        graph.GraphSeed("source", "trusted_function", 0x100, 16, is_function=True),
        graph.GraphSeed("table", "decoder_table", target_offset, 8),
    )
    result = graph.build_elf_graph(
        linked_relocation_fixture(
            target_address=target_address,
            target_size=target_size,
        ),
        supplied,
        instructions=(),
        auto_capstone=False,
    )
    edges = [edge for edge in result.edges if edge.kind == "relocation_reference"]
    assert bool(edges) is expected
    assert any(gap.code == "inconsistent_relocation_symbol" for gap in result.gaps) is (
        not expected
    )


def test_function_symbol_requires_consistent_executable_section_ownership():
    result = graph.build_elf_graph(
        linked_relocation_fixture(target_section=2, target_info=0x12),
        instructions=(),
        auto_capstone=False,
    )
    assert all("table" not in function.names for function in result.functions)
    assert any(gap.code == "inconsistent_function_symbol" for gap in result.gaps)


@pytest.mark.parametrize(
    ("section_index", "field", "value", "gap_code"),
    [
        (3, 9, 1, "malformed_symbols"),
        (3, 6, 99, "malformed_symbols"),
        (3, 5, 1, "malformed_symbols"),
        (3, 4, "outside", "malformed_symbols"),
        (4, 6, 99, "malformed_relocation"),
        (4, 9, 1, "malformed_relocation"),
        (4, 5, 1, "malformed_relocation"),
        (4, 4, "outside", "malformed_relocation"),
    ],
    ids=[
        "symbol-entsize",
        "symbol-link",
        "symbol-partial",
        "symbol-outside",
        "relocation-link",
        "relocation-entsize",
        "relocation-partial",
        "relocation-outside",
    ],
)
def test_malformed_symbol_and_relocation_tables_are_gaps(section_index, field, value, gap_code):
    data = linked_relocation_fixture()
    changed = len(data) + 1 if value == "outside" else value
    result = graph.build_elf_graph(
        patch_section(data, section_index, field, changed),
        instructions=(),
        auto_capstone=False,
    )
    assert any(gap.code == gap_code for gap in result.gaps)
