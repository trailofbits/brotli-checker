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


def test_decode_byte_budget_fails_before_partial_code_window_edges():
    result = graph.build_elf_graph(
        elf(aarch64_fixture()),
        seeds(),
        limits=graph.GraphLimits(max_decode_bytes=1),
    )
    assert result.limited
    assert result.edges == ()
    assert any(gap.code == "priority_decode_window_limit" for gap in result.gaps)


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


def linked_relocation_fixture(relocation_kind=2):
    code_offset = 0x100
    code = bytes(64)
    strings = b"\0source\0table\0"
    symbol = matcher.ELFLayout(64, "little").parser("symbol")
    symbols = b"".join(
        [
            bytes(symbol.size),
            symbol.pack(1, 0x12, 0, 1, BASE, 16),
            symbol.pack(8, 0x11, 0, 1, BASE + 32, 8),
        ]
    )
    sym_offset = code_offset + len(code)
    str_offset = sym_offset + len(symbols)
    rela = matcher.ELFLayout(64, "little").parser("rela")
    rela_bytes = rela.pack(BASE + 4, (2 << 32) | relocation_kind, 0)
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
