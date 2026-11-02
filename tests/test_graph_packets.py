import copy
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import brotli_binary_graph as graph
import brotli_binary_match as matcher
import brotli_binary_triage as triage
import brotli_graph_packets as packets
import pytest


def elf(payload=b"\x90\xc3", machine=matcher.EM_X86_64):
    header = matcher.ELF_HEADER.pack(
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3,
        machine,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    program = matcher.PROGRAM_HEADER.pack(
        1, 5, 120, 0x401000, 0x401000, len(payload), len(payload), 1
    )
    return header + program + payload


def triage_document(
    tmp_path,
    data,
    text="401000: 90 nop\n401001: c3 ret",
    *,
    limited=False,
    stop_address=0x401002,
):
    args = triage.build_parser().parse_args(["target"])
    report = triage.base_report(Path("target"), args)
    report["target"].update(
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )
    directory = tmp_path / f"capture-{sum(1 for _ in tmp_path.iterdir())}"
    directory.mkdir()
    command = triage.fragment_command(
        report,
        data,
        directory,
        Path("/trusted/objdump"),
        0x401000,
        stop_address,
    )
    report["tool"]["path"] = "/trusted/objdump"
    report["tool"]["commands"].append(command)
    report["evidence"]["disassembly"].append(
        {
            "scope": {
                "mode": "symbol",
                "name": "ProcessCommands",
                "start_address": 0x401000,
                "stop_address": stop_address,
                "size_bytes": stop_address - 0x401000,
            },
            "returncode": 0,
            "limited": limited,
            "reason": "output capped" if limited else None,
            "text": text,
        }
    )
    if limited:
        report["collection"]["reasons"].append("output capped")
    else:
        report["collection"].update(status="evidence_collected", incomplete=False)
    return report


def encoded(report):
    return json.dumps(report, sort_keys=True).encode()


def test_real_triage_schema_yields_exact_target_instruction_packet(tmp_path):
    data = elf()
    raw = encoded(triage_document(tmp_path, data))

    packet = packets.instruction_packet_from_triage(data, raw)
    result = graph.build_elf_graph(data, instructions=packet, auto_capstone=False)

    assert packets.graph_triage_target_sha256(raw) == hashlib.sha256(data).hexdigest()
    assert packet.machine == matcher.EM_X86_64
    assert [(item.address, item.raw) for item in packet.instructions] == [
        (0x401000, b"\x90"),
        (0x401001, b"\xc3"),
    ]
    assert packet.gaps == ()
    assert packet.limited is False
    assert not any(gap.code == "objdump_machine_mismatch" for gap in result.gaps)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda report: report["target"].update(sha256="0" * 64),
        lambda report: report["tool"]["fragments"][0].update(sha256="0" * 64),
        lambda report: report["tool"]["commands"][0].__setitem__(
            report["tool"]["commands"][0].index("--architecture=i386:x86-64"),
            "--architecture=aarch64",
        ),
        lambda report: report["evidence"]["disassembly"][0].update(
            text="401000: cc int3\n401001: c3 ret"
        ),
    ],
    ids=["target-hash", "fragment-hash", "architecture", "instruction-bytes"],
)
def test_hash_architecture_and_instruction_tampering_are_rejected(tmp_path, mutate):
    data = elf()
    report = triage_document(tmp_path, data)
    mutate(report)

    with pytest.raises(ValueError, match=r"[Gg]raph-triage"):
        packets.instruction_packet_from_triage(data, encoded(report))


def test_duplicate_json_and_nonexecutable_fragment_mapping_are_rejected(tmp_path):
    data = elf()
    raw = encoded(triage_document(tmp_path, data))
    duplicated = raw[:-1] + b',"schema_version":2}'
    with pytest.raises(ValueError, match="Duplicate"):
        packets.graph_triage_target_sha256(duplicated)

    report = triage_document(tmp_path, data)
    fragment = report["tool"]["fragments"][0]
    fragment.update(file_offset=0, sha256=hashlib.sha256(data[:2]).hexdigest())
    with pytest.raises(ValueError, match="executable target ownership"):
        packets.instruction_packet_from_triage(data, encoded(report))


def test_routing_rejects_malformed_target_shape_and_digest(tmp_path):
    data = elf()
    base = triage_document(tmp_path, data)
    malformed = []
    value = copy.deepcopy(base)
    value["target"] = []
    malformed.append(value)
    value = copy.deepcopy(base)
    value["target"]["sha256"] = 7
    malformed.append(value)
    value = copy.deepcopy(base)
    value["target"]["sha256"] = "A" * 64
    malformed.append(value)
    for report in malformed:
        with pytest.raises(ValueError, match="target"):
            packets.graph_triage_target_sha256(encoded(report))


def test_disassembly_scope_optional_file_offset_must_match_exact_fragment(tmp_path):
    data = elf()
    report = triage_document(tmp_path, data)
    report["evidence"]["disassembly"][0]["scope"]["file_offset"] = 120
    packet = packets.instruction_packet_from_triage(data, encoded(report))
    assert packet.instructions
    report["evidence"]["disassembly"][0]["scope"]["file_offset"] = 121
    with pytest.raises(ValueError, match="file offset disagrees"):
        packets.instruction_packet_from_triage(data, encoded(report))


def test_incomplete_and_total_budget_evidence_remains_explicitly_partial(tmp_path):
    data = elf()
    raw = encoded(triage_document(tmp_path, data, limited=True))
    packet = packets.instruction_packet_from_triage(data, raw)
    assert packet.instructions
    assert packet.limited is True
    assert {gap.code for gap in packet.gaps} == {
        "triage_collection_incomplete",
        "triage_objdump_incomplete",
    }

    output_limited = packets.instruction_packet_from_triage(
        data,
        encoded(triage_document(tmp_path, data)),
        replace(graph.DEFAULT_GRAPH_LIMITS, max_objdump_bytes=1),
    )
    assert output_limited.instructions == ()
    assert output_limited.limited is True
    assert "objdump_output_limit" in {gap.code for gap in output_limited.gaps}

    limits = replace(graph.DEFAULT_GRAPH_LIMITS, max_decode_bytes=1)
    bounded = packets.instruction_packet_from_triage(
        data, encoded(triage_document(tmp_path, data)), limits
    )
    assert bounded.instructions == ()
    assert bounded.limited is True
    assert "triage_fragment_byte_limit" in {gap.code for gap in bounded.gaps}

    omitted_row = triage_document(tmp_path, data, text="401000: 90 nop")
    incomplete = packets.instruction_packet_from_triage(data, encoded(omitted_row))
    assert incomplete.instructions
    assert incomplete.limited is True
    assert {gap.code for gap in incomplete.gaps} >= {
        "triage_instruction_coverage_incomplete",
        "triage_fragments_unexamined",
    }


def test_non_x86_text_cannot_fabricate_semantic_branch_targets(tmp_path):
    data = elf(machine=matcher.EM_PPC64)
    report = triage_document(
        tmp_path,
        data,
        text="401000: 90 bl 401001\n401001: c3 ret",
        limited=True,
    )
    packet = packets.instruction_packet_from_triage(data, encoded(report))

    assert all(not instruction.direct_call_targets for instruction in packet.instructions)
    assert packet.limited is True
    assert "triage_instruction_semantics_unknown" in {gap.code for gap in packet.gaps}

    result = graph.build_elf_graph(
        data,
        seeds=(
            graph.GraphSeed("source", "supplied", 120, 1, is_function=True),
            graph.GraphSeed("target", "supplied", 121, 1, is_function=True),
        ),
        instructions=packet,
        auto_capstone=False,
    )
    assert not any(edge.kind in {"direct_call", "tail_call"} for edge in result.edges)


@pytest.mark.parametrize("byteorder", ["little", "big"])
def test_ppc64_i_form_branch_targets_are_derived_from_bytes(byteorder):
    address = 0x1000

    def decoded(word):
        instruction = graph.DecodedInstruction(address, word.to_bytes(4, byteorder), "fake", "0")
        return packets._ppc64_direct_transfer(instruction, byteorder)  # noqa: SLF001

    assert decoded(0x48000009) == (address + 8, True)  # bl +8
    assert decoded(0x48000008) == (address + 8, False)  # b +8
    assert decoded(0x48000102) == (0x100, False)  # ba 0x100
    assert decoded(0x4BFFFFFC) == (address - 4, False)  # b -4


@pytest.mark.parametrize(
    ("address", "raw", "byteorder"),
    [
        (0x1001, bytes.fromhex("09000048"), "little"),
        (0x1000, bytes.fromhex("090000"), "little"),
        (0x1000, bytes.fromhex("09000048"), "middle"),
        (0x1000, bytes.fromhex("00000060"), "little"),
    ],
)
def test_ppc64_decoder_rejects_unaligned_truncated_wrong_endian_and_nonbranch(
    address, raw, byteorder
):
    instruction = graph.DecodedInstruction(address, raw, "fake", "0")
    assert packets._ppc64_direct_transfer(instruction, byteorder) is None  # noqa: SLF001


def test_ppc64_vle_flag_is_rejected_before_packet_semantics(tmp_path):
    data = bytearray(elf(machine=matcher.EM_PPC64))
    data[48:52] = packets.EF_PPC_VLE.to_bytes(4, "little")
    report = triage_document(tmp_path, bytes(data), text="401000: 90 nop\n401001: c3 ret")
    with pytest.raises(ValueError, match="VLE"):
        packets.instruction_packet_from_triage(bytes(data), encoded(report))


def test_ppc64_text_target_cannot_override_byte_derived_branch(tmp_path):
    data = elf(payload=bytes.fromhex("09000048"), machine=matcher.EM_PPC64)
    report = triage_document(
        tmp_path,
        data,
        text="401000: 09 00 00 48 bl deadbeef",
        stop_address=0x401004,
    )
    packet = packets.instruction_packet_from_triage(data, encoded(report))
    assert packet.instructions[0].direct_call_targets == (0x401008,)
    assert packet.limited is True
    assert "triage_semantics_mismatch" in {gap.code for gap in packet.gaps}


def test_ppc64_matching_text_and_bytes_retains_verified_branch_without_gap(tmp_path):
    data = elf(payload=bytes.fromhex("09000048"), machine=matcher.EM_PPC64)
    report = triage_document(
        tmp_path,
        data,
        text="401000: 09 00 00 48 bl 401008",
        stop_address=0x401004,
    )
    packet = packets.instruction_packet_from_triage(data, encoded(report))
    assert packet.instructions[0].direct_call_targets == (0x401008,)
    assert packet.gaps == ()
    assert packet.limited is False


def test_x86_text_cannot_fabricate_rip_data_reference(tmp_path):
    data = elf(payload=b"\x05\x00\x00\x00\x00\xc3")
    report = triage_document(
        tmp_path,
        data,
        text="401000: 05 00 00 00 00 mov 0x0(%rip)\n401005: c3 ret",
        stop_address=0x401006,
    )
    packet = packets.instruction_packet_from_triage(data, encoded(report))
    assert packet.instructions[0].mnemonic == ""
    assert packet.instructions[0].operands == ""
    assert packet.limited is True
    assert "triage_semantics_unverified" in {gap.code for gap in packet.gaps}

    result = graph.build_elf_graph(
        data,
        seeds=(
            graph.GraphSeed("source", "supplied", 120, 5, is_function=True),
            graph.GraphSeed("target", "decoder_table", 125, 1),
        ),
        instructions=packet,
        auto_capstone=False,
    )
    assert not any(edge.target == "target" for edge in result.edges)


def test_aggregate_output_limit_skips_all_later_scopes_without_schema_failure(tmp_path):
    data = elf(payload=b"\x90\xc3" * 3)
    report = triage_document(tmp_path, data)
    directory = Path(report["tool"]["fragments"][0]["path"]).parent
    for start in (0x401002, 0x401004):
        report["tool"]["commands"].append(
            triage.fragment_command(
                report,
                data,
                directory,
                Path("/trusted/objdump"),
                start,
                start + 2,
            )
        )
        report["evidence"]["disassembly"].append(
            {
                "scope": {
                    "mode": "symbol",
                    "name": f"function_{start:x}",
                    "start_address": start,
                    "stop_address": start + 2,
                    "size_bytes": 2,
                },
                "returncode": 0,
                "limited": False,
                "reason": None,
                "text": f"{start:x}: 90 nop\n{start + 1:x}: c3 ret",
            }
        )
    first_size = len(report["evidence"]["disassembly"][0]["text"].encode())
    packet = packets.instruction_packet_from_triage(
        data,
        encoded(report),
        replace(graph.DEFAULT_GRAPH_LIMITS, max_objdump_bytes=first_size),
    )
    assert [(item.address, item.raw) for item in packet.instructions] == [
        (0x401000, b"\x90"),
        (0x401001, b"\xc3"),
    ]
    assert packet.limited is True
    assert {gap.code for gap in packet.gaps} >= {
        "objdump_output_limit",
        "triage_fragments_unexamined",
    }


def test_document_and_fragment_population_limits_fail_closed(tmp_path, monkeypatch):
    data = elf()
    raw = encoded(triage_document(tmp_path, data))
    with pytest.raises(ValueError, match="document exceeds"):
        packets._document(raw, maximum=len(raw) - 1)  # noqa: SLF001

    monkeypatch.setattr(packets, "MAX_FRAGMENTS", 0)
    with pytest.raises(ValueError, match="excessive"):
        packets.instruction_packet_from_triage(data, raw)


def test_schema_type_and_shape_failures_are_independently_rejected(tmp_path):
    data = elf()
    base = triage_document(tmp_path, data)
    malformed = []

    value = copy.deepcopy(base)
    value["schema_version"] = True
    malformed.append(value)
    value = copy.deepcopy(base)
    value["target"]["sha256"] = 7
    malformed.append(value)
    value = copy.deepcopy(base)
    value["tool"]["fragments"][0] = []
    malformed.append(value)
    value = copy.deepcopy(base)
    value["tool"]["commands"][0] = []
    malformed.append(value)
    value = copy.deepcopy(base)
    value["evidence"]["disassembly"][0]["scope"]["start_address"] = "0x401000"
    malformed.append(value)
    value = copy.deepcopy(base)
    value["evidence"] = []
    malformed.append(value)
    value = copy.deepcopy(base)
    value["collection"] = []
    malformed.append(value)
    value = copy.deepcopy(base)
    value["classification"] = []
    malformed.append(value)

    for report in malformed:
        with pytest.raises(ValueError, match=r"[Gg]raph-triage"):
            packets.instruction_packet_from_triage(data, encoded(report))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda item: item.update(returncode=True),
        lambda item: item.update(limited=1),
        lambda item: item.update(text=7),
        lambda item: item.update(reason=""),
        lambda item: item.pop("scope"),
    ],
)
def test_disassembly_result_fields_fail_independently(tmp_path, mutation):
    data = elf()
    report = triage_document(tmp_path, data)
    mutation(report["evidence"]["disassembly"][0])
    with pytest.raises(ValueError, match="disassembly"):
        packets.instruction_packet_from_triage(data, encoded(report))


def test_inclusive_limits_accept_exact_populations_and_mark_first_overflow(tmp_path, monkeypatch):
    data = elf()
    report = triage_document(tmp_path, data)
    raw = encoded(report)
    assert packets._document(raw, maximum=len(raw))["schema_version"] == 2  # noqa: SLF001

    collector = packets._GapCollector(1)  # noqa: SLF001
    collector.add("first", "first")
    collector.add("second", "second")
    assert [gap.code for gap in collector.values] == ["first"]
    assert collector.limited is True

    monkeypatch.setattr(packets, "MAX_FRAGMENTS", 1)
    text_size = len(report["evidence"]["disassembly"][0]["text"].encode())
    exact = packets.instruction_packet_from_triage(
        data,
        raw,
        replace(
            graph.DEFAULT_GRAPH_LIMITS,
            max_decode_bytes=2,
            max_instructions=2,
            max_objdump_bytes=text_size,
        ),
    )
    assert len(exact.instructions) == 2
    assert exact.limited is False

    with pytest.raises(ValueError, match="limits must be positive"):
        packets.instruction_packet_from_triage(
            data,
            raw,
            replace(graph.DEFAULT_GRAPH_LIMITS, max_decode_bytes=0),
        )


@pytest.mark.parametrize(
    "case",
    [
        {
            "payload": b"\xe8\x00\x00\x00\x00\xc3",
            "text": "401000: e8 00 00 00 00 nop\n401005: c3 ret",
            "stop": 0x401006,
            "source_size": 5,
            "target_offset": 125,
            "kind": "direct_call",
        },
        {
            "payload": b"\xeb\x00\xc3",
            "text": "401000: eb 00 nop\n401002: c3 ret",
            "stop": 0x401003,
            "source_size": 2,
            "target_offset": 122,
            "kind": "tail_call",
        },
    ],
)
def test_x86_direct_transfers_are_canonicalized_from_bytes(tmp_path, case):
    data = elf(payload=case["payload"])
    report = triage_document(tmp_path, data, text=case["text"], stop_address=case["stop"])
    packet = packets.instruction_packet_from_triage(data, encoded(report))
    assert packet.instructions[0].mnemonic == ("call" if case["kind"] == "direct_call" else "jmp")
    assert packet.instructions[0].operands == ""
    assert packet.limited is False

    result = graph.build_elf_graph(
        data,
        seeds=(
            graph.GraphSeed("source", "supplied", 120, case["source_size"], is_function=True),
            graph.GraphSeed("target", "supplied", case["target_offset"], 1, is_function=True),
        ),
        instructions=packet,
        auto_capstone=False,
    )
    assert any(edge.kind == case["kind"] for edge in result.edges)


def test_unknown_generic_isa_instruction_is_explicitly_incomplete(tmp_path):
    data = elf(payload=b"\x00\x00\x00\x00", machine=matcher.EM_LOONGARCH)
    report = triage_document(
        tmp_path,
        data,
        text="401000: 00 00 00 00 nop",
        stop_address=0x401004,
    )
    packet = packets.instruction_packet_from_triage(data, encoded(report))
    assert packet.limited is True
    assert "triage_instruction_semantics_unknown" in {gap.code for gap in packet.gaps}


def test_independent_collection_and_result_incompleteness_are_retained(tmp_path):
    data = elf()
    collection_report = triage_document(tmp_path, data)
    collection_report["collection"]["reasons"] = ["collector stopped early"]
    collection_report["collection"]["incomplete"] = False
    collection = packets.instruction_packet_from_triage(data, encoded(collection_report))
    assert collection.limited is True
    assert "triage_collection_incomplete" in {gap.code for gap in collection.gaps}

    result_report = triage_document(tmp_path, data)
    result_report["evidence"]["disassembly"][0].update(limited=True, reason="output capped")
    result = packets.instruction_packet_from_triage(data, encoded(result_report))
    assert result.limited is True
    assert "triage_objdump_incomplete" in {gap.code for gap in result.gaps}


@pytest.mark.skipif(
    not os.environ.get("BROTLI_PPC64_BRANCH_FIXTURE"),
    reason="set BROTLI_PPC64_BRANCH_FIXTURE to a linked retained ppc64le sample",
)
def test_retained_ppc64le_objdump_sample_builds_only_byte_derived_edges(tmp_path):
    data = Path(os.environ["BROTLI_PPC64_BRANCH_FIXTURE"]).read_bytes()
    header = matcher.elf_header(data)
    executable = [
        (offset, virtual, size)
        for kind, flags, offset, virtual, _, size, _, _ in matcher.program_headers(data, header)
        if kind == 1 and flags & 1 and size
    ]
    assert len(executable) == 1
    offset, start, size = executable[0]
    assert size == 16
    assert data[offset : offset + size] == bytes.fromhex("09000048 08000048 2000804e 00000060")

    args = triage.build_parser().parse_args(["target"])
    report = triage.base_report(Path("target"), args)
    report["target"].update(sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))
    directory = tmp_path / "capture"
    directory.mkdir()
    command = triage.fragment_command(
        report,
        data,
        directory,
        Path("/trusted/objdump"),
        start,
        start + size,
    )
    report["tool"]["path"] = "/trusted/objdump"
    report["tool"]["commands"].append(command)
    report["evidence"]["disassembly"].append(
        {
            "scope": {
                "mode": "symbol",
                "name": "_start_and_callees",
                "start_address": start,
                "stop_address": start + size,
                "size_bytes": size,
            },
            "returncode": 0,
            "limited": False,
            "reason": None,
            "text": (
                f"{start:x}: 09 00 00 48 bl {start + 8:x}\n"
                f"{start + 4:x}: 08 00 00 48 b {start + 12:x}\n"
                f"{start + 8:x}: 20 00 80 4e blr\n"
                f"{start + 12:x}: 00 00 00 60 nop"
            ),
        }
    )
    report["collection"].update(status="evidence_collected", incomplete=False)
    packet = packets.instruction_packet_from_triage(data, encoded(report))
    assert "triage_instruction_semantics_unknown" in {gap.code for gap in packet.gaps}
    assert packet.limited is True
    assert packet.instructions[0].direct_call_targets == (start + 8,)
    assert packet.instructions[1].tail_call_targets == (start + 12,)

    result = graph.build_elf_graph(
        data,
        seeds=(
            graph.GraphSeed("start", "supplied", offset, 8, is_function=True),
            graph.GraphSeed("callee", "supplied", offset + 8, 4, is_function=True),
            graph.GraphSeed("done", "supplied", offset + 12, 4, is_function=True),
        ),
        instructions=packet,
        auto_capstone=False,
    )
    assert {(edge.kind, edge.target) for edge in result.edges} >= {
        ("direct_call", f"function:0x{offset + 8:x}"),
        ("tail_call", f"function:0x{offset + 12:x}"),
    }
