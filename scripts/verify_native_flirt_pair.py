#!/usr/bin/env python3
# ruff: noqa: EM101, TRY003
"""Verify paired native FLIRT profiles and opposite-state negative controls."""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))
from brotli_binary_data import file_data, sha256_data  # noqa: E402
from brotli_binary_layout import inspect_layout  # noqa: E402
from brotli_flirt import FlirtAssessment, load_flirt_bundle, match_flirt  # noqa: E402

I386_MACHINE = 0x14C
MACH_CPUS = {"x86_64": 0x01000007, "aarch64": 0x0100000C}


def assessment(binary: Path, bundle: Path) -> FlirtAssessment:
    with binary.open("rb") as stream, file_data(stream, None) as data:
        return match_flirt(data, load_flirt_bundle(bundle))


def verify_own(
    binary: Path, bundle: Path, state: str, *, component_bound: bool = False
) -> FlirtAssessment:
    result = assessment(binary, bundle)
    profiles = result.get("patch_profiles", [])
    if result["status"] != "recognized" or not profiles:
        msg = f"Native {state} profile did not match its own binary completely"
        raise ValueError(msg)
    expected_status = f"{state}_code_match" if component_bound else "unknown"
    if {item["source_state_provenance"] for item in profiles} != {state} or any(
        item["target_patch_status"] != expected_status for item in profiles
    ):
        msg = f"Native {state} profile returned the wrong source-state population"
        raise ValueError(msg)
    if component_bound and any(
        item["method"] != "native_flirt_postlink_component" for item in profiles
    ):
        msg = f"Native {state} profile lacks post-link component ownership"
        raise ValueError(msg)
    return result


def verify_cross(binary: Path, bundle: Path, forbidden: str) -> None:
    profiles = assessment(binary, bundle).get("patch_profiles", [])
    if any(item["source_state_provenance"] == forbidden for item in profiles):
        msg = f"Opposite-state native {forbidden} profile matched completely"
        raise ValueError(msg)


def _executable_payload(path: Path) -> tuple[bytes, int]:
    with path.open("rb") as stream, file_data(stream, None) as data:
        layout = inspect_layout(data)
        executable = layout.get("ranges", {}).get("executable", [])
        if layout.get("kind") != "pe" or layout.get("gaps") or len(executable) != 1:
            msg = "Mixed-copy control requires one complete PE executable range"
            raise ValueError(msg)
        owner = executable[0]
        return data[owner["file_offset"] : owner["file_offset"] + owner["size"]], {
            "i386": 0x14C,
            "x86_64": 0x8664,
            "aarch64": 0xAA64,
        }[layout["machine"]]


def _mixed_pe(first: Path, second: Path) -> bytes:
    first_code, first_machine = _executable_payload(first)
    second_code, second_machine = _executable_payload(second)
    if first_machine != second_machine:
        msg = "Mixed-copy control inputs have different PE machines"
        raise ValueError(msg)
    payload = first_code + bytes(64) + second_code
    result = bytearray(0x200 + len(payload))
    result[:2] = b"MZ"
    struct.pack_into("<I", result, 0x3C, 0x80)
    result[0x80:0x84] = b"PE\0\0"
    optional_size = 0xE0 if first_machine == I386_MACHINE else 0xF0
    struct.pack_into("<HHIIIHH", result, 0x84, first_machine, 1, 0, 0, 0, optional_size, 0x22)
    struct.pack_into("<H", result, 0x98, 0x10B if first_machine == I386_MACHINE else 0x20B)
    section = 0x98 + optional_size
    result[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", result, section + 8, len(payload), 0x1000, len(payload), 0x200)
    struct.pack_into("<I", result, section + 36, 0x60000020)
    result[0x200:] = payload
    return bytes(result)


def _mach_executable_payloads(path: Path) -> dict[str, bytes]:
    with path.open("rb") as stream, file_data(stream, None) as data:
        layout = inspect_layout(data)
        rows = layout["slices"] or [layout]
        result = {}
        for row in rows:
            executable = row.get("ranges", {}).get("executable", [])
            if row.get("kind") != "mach_o" or row.get("gaps") or not executable:
                raise ValueError("Mixed-copy control requires complete Mach executable ranges")
            start = min(item["file_offset"] for item in executable)
            end = max(item["file_offset"] + item["size"] for item in executable)
            machine = row["machine"]
            if machine in result or machine not in MACH_CPUS:
                raise ValueError("Mixed-copy control has ambiguous Mach architecture ownership")
            result[machine] = data[start:end]
        return result


def _mixed_mach(first_code: bytes, second_code: bytes, machine: str) -> bytes:
    payload = first_code + bytes(64) + second_code
    file_offset = 0x100
    result = bytearray(file_offset + len(payload))
    struct.pack_into(
        "<8I",
        result,
        0,
        0xFEEDFACF,
        MACH_CPUS[machine],
        0,
        6,
        1,
        72,
        0,
        0,
    )
    struct.pack_into(
        "<II16sQQQQIIII",
        result,
        32,
        0x19,
        72,
        b"__TEXT" + bytes(10),
        0x100000,
        len(payload),
        file_offset,
        len(payload),
        7,
        5,
        0,
        0,
    )
    result[file_offset:] = payload
    return bytes(result)


def _verify_mixed_mach_components(
    affected_binary: Path,
    affected_bundle: Path,
    fixed_binary: Path,
    fixed_bundle: Path,
) -> dict:
    affected_payloads = _mach_executable_payloads(affected_binary)
    fixed_payloads = _mach_executable_payloads(fixed_binary)
    if affected_payloads.keys() != fixed_payloads.keys():
        raise ValueError("Mixed-copy control Mach architectures differ")
    affected_catalog = load_flirt_bundle(affected_bundle)
    fixed_catalog = load_flirt_bundle(fixed_bundle)
    affected_components = []
    fixed_components = []
    for machine in sorted(affected_payloads):
        carrier = _mixed_mach(affected_payloads[machine], fixed_payloads[machine], machine)
        affected = match_flirt(carrier, affected_catalog).get("patch_profiles", [])
        fixed = match_flirt(carrier, fixed_catalog).get("patch_profiles", [])
        if {item["target_patch_status"] for item in affected} != {"vulnerable_code_match"}:
            raise ValueError("Mixed-copy control lost a vulnerable Mach component")
        if {item["target_patch_status"] for item in fixed} != {"fixed_code_match"}:
            raise ValueError("Mixed-copy control lost a fixed Mach component")
        affected_offsets = {item["component_file_offset"] for item in affected}
        fixed_offsets = {item["component_file_offset"] for item in fixed}
        if not affected_offsets or not fixed_offsets or affected_offsets & fixed_offsets:
            raise ValueError("Mixed-copy control did not separate Mach component ownership")
        affected_components.extend(
            {"machine": machine, "file_offset": offset} for offset in sorted(affected_offsets)
        )
        fixed_components.extend(
            {"machine": machine, "file_offset": offset} for offset in sorted(fixed_offsets)
        )
    return {
        "status": "separate_components_verified",
        "vulnerable_components": affected_components,
        "fixed_components": fixed_components,
    }


def verify_mixed_components(
    affected_binary: Path,
    affected_bundle: Path,
    fixed_binary: Path,
    fixed_bundle: Path,
) -> dict:
    with affected_binary.open("rb") as stream, file_data(stream, None) as data:
        kind = inspect_layout(data)["kind"]
    if kind in {"mach_o", "mach_o_universal"}:
        return _verify_mixed_mach_components(
            affected_binary, affected_bundle, fixed_binary, fixed_bundle
        )
    if kind != "pe":
        raise ValueError("Mixed-copy control requires PE or Mach binaries")
    carrier = _mixed_pe(affected_binary, fixed_binary)
    affected = match_flirt(carrier, load_flirt_bundle(affected_bundle)).get("patch_profiles", [])
    fixed = match_flirt(carrier, load_flirt_bundle(fixed_bundle)).get("patch_profiles", [])
    if {item["target_patch_status"] for item in affected} != {"vulnerable_code_match"}:
        msg = "Mixed-copy control lost the vulnerable component"
        raise ValueError(msg)
    if {item["target_patch_status"] for item in fixed} != {"fixed_code_match"}:
        msg = "Mixed-copy control lost the fixed component"
        raise ValueError(msg)
    affected_offsets = {item["component_file_offset"] for item in affected}
    fixed_offsets = {item["component_file_offset"] for item in fixed}
    if not affected_offsets or not fixed_offsets or affected_offsets & fixed_offsets:
        msg = "Mixed-copy control did not preserve distinct component ownership"
        raise ValueError(msg)
    return {
        "status": "separate_components_verified",
        "vulnerable_component_offsets": sorted(affected_offsets),
        "fixed_component_offsets": sorted(fixed_offsets),
    }


def artifact_assertion(path: Path, state: str, result: FlirtAssessment) -> dict:
    profiles = [
        item
        for item in result.get("patch_profiles", [])
        if item["source_state_provenance"] == state
    ]
    if not profiles:
        msg = f"Exact native artifact has no complete {state} build provenance"
        raise ValueError(msg)
    provenance_by_id = {
        item["id"]: {
            **{
                key: item[key]
                for key in (
                    "id",
                    "format",
                    "abi",
                    "machine",
                    "elf_class",
                    "byteorder",
                    "source",
                    "source_sha256",
                    "headers_sha256",
                    "object_sha256",
                    "compiler",
                    "flags",
                    "build_note",
                )
            },
            "source_state": item["source_state_provenance"],
        }
        for item in profiles
    }
    provenance = [provenance_by_id[key] for key in sorted(provenance_by_id)]
    with path.open("rb") as stream, file_data(stream, None) as data:
        binary_sha256 = sha256_data(data)
        size = len(data)
    return {
        "sha256": binary_sha256,
        "size": size,
        "patch_status": f"{state}_code_match",
        "method": "paired_native_build_exact_artifact",
        "provenance": provenance,
        "negative_control": "opposite_source_state_rejected",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--affected-binary", required=True, type=Path)
    parser.add_argument("--affected-bundle", required=True, type=Path)
    parser.add_argument("--fixed-binary", required=True, type=Path)
    parser.add_argument("--fixed-bundle", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--component-bound", action="store_true")
    parser.add_argument("--mixed-copy-control", action="store_true")
    args = parser.parse_args()
    try:
        affected = verify_own(
            args.affected_binary,
            args.affected_bundle,
            "vulnerable",
            component_bound=args.component_bound,
        )
        fixed = verify_own(
            args.fixed_binary,
            args.fixed_bundle,
            "fixed",
            component_bound=args.component_bound,
        )
        verify_cross(args.fixed_binary, args.affected_bundle, "vulnerable")
        verify_cross(args.affected_binary, args.fixed_bundle, "fixed")
        args.output.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "affected_match_count": len(affected["matches"]),
                    "fixed_match_count": len(fixed["matches"]),
                    "opposite_state_controls": "rejected",
                    "component_binding": (
                        verify_mixed_components(
                            args.affected_binary,
                            args.affected_bundle,
                            args.fixed_binary,
                            args.fixed_bundle,
                        )
                        if args.mixed_copy_control
                        else "not_requested"
                    ),
                    "exact_artifact_assertions": [
                        artifact_assertion(args.affected_binary, "vulnerable", affected),
                        artifact_assertion(args.fixed_binary, "fixed", fixed),
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
