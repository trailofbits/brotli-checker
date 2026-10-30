#!/usr/bin/env python3
"""Build strict FLIRT function references from reviewed local Brotli ELF objects.

No downloads or target execution. Supply complete trusted upstream source trees.
The adjacent JSON bundle pins the generated ASCII .pat file and records source,
object, compiler, and flag provenance. These signatures identify decoder functions
only; they do not establish patch state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))
from brotli_binary_match import (  # noqa: E402
    EM_ARM,
    MAX_REFERENCE_SYMBOL_NAME_BYTES,
    STT_FUNC,
    ELFLayout,
    apply_relocations,
    checked_slice,
    elf_header,
    reference_symbol_name,
    reference_symbol_tables,
    section_headers,
    symbol_rows,
    valid_reference_function_owner,
)
from brotli_flirt import (  # noqa: E402
    EXACT_BYTE,
    MAX_BUNDLE_BYTES,
    MAX_FUNCTION_BYTES,
    MAX_PAT_BYTES,
    MIN_EXACT_DENSITY_DENOMINATOR,
    MIN_EXACT_DENSITY_NUMERATOR,
    MIN_EXACT_RUN_BYTES,
    parse_pat_records,
    validate_bundle_data,
)

SCHEMA_VERSION = 1
PATTERN_HEAD_BYTES = 32
MIN_EXACT_BYTES = 16
DEFAULT_PROFILES = (
    "-O2 -fno-pic -fno-PIE",
    "-O2 -fPIC",
    "-O3 -fno-pic -fno-PIE",
    "-O3 -fPIC",
)
DEFAULT_BUILD_NOTE = "Reviewed pristine upstream headers; decode.c unchanged"


@dataclass(frozen=True)
class FunctionPattern:
    name: str
    machine: int
    elf_class: int
    byteorder: str
    code: bytes
    mask: bytes

    @property
    def canonical(self) -> bytes:
        return bytes(
            value if selected == EXACT_BYTE else 0
            for value, selected in zip(self.code, self.mask, strict=True)
        )

    @property
    def wildcard_mask(self) -> bytes:
        return bytes(EXACT_BYTE if value == EXACT_BYTE else 0 for value in self.mask)

    @property
    def content_key(self) -> tuple[bytes, bytes]:
        return self.canonical, self.wildcard_mask

    @property
    def key(self) -> tuple[int, int, str, bytes, bytes]:
        wildcard_mask = bytes(EXACT_BYTE if value == EXACT_BYTE else 0 for value in self.mask)
        return self.machine, self.elf_class, self.byteorder, self.canonical, wildcard_mask

    @property
    def signature_id(self) -> str:
        digest = hashlib.sha256()
        digest.update(self.canonical)
        digest.update(self.wildcard_mask)
        return "brotli_" + digest.hexdigest()[:32]


def longest_exact_run(mask: bytes) -> int:
    longest = current = 0
    for value in mask:
        if value == EXACT_BYTE:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def strong_pattern(pattern: FunctionPattern) -> bool:
    size = len(pattern.code)
    exact = pattern.mask.count(EXACT_BYTE)
    return (
        PATTERN_HEAD_BYTES <= size <= MAX_FUNCTION_BYTES
        and exact >= MIN_EXACT_BYTES
        and longest_exact_run(pattern.mask) >= MIN_EXACT_RUN_BYTES
        and exact * MIN_EXACT_DENSITY_DENOMINATOR >= size * MIN_EXACT_DENSITY_NUMERATOR
    )


def render_bytes(code: bytes, mask: bytes) -> str:
    if len(code) != len(mask):
        msg = "Function code and relocation mask lengths differ"
        raise ValueError(msg)
    return "".join(
        f"{value:02X}" if selected == EXACT_BYTE else ".."
        for value, selected in zip(code, mask, strict=True)
    )


def render_pattern(pattern: FunctionPattern) -> str:
    if not strong_pattern(pattern):
        msg = f"Weak or unsupported function pattern: {pattern.name}"
        raise ValueError(msg)
    head = render_bytes(pattern.code[:PATTERN_HEAD_BYTES], pattern.mask[:PATTERN_HEAD_BYTES])
    tail = render_bytes(pattern.code[PATTERN_HEAD_BYTES:], pattern.mask[PATTERN_HEAD_BYTES:])
    line = f"{head} 00 0000 {len(pattern.code):04X} :0000 {pattern.signature_id}"
    return f"{line} {tail}" if tail else line


def _function_rows(data: bytes) -> tuple[tuple, list[tuple], list[tuple[str, int, int, int]]]:
    header = elf_header(data)
    if header[1] != 1 or not header[12]:
        msg = "Expected ELF relocatable object with section headers"
        raise ValueError(msg)
    sections = section_headers(data, header)
    rows: set[tuple[str, int, int, int]] = set()
    for table, strings, string_start, string_end in reference_symbol_tables(data, header, sections):
        for name_offset, info, _, index, symbol_address, size in symbol_rows(data, header, table):
            if info & 0xF != STT_FUNC or index == 0 or index >= len(sections):
                continue
            address = symbol_address & (~1 if header[2] == EM_ARM else -1)
            if not valid_reference_function_owner(sections[index], address, size):
                continue
            name = reference_symbol_name(data, name_offset, strings, string_start, string_end)
            if name is None or not name or any(character.isspace() for character in name):
                continue
            if len(name.encode("ascii")) >= MAX_REFERENCE_SYMBOL_NAME_BYTES:
                continue
            rows.add((name, index, address, size))
    return header, sections, sorted(rows, key=lambda row: (row[1], row[2], row[3], row[0]))


def _ambiguous_rows(rows: list[tuple[str, int, int, int]]) -> set[tuple[str, int, int, int]]:
    ambiguous: set[tuple[str, int, int, int]] = set()
    by_name: dict[str, list[tuple[str, int, int, int]]] = {}
    by_section: dict[int, list[tuple[str, int, int, int]]] = {}
    for row in rows:
        by_name.setdefault(row[0], []).append(row)
        by_section.setdefault(row[1], []).append(row)
    for named in by_name.values():
        if len(named) > 1:
            ambiguous.update(named)
    for section_rows in by_section.values():
        ordered = sorted(section_rows, key=lambda row: (row[2], row[2] + row[3]))
        for index, first in enumerate(ordered):
            first_end = first[2] + first[3]
            for second in ordered[index + 1 :]:
                if second[2] >= first_end:
                    break
                ambiguous.update((first, second))
    return ambiguous


def patterns_from_object(data: bytes) -> tuple[list[FunctionPattern], dict[str, int]]:
    """Extract strong, unambiguous full-function patterns from one trusted object."""
    header, sections, rows = _function_rows(data)
    ambiguous = _ambiguous_rows(rows)
    section_payloads: dict[int, tuple[bytes, bytes]] = {}
    patterns = []
    rejected = {"tiny_or_weak": 0, "ambiguous": 0}
    layout = ELFLayout.of(header)
    for name, index, address, size in rows:
        row = (name, index, address, size)
        if row in ambiguous:
            rejected["ambiguous"] += 1
            continue
        owner = sections[index]
        if index not in section_payloads:
            section_code = checked_slice(data, owner[4], owner[5])
            section_mask = bytearray(b"\xff" * len(section_code))
            apply_relocations(data, sections, index, section_code, section_mask, machine=header[2])
            section_payloads[index] = section_code, bytes(section_mask)
        section_code, section_mask = section_payloads[index]
        offset = address - owner[3]
        pattern = FunctionPattern(
            name=name,
            machine=header[2],
            elf_class=layout.bits,
            byteorder=layout.byteorder,
            code=section_code[offset : offset + size],
            mask=section_mask[offset : offset + size],
        )
        if not strong_pattern(pattern):
            rejected["tiny_or_weak"] += 1
            continue
        patterns.append(pattern)
    if not patterns:
        msg = "Object contains no strong, unambiguous function patterns"
        raise ValueError(msg)
    return patterns, rejected


def reviewed_sources() -> dict[str, dict]:
    registry = json.loads((ROOT / "skills/brotli-checker/references/fingerprints.json").read_text())
    return {
        entry["sha256"]: entry
        for entry in registry["fingerprints"]
        if entry.get("implementation", "google_brotli_c") == "google_brotli_c"
    }


def header_digest(tree: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((tree / "c").rglob("*.h")):
        digest.update(path.relative_to(tree).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def build_groups(
    trees: list[Path], compiler: str, flags: list[str], build_note: str
) -> tuple[list[FunctionPattern], list[dict]]:
    sources = reviewed_sources()
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        msg = f"Compiler not found: {compiler}"
        raise ValueError(msg)
    compiler_version = subprocess.check_output(  # noqa: S603 -- Trusted maintainer compiler.
        [compiler_path, "--version"], text=True
    ).splitlines()[0]
    patterns: list[FunctionPattern] = []
    groups = []
    with tempfile.TemporaryDirectory(prefix="brotli-flirt-") as temporary:
        output = Path(temporary) / "decode.o"
        for requested_tree in trees:
            tree = requested_tree.resolve()
            source = tree / "c/dec/decode.c"
            source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
            if source_sha256 not in sources:
                msg = f"Unreviewed decoder source: {source} ({source_sha256})"
                raise ValueError(msg)
            command = [
                compiler_path,
                *flags,
                "-I",
                str(tree / "c/include"),
                "-c",
                str(source),
                "-o",
                str(output),
            ]
            subprocess.run(command, check=True, capture_output=True)  # noqa: S603
            object_data = output.read_bytes()
            object_patterns, _rejected = patterns_from_object(object_data)
            source_entry = sources[source_sha256]
            identity = object_patterns[0]
            headers_sha256 = header_digest(tree)
            functions: dict[str, list[str]] = {}
            for pattern in object_patterns:
                functions.setdefault(pattern.name, []).append(pattern.signature_id)
            functions = {
                name: sorted(set(identifiers)) for name, identifiers in sorted(functions.items())
            }
            group_seed = json.dumps(
                {
                    "source_sha256": source_sha256,
                    "compiler": compiler_version,
                    "flags": shlex.join(flags),
                    "machine": identity.machine,
                    "elf_class": identity.elf_class,
                    "byteorder": identity.byteorder,
                    "headers_sha256": headers_sha256,
                    "build_note": build_note,
                },
                sort_keys=True,
            ).encode()
            group = {
                "id": "brotli_decoder_" + hashlib.sha256(group_seed).hexdigest()[:32],
                "machine": identity.machine,
                "elf_class": identity.elf_class,
                "byteorder": identity.byteorder,
                "source_sha256": source_sha256,
                "headers_sha256": headers_sha256,
                "source": source_entry["sources"][0]["url"],
                "object_sha256": hashlib.sha256(object_data).hexdigest(),
                "source_state": source_entry["state"],
                "compiler": compiler_version,
                "flags": shlex.join(flags),
                "build_note": build_note,
                "functions": functions,
            }
            # Keep non-schema provenance in the local generation report. Reading
            # these inputs here ensures a missing license/header tree fails before
            # a catalog is written.
            hashlib.sha256((tree / "LICENSE").read_bytes()).hexdigest()
            del _rejected
            patterns.extend(object_patterns)
            groups.append(group)
    return patterns, groups


def resolve_ambiguities(patterns: list[FunctionPattern]) -> tuple[list[FunctionPattern], set[str]]:
    """Drop identities whose same-machine byte pattern names multiple functions."""
    by_key: dict[tuple[int, int, str, bytes, bytes], dict[str, FunctionPattern]] = {}
    for pattern in patterns:
        by_key.setdefault(pattern.key, {})[pattern.name] = pattern
    ambiguous_ids = {
        pattern.signature_id
        for names in by_key.values()
        if len(names) > 1
        for pattern in names.values()
    }
    unique = {
        pattern.signature_id: pattern
        for pattern in patterns
        if pattern.signature_id not in ambiguous_ids
    }
    return sorted(unique.values(), key=lambda pattern: pattern.signature_id), ambiguous_ids


def render_pat(patterns: list[FunctionPattern]) -> str:
    return render_record_lines(
        {pattern.signature_id: render_pattern(pattern) for pattern in patterns}
    )


def render_record_lines(records: dict[str, str]) -> str:
    lines = [
        "# Generated by scripts/build_flirt_references.py; do not edit.",
        "# Derived from Google Brotli source under the MIT license.",
        "# Decoder function identity only; no patch-state claim.",
        *(records[identifier] for identifier in sorted(records)),
        "---",
        "",
    ]
    return "\n".join(lines)


def validate_pat(text: str) -> dict[str, str]:
    """Delegate strict PAT validation to the runtime format owner."""
    records = parse_pat_records(text.encode("ascii"))
    return {identifier: record.line for identifier, record in records.items()}


def validated_bundle(pat_path: Path, pat_text: str, groups: list[dict]) -> dict:
    if pat_path.suffix != ".pat":
        msg = "PAT output must end in .pat"
        raise ValueError(msg)
    bundle = {
        "schema_version": SCHEMA_VERSION,
        "pat_file": pat_path.name,
        "pat_sha256": hashlib.sha256(pat_text.encode()).hexdigest(),
        "groups": sorted(groups, key=lambda group: group["id"]),
    }
    validate_bundle_data(bundle, pat_text.encode("ascii"))
    return bundle


def read_bounded(path: Path, limit: int, label: str) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        msg = f"{label} exceeds the {limit}-byte limit"
        raise ValueError(msg)
    return data


def load_catalog(path: Path) -> tuple[dict[str, str], list[dict]]:
    try:
        bundle = json.loads(read_bounded(path, MAX_BUNDLE_BYTES, "FLIRT bundle"))
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as error:
        msg = "Invalid FLIRT bundle JSON"
        raise ValueError(msg) from error
    if not isinstance(bundle, dict) or set(bundle) != {
        "schema_version",
        "pat_file",
        "pat_sha256",
        "groups",
    }:
        msg = "Invalid FLIRT bundle fields"
        raise ValueError(msg)
    pat_file = bundle["pat_file"]
    if (
        bundle["schema_version"] != SCHEMA_VERSION
        or not isinstance(pat_file, str)
        or Path(pat_file).name != pat_file
        or not pat_file.endswith(".pat")
        or not isinstance(bundle["groups"], list)
    ):
        msg = "Invalid FLIRT bundle schema"
        raise ValueError(msg)
    pat_path = path.parent / pat_file
    if pat_path.is_symlink() or pat_path.resolve().parent != path.parent.resolve():
        msg = "FLIRT PAT must be a regular adjacent file"
        raise ValueError(msg)
    pat_data = read_bounded(pat_path, MAX_PAT_BYTES, "FLIRT PAT")
    if hashlib.sha256(pat_data).hexdigest() != bundle["pat_sha256"]:
        msg = "FLIRT PAT hash does not match its bundle"
        raise ValueError(msg)
    pat_text = pat_data.decode("ascii")
    expected = validated_bundle(pat_path, pat_text, bundle["groups"])
    if expected != bundle:
        msg = "FLIRT bundle is not in canonical generated form"
        raise ValueError(msg)
    return validate_pat(pat_text), bundle["groups"]


def merge_catalogs(
    record_sets: list[dict[str, str]], group_sets: list[list[dict]]
) -> tuple[dict[str, str], list[dict]]:
    records: dict[str, str] = {}
    groups: dict[str, dict] = {}
    for source_records in record_sets:
        for identifier, line in source_records.items():
            if identifier in records and records[identifier] != line:
                msg = f"Conflicting FLIRT signature id: {identifier}"
                raise ValueError(msg)
            records[identifier] = line
    for source_groups in group_sets:
        for group in source_groups:
            identifier = group["id"]
            if identifier in groups and groups[identifier] != group:
                msg = f"Conflicting FLIRT reference group id: {identifier}"
                raise ValueError(msg)
            groups[identifier] = group
    return records, list(groups.values())


def prune_ambiguous_names(
    records: dict[str, str], groups: list[dict]
) -> tuple[dict[str, str], list[dict]]:
    """Drop same-target patterns that provenance maps to multiple symbol names."""
    names: dict[tuple[tuple[str, int, int, str, str], str], set[str]] = {}
    for group in groups:
        identity = (
            group.get("format", "elf"),
            group["machine"],
            group["elf_class"],
            group["byteorder"],
            group.get("abi", "sysv"),
        )
        for symbol, identifiers in group["functions"].items():
            for identifier in identifiers:
                names.setdefault((identity, identifier), set()).add(symbol)
    ambiguous = {key for key, symbols in names.items() if len(symbols) > 1}
    kept_groups = []
    for original in groups:
        group = {**original, "functions": {}}
        identity = (
            group.get("format", "elf"),
            group["machine"],
            group["elf_class"],
            group["byteorder"],
            group.get("abi", "sysv"),
        )
        for symbol, identifiers in original["functions"].items():
            retained = [
                identifier for identifier in identifiers if (identity, identifier) not in ambiguous
            ]
            if retained:
                group["functions"][symbol] = retained
        if group["functions"]:
            kept_groups.append(group)
    referenced = {
        identifier
        for group in kept_groups
        for identifiers in group["functions"].values()
        for identifier in identifiers
    }
    return {
        identifier: line for identifier, line in records.items() if identifier in referenced
    }, kept_groups


def write_catalog(bundle_path: Path, pat_path: Path, pat_text: str, groups: list[dict]) -> None:
    if bundle_path.parent != pat_path.parent:
        msg = "Bundle and PAT output must share a directory"
        raise ValueError(msg)
    bundle = validated_bundle(pat_path, pat_text, groups)
    bundle_text = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
    if len(pat_text.encode()) > MAX_PAT_BYTES or len(bundle_text.encode()) > MAX_BUNDLE_BYTES:
        msg = "Generated FLIRT catalog exceeds its consumer byte limit"
        raise ValueError(msg)
    temporary_paths = []
    try:
        for target, data in (
            (pat_path, pat_text),
            (bundle_path, bundle_text),
        ):
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="ascii",
                newline="\n",
                dir=target.parent,
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            ) as stream:
                stream.write(data)
                temporary_paths.append((target, Path(stream.name)))
        pat_bytes = temporary_paths[0][1].read_bytes()
        if hashlib.sha256(pat_bytes).hexdigest() != bundle["pat_sha256"]:
            msg = "Written FLIRT pattern bytes do not match the manifest digest"
            raise ValueError(msg)
        validate_pat(pat_bytes.decode("ascii"))
        written_bundle = json.loads(temporary_paths[1][1].read_text(encoding="ascii"))
        if written_bundle != bundle:
            msg = "Written FLIRT bundle failed validation"
            raise ValueError(msg)
        for target, temporary in temporary_paths:
            temporary.replace(target)
    finally:
        for _, temporary in temporary_paths:
            temporary.unlink(missing_ok=True)


def ensure_nonempty_groups(records: dict[str, str], groups: list[dict]) -> None:
    if not records or any(not group["functions"] for group in groups):
        msg = "Ambiguity filtering left an empty FLIRT reference group"
        raise ValueError(msg)


def main() -> int:  # noqa: C901 -- CLI build and merge validation is fail-closed.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trees", nargs="*", type=Path)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--cflags", action="append", help="repeat for multiple profiles")
    parser.add_argument("--output", required=True, type=Path, help="JSON bundle output")
    parser.add_argument("--pat-output", type=Path, help="adjacent PAT output")
    parser.add_argument("--merge", action="append", default=[], type=Path)
    parser.add_argument("--build-note", default=DEFAULT_BUILD_NOTE)
    args = parser.parse_args()
    if not args.trees and not args.merge:
        parser.error("provide reviewed source trees or --merge catalogs")
    pat_output = args.pat_output or args.output.with_suffix(".pat")
    try:
        record_sets = []
        group_sets = []
        all_patterns: list[FunctionPattern] = []
        groups: list[dict] = []
        profiles = args.cflags or DEFAULT_PROFILES
        for profile in profiles:
            patterns, built_groups = build_groups(
                args.trees, args.cc, shlex.split(profile), args.build_note
            )
            all_patterns.extend(patterns)
            groups.extend(built_groups)
        if all_patterns:
            patterns, ambiguous_ids = resolve_ambiguities(all_patterns)
            for group in groups:
                for name in list(group["functions"]):
                    identifiers = [
                        identifier
                        for identifier in group["functions"][name]
                        if identifier not in ambiguous_ids
                    ]
                    if identifiers:
                        group["functions"][name] = identifiers
                    else:
                        del group["functions"][name]
            record_sets.append(
                {pattern.signature_id: render_pattern(pattern) for pattern in patterns}
            )
            group_sets.append(groups)
        for catalog in args.merge:
            records, merged_groups = load_catalog(catalog)
            record_sets.append(records)
            group_sets.append(merged_groups)
        records, groups = merge_catalogs(record_sets, group_sets)
        records, groups = prune_ambiguous_names(records, groups)
        ensure_nonempty_groups(records, groups)
        write_catalog(args.output, pat_output, render_record_lines(records), groups)
    except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    sys.exit(main())
