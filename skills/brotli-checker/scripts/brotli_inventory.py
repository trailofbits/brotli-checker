#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12,<3.16"
# dependencies = []
# [tool.ty.environment]
# extra-paths = ["."]
# ///

"""Offline, non-executing evidence collection for CVE-2026-111497."""

from __future__ import annotations

import argparse
import bz2
import gzip
import io
import json
import lzma
import os
import re
import stat
import sys
import tarfile
import zipfile
import zlib
from contextlib import contextmanager
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, cast

from brotli_analysis import AnalysisSession, add_analysis_arguments, scan_with_analysis
from brotli_binary_data import (
    Buffer,
    DataChangedError,
    DataLimitError,
    file_data,
    read_data,
    sha256_data,
)
from brotli_binary_match import (
    REFERENCES,
    CodeAssessment,
    CodeReference,
    file_backed_ranges,
    load_references,
    match_code,
)
from brotli_binary_metadata import decoder_metadata
from brotli_binary_signatures import recognize_decoder_data
from brotli_dependencies import MAX_DEPENDENCY_MATCHES, dependency_manifest, dependency_matches
from brotli_flirt import (
    FlirtAssessment,
    FlirtCatalog,
    FlirtSession,
    FlirtUnavailableError,
    load_flirt_bundle,
    match_flirt,
)
from brotli_payloads import (
    NotOciImageError,
    PayloadError,
    PayloadLimits,
    iter_payload_members,
    iter_rpm_members,
    oci_archive_candidate,
    open_oci_filesystems,
    payload_kind,
    rpm_payload,
)
from brotli_reporting_cli import CliEvidence, add_reporting_arguments, policy_exit
from brotli_source_leads import MAX_SOURCE_MATCHES, source_references

if TYPE_CHECKING:
    from collections.abc import Generator

REGISTRY = Path(__file__).resolve().parent.parent / "references" / "fingerprints.json"
SOURCE_SUFFIXES = {"", ".c", ".cc", ".cpp", ".cxx", ".h", ".inc", ".inl", ".unbr"}
JS_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
NATIVE_SUFFIXES = {".so", ".dylib", ".dll", ".node", ".a", ".lib", ".wasm", ".exe"}
ZIP_SUFFIXES = {".zip", ".jar", ".war", ".ear", ".whl", ".nupkg", ".apk"}
BINARY_SYMBOLS = (
    b"BrotliDecoderDecompress",
    b"BrotliDecoderCreateInstance",
    b"BrotliDecoderVersion",
    b"BrotliDecoderDestroyInstance",
    b"BrotliEncoderCompress",
    b"BrotliEncoderVersion",
    b"libbrotlidec",
    b"libbrotlicommon",
    b"libbrotlienc",
    b"org/brotli/dec/",
    b"com/aayushatharva/brotli4j/",
    b"DecoderJNI",
)
BINARY_INDICATOR_PATTERN = re.compile(
    b"|".join(re.escape(symbol) for symbol in sorted(BINARY_SYMBOLS, key=len, reverse=True))
)
INDICATOR_CHUNK_BYTES = 4 * 1024 * 1024
TEXT_PROBE_BYTES = 4096
COMPRESSED_SUFFIXES = {".gz": "gzip", ".bz2": "bzip2", ".xz": "xz"}
TAR_SUFFIXES = (".tar", ".tgz", ".txz", ".tbz", ".tbz2")
PAYLOAD_SUFFIXES = {
    ".ar": "ar",
    ".cpio": "cpio",
    ".deb": "deb",
    ".docker": "oci",
    ".oci": "oci",
    ".rpm": "rpm",
    ".tzst": "zstd",
    ".zst": "zstd",
    ".zstd": "zstd",
}
UNSUPPORTED_SUFFIXES = {
    ".7z",
    ".rar",
    ".br",
    ".lz",
    ".lz4",
    ".lzma",
    ".z",
    ".cab",
    ".iso",
    ".dmg",
    ".snap",
    ".squashfs",
    ".sqfs",
    ".appimage",
    ".asar",
}
ARCHIVE_SIGNATURES = (
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\0", "xz"),
    (b"!<arch>\n", "ar"),
    (b"!<thin>\n", "unsupported"),
    (b"\xed\xab\xee\xdb", "rpm"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"7z\xbc\xaf\x27\x1c", "unsupported"),
    (b"Rar!\x1a\x07", "unsupported"),
    (b"\x04\x22\x4d\x18", "unsupported"),
    (b"LZIP", "unsupported"),
    (b"\x1f\x9d", "unsupported"),
    (b"MSCF", "unsupported"),
    (b"xar!", "unsupported"),
    (b"070701", "cpio"),
    (b"070702", "cpio"),
    (b"070707", "cpio"),
    (b"hsqs", "unsupported"),
    (b"sqsh", "unsupported"),
)
NODE_FIXES = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
# Frozen from the Node.js release schedule on the advisory snapshot date.
NODE_EOL_BRANCHES = {0, *range(4, 22), 23, 25}
SKIPPABLE_FRAMES = tuple(bytes((first, 0x2A, 0x4D, 0x18)) for first in range(0x50, 0x60))
UNDICI = re.compile(r"(?<![\w-])undici(?![\w-])", re.IGNORECASE)
JS_NON_CODE = re.compile(
    r"(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)"
    r"""|(?P<string>'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")"""
    r"|(?P<template>\x60(?:\\.|[^\x60\\])*\x60)"
)
JS_FETCH_LEAD = re.compile(
    r"""(?P<fetch_reference>(?<![\w$'"])fetch\b)"""
    r"""|(?P<global_fetch_property>\b(?:globalThis|global)\s*\[\s*['"]fetch['"]\s*\])"""
    r"""|(?P<undici_import>\b(?:from\s+|(?:require|import)\s*(?:\(\s*)?)"""
    r"""['"]undici(?:/[^'"\\]*)?['"])"""
)
SWITCH_CALL = r"Decode(?:Literal|Command|Distance)BlockSwitch\s*\("
OLD_CALL = re.compile(r"\bBROTLI_SAFE\s*\(\s*(" + SWITCH_CALL + r")")
NEW_CALL = re.compile(r"\bBROTLI_SAFE_WITH_STATUS\s*\(\s*(" + SWITCH_CALL + r")")
BAD_GUARD = re.compile(r"if\s*\(\s*max_block_type\s*<=\s*1\s*\)\s*\{\s*return\s+BROTLI_FALSE\s*;")
COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
GOOD = {"fixed_source", "fixed_port_source", "upstream_fixed_version"}
WARNING = {
    "affected_port_source",
    "vulnerable_source",
    "potentially_vulnerable",
    "vulnerable_code_match",
    "mixed_code_matches",
}
MAX_RECORDED_GAPS = 200
MAX_DISPLAY_COPIES = 10
MAX_DISPLAY_GAPS = 5
DEFAULT_MAX_FILE_BYTES = None
DEFAULT_MAX_TOTAL_BYTES = None
DEFAULT_MAX_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_MAX_TOTAL_EXPANDED_BYTES = 64 * 1024 * 1024 * 1024
DEFAULT_MAX_TEXT_BYTES = 128 * 1024 * 1024
PYC_HEADER_BYTES = 16
DECODER_SYMBOLS = (
    b"BrotliDecoderDecompress",
    b"BrotliDecoderCreateInstance",
    b"DecoderJNI",
)


def leaf_name(label: str) -> str:
    return label.rsplit("!", 1)[-1].replace("\\", "/").rsplit("/", 1)[-1].lower()


def tar_content(data: Buffer) -> bool:
    if data[257:262] == b"ustar":
        return True
    try:
        tarfile.TarInfo.frombuf(data[: tarfile.BLOCKSIZE], "utf-8", "surrogateescape")
    except tarfile.HeaderError:
        return False
    return True


@contextmanager
def buffer_stream(data: Buffer) -> Generator[BinaryIO]:
    if isinstance(data, bytes):
        yield io.BytesIO(data)
        return
    data.seek(0)
    try:
        yield cast("BinaryIO", data)
    finally:
        data.seek(0)


def archive_kind(data: Buffer, label: str) -> str | None:
    """Recognize containers by bytes, then use names to catch damaged/opaque ones."""
    for signature, kind in ARCHIVE_SIGNATURES:
        if data.startswith(signature):
            return kind
    if data.startswith(SKIPPABLE_FRAMES):
        return "zstd"
    if tar_content(data):
        return "tar"
    with buffer_stream(data) as stream:
        try:
            if zipfile.is_zipfile(stream):
                return "zip"  # Also recognizes ZIPs with a prepended executable stub.
        except (OSError, ValueError):
            pass
    return named_archive_kind(label)


def named_archive_kind(label: str) -> str | None:
    name = leaf_name(label)
    suffix = Path(name).suffix
    if suffix in ZIP_SUFFIXES:
        return "zip"
    if suffix in COMPRESSED_SUFFIXES:
        return COMPRESSED_SUFFIXES[suffix]
    if suffix in PAYLOAD_SUFFIXES:
        return PAYLOAD_SUFFIXES[suffix]
    if name.endswith(TAR_SUFFIXES):
        return {".tgz": "gzip", ".txz": "xz", ".tbz": "bzip2", ".tbz2": "bzip2"}.get(suffix, "tar")
    return "unsupported" if suffix in UNSUPPORTED_SUFFIXES else None


def safe_text(value: str) -> str:
    """Quote untrusted display fields, escaping controls, bidi marks, and surrogates."""
    return json.dumps(value, ensure_ascii=True)


def python_bytecode(data: Buffer, name: str) -> bool:
    return (
        Path(name).suffix in {".pyc", ".pyo"}
        and len(data) >= PYC_HEADER_BYTES
        and data[2:4] == b"\r\n"
        and int.from_bytes(data[4:8], "little") in {0, 1, 3}
    )


def mask_js_non_code(match: re.Match[str]) -> str:
    token = match.group()
    # Keep templates so references in template expressions remain visible.
    # Literal template text can produce extra leads; this is not a JS parser.
    if match.lastgroup == "template":
        return token
    if match.lastgroup == "string" and (
        token[1:-1] in {"fetch", "undici"} or token[1:-1].startswith("undici/")
    ):
        return token
    return re.sub(r"[^\r\n]", " ", token)


def fetch_references(text: str) -> tuple[list[dict], bool]:
    code = JS_NON_CODE.sub(mask_js_non_code, text)
    found = list(islice(JS_FETCH_LEAD.finditer(code), MAX_SOURCE_MATCHES + 1))
    matches = []
    line = 1
    previous = 0
    for match in found[:MAX_SOURCE_MATCHES]:
        offset = match.start()
        line += text.count("\n", previous, offset)
        start = text.rfind("\n", 0, offset) + 1
        end = text.find("\n", offset)
        matches.append(
            {
                "line": line,
                "column": offset - start + 1,
                "signal": match.lastgroup,
                "text": text[start : min(end if end >= 0 else len(text), start + 300)],
            }
        )
        previous = offset
    return matches, len(found) > MAX_SOURCE_MATCHES


def finding(path: str, kind: str, patch_status: str, reason: str, **evidence: object) -> dict:
    return {
        "path": path,
        "kind": kind,
        "patch_status": patch_status,
        "reason": reason,
        "evidence": evidence,
        "build_selection": "unknown",
        "shipment": "unknown",
        "reachability": "unknown",
        "exploitability": "not_assessed",
    }


def is_binary_name_candidate(label: str) -> bool:
    name = leaf_name(label)
    return "brotli" in name and (
        Path(name).suffix in NATIVE_SUFFIXES | ZIP_SUFFIXES or ".so." in name
    )


def binary_indicators(data: Buffer) -> list[str]:
    if data.startswith(b"\x7fELF"):
        try:
            _, ranges = file_backed_ranges(data)
        except ValueError:
            ranges = []
    else:
        ranges = [(0, len(data))]
    found = set()
    overlap = max(map(len, BINARY_SYMBOLS)) - 1
    for start, size in ranges:
        tail = b""
        position = start
        stop = start + size
        while position < stop:
            chunk = data[position : min(position + INDICATOR_CHUNK_BYTES, stop)]
            candidate = tail + chunk
            found.update(match.group() for match in BINARY_INDICATOR_PATTERN.finditer(candidate))
            tail = candidate[-overlap:]
            position += len(chunk)
    return [symbol.decode("ascii") for symbol in BINARY_SYMBOLS if symbol in found]


def assess_version(component: str, value: str) -> dict:
    match = re.fullmatch(r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", value.strip())
    path = f"supplied:{component}:{value}"
    evidence = {"component": component, "supplied_version": value}
    if not match:
        return finding(
            path,
            "supplied_version",
            "unknown",
            "Not an unambiguous upstream stable version.",
            **evidence,
        )
    version = tuple(map(int, match.groups()))
    if component == "node":
        return assess_node_version(path, version, evidence)
    branch = (version[0], version[1])
    fixes = {(1, 0): 10, (1, 1): 1, (1, 2): 1}
    if branch not in fixes or version < (1, 0, 3):
        return finding(
            path,
            "supplied_version",
            "unknown",
            "Outside snapshot patch rules; inspect the actual decoder.",
            **evidence,
        )
    minimum = f"{branch[0]}.{branch[1]}.{fixes[branch]}"
    return version_finding(path, minimum, evidence, fixed=version[2] >= fixes[branch])


def assess_node_version(path: str, version: tuple[int, ...], evidence: dict) -> dict:
    if version[0] not in NODE_FIXES:
        return finding(
            path,
            "supplied_version",
            "unknown",
            "No upstream patch rule for this Node branch; "
            "inspect embedded Brotli or vendor guidance.",
            support_status="end_of_life" if version[0] in NODE_EOL_BRANCHES else "outside_snapshot",
            **evidence,
        )
    minimum = ".".join(map(str, NODE_FIXES[version[0]]))
    return version_finding(path, minimum, evidence, fixed=version >= NODE_FIXES[version[0]])


def version_finding(path: str, minimum: str, evidence: dict, *, fixed: bool) -> dict:
    return finding(
        path,
        "supplied_version",
        "upstream_fixed_version" if fixed else "potentially_vulnerable",
        "Supplied upstream version meets the branch fix; installed build unverified."
        if fixed
        else "Supplied upstream version precedes the branch fix; vendor backport status unknown.",
        fixed_branch_version=minimum,
        **evidence,
    )


def assess_binary(  # noqa: C901 -- Ordered evidence precedence is intentionally explicit.
    data: Buffer,
    references: list[CodeReference],
    flirt_catalog: FlirtCatalog | FlirtSession | None = None,
) -> dict:
    is_elf = data.startswith(b"\x7fELF")
    code = (
        match_code(data, references)
        if is_elf
        else CodeAssessment([], "Code matching requires a supported linked ELF32/ELF64 binary")
    )
    metadata = decoder_metadata(data) if is_elf else {}
    recognition = recognize_decoder_data(data)
    flirt: FlirtAssessment = {
        "status": "not_requested",
        "matches": [],
        "gaps": [],
        "limitations": [],
        "ambiguous_matches": [],
    }
    if flirt_catalog is not None:
        flirt = (
            (
                flirt_catalog.analyze(data)
                if isinstance(flirt_catalog, FlirtSession)
                else match_flirt(data, flirt_catalog)
            )
            if is_elf
            else {
                "status": "not_applicable",
                "matches": [],
                "gaps": ["FLIRT executable mapping is unsupported for this non-ELF binary."]
                if recognition["scope"] != "none"
                else [],
                "ambiguous_matches": [],
                "limitations": [
                    "FLIRT function recognition currently requires mapped ELF executable ranges."
                ],
            }
        )
    versions = metadata.get("versions", [])
    for version in versions:
        rule = assess_version("brotli", version["version"])
        version["upstream_status"] = rule["patch_status"]
        version["fixed_branch_version"] = rule["evidence"].get("fixed_branch_version")
    old_version = any(v["upstream_status"] == "potentially_vulnerable" for v in versions)
    indicators = binary_indicators(data)
    for symbol in (*metadata.get("defined_symbols", []), *metadata.get("imported_symbols", [])):
        if symbol not in indicators:
            indicators.append(symbol)
    status, reason = code.patch_status, code.reason
    kind = "decoder_code_match" if code.matches else "binary_candidate"
    linkage = "embedded_code" if code.matches else "unknown"
    if not code.matches:
        if metadata.get("defined_symbols"):
            kind, linkage = "decoder_symbol_candidate", "defined_decoder_symbols"
            reason = "Decoder API definitions found; compiled reference did not match."
        elif metadata.get("imported_symbols"):
            kind, linkage = "decoder_import_candidate", "decoder_import"
            reason = "Decoder API imports found; inspect the library providing these imports."
        elif {symbol.decode("ascii") for symbol in DECODER_SYMBOLS}.intersection(indicators):
            kind = "decoder_symbol_candidate"
            reason = "Decoder symbol/string found; implementation and patch status unresolved."
        if recognition["matches"]:
            kind = "decoder_data_signature"
            reason = (
                "Brotli decoder-specific table signatures detected; inspect code references "
                "to these tables to determine implementation and patch state."
            )
        if flirt["matches"]:
            kind = "decoder_function_signature"
            reason = (
                "Brotli function patterns matched with FLIRT; source-profile state is provenance, "
                "not this binary's patch verdict. Review the located code and its references."
            )
        if versions:
            reason += " Reported decoder version is metadata, not proof of a fix."
    if old_version and status not in {"vulnerable_code_match", "mixed_code_matches"}:
        status, kind = "potentially_vulnerable", "binary_version_candidate"
        reason = (
            "Statically read decoder version precedes the upstream fix. Update or verify a "
            "vendor backport; version evidence does not prove the code is vulnerable."
        )
    return {
        "kind": kind,
        "patch_status": status,
        "reason": reason,
        "linkage": linkage,
        "indicators": indicators,
        "decoder_metadata": metadata,
        "recognition": recognition,
        "flirt": flirt,
        "detection_status": "decoder_code_identified"
        if code.matches
        else "decoder_functions_recognized"
        if flirt["matches"]
        else recognition["status"]
        if recognition["matches"]
        else "decoder_symbols_defined"
        if metadata.get("defined_symbols")
        else "decoder_import_detected"
        if metadata.get("imported_symbols")
        else "name_or_string_only"
        if indicators
        else "not_detected",
        "code_matches": code.matches,
        "code_assessment": code.reason,
        "gaps": ([code.reason] if code.limited else [])
        + ([metadata["reason"]] if metadata.get("limited") else [])
        + ([recognition["reason"]] if recognition["limited"] else [])
        + flirt["gaps"],
    }


class Inventory:
    def __init__(  # noqa: PLR0913 -- Traversal limits plus optional code references.
        self,
        registry: dict,
        max_file_bytes: int | None,
        max_total_bytes: int | None,
        max_files: int,
        archive_depth: int,
        *,
        max_expanded_bytes: int = DEFAULT_MAX_EXPANDED_BYTES,
        max_total_expanded_bytes: int = DEFAULT_MAX_TOTAL_EXPANDED_BYTES,
        max_text_bytes: int = DEFAULT_MAX_TEXT_BYTES,
        code_references: list[CodeReference] | None = None,
        flirt_catalog: FlirtCatalog | FlirtSession | None = None,
        analysis: AnalysisSession | None = None,
    ) -> None:
        self.fingerprints = {entry["sha256"]: entry for entry in registry["fingerprints"]}
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.max_files = max_files
        self.archive_depth = archive_depth
        self.max_expanded_bytes = max_expanded_bytes
        self.max_total_expanded_bytes = max_total_expanded_bytes
        self.max_text_bytes = max_text_bytes
        self.findings: list[dict] = []
        self.gaps: list[dict] = []
        self.gap_count = 0
        self.files_seen = 0
        self.files_read = 0
        self.bytes_read = 0
        self.expanded_items_read = 0
        self.expanded_bytes_read = 0
        self.archives_attempted = 0
        self.archives_opened = 0
        self.code_references = code_references
        self.flirt_catalog = flirt_catalog
        self.analysis = analysis
        self.checked_paths: set[Path] = set()
        self.pending_symlinks: list[Path] = []
        self.covered_symlinks = 0

    def gap(self, path: str, reason: str) -> None:
        self.gap_count += 1
        if len(self.gaps) < MAX_RECORDED_GAPS:
            self.gaps.append({"path": path, "reason": reason})

    def exhausted(self) -> bool:
        return self.files_seen >= self.max_files or (
            self.max_total_bytes is not None and self.bytes_read >= self.max_total_bytes
        )

    def record_name_fallback(self, label: str, size_bytes: int | None = None) -> None:
        if is_binary_name_candidate(label):
            self.findings.append(
                finding(
                    label,
                    "artifact_name_candidate",
                    "unknown",
                    (
                        "Artifact name suggests a Brotli component; contents, linkage, and "
                        "patch status need review."
                    ),
                    size_bytes=size_bytes,
                    detection_status="name_or_string_only",
                )
            )

    def _read_limit(self, *, expanded: bool) -> int | None:
        limits = []
        if self.max_file_bytes is not None:
            limits.append(self.max_file_bytes)
        if self.max_total_bytes is not None:
            limits.append(max(0, self.max_total_bytes - self.bytes_read))
        if expanded:
            limits.extend(
                (
                    self.max_expanded_bytes,
                    max(0, self.max_total_expanded_bytes - self.expanded_bytes_read),
                )
            )
        return min(limits) if limits else None

    def _account_read(self, size: int, *, expanded: bool) -> None:
        self.bytes_read += size
        if expanded:
            self.expanded_bytes_read += size

    def _limit_gap(self, label: str, limit: int | None, *, expanded: bool) -> None:
        scope = "Expanded member/stream" if expanded else "File/member"
        rendered = "active byte limits" if limit is None else f"the active {limit}-byte limit"
        self.gap(label, f"{scope} exceeds {rendered}.")

    @contextmanager
    def _load_data(
        self,
        stream: BinaryIO,
        size: int,
        label: str,
        *,
        expanded: bool,
        record_fallback: bool = True,
    ) -> Generator[Buffer | None]:
        limit = self._read_limit(expanded=expanded)
        if size >= 0 and limit is not None and size > limit:
            if record_fallback:
                self.record_name_fallback(label, size)
            self._limit_gap(label, limit, expanded=expanded)
            yield None
            return
        entered = False
        try:
            with read_data(stream, limit) as data:
                entered = True
                self._account_read(len(data), expanded=expanded)
                if expanded:
                    self.expanded_items_read += 1
                yield data
        except DataLimitError as error:
            if entered:
                raise
            self._account_read(error.bytes_read, expanded=expanded)
            if record_fallback:
                self.record_name_fallback(label, size if size >= 0 else None)
            self._limit_gap(label, error.limit, expanded=expanded)
            yield None

    def read(
        self,
        stream: BinaryIO,
        size: int,
        label: str,
        depth: int,
        *,
        expanded: bool = False,
    ) -> None:
        self.files_seen += 1
        if self.files_seen > self.max_files:
            self.record_name_fallback(label, size)
            self.gap(label, "File/member count limit reached.")
            return
        with self._load_data(stream, size, label, expanded=expanded) as data:
            if data is not None:
                self.files_read += 1
                self.inspect(data, label, depth)

    def inspect(self, data: Buffer, label: str, depth: int) -> None:
        digest = sha256_data(data)
        if self.analysis is not None:
            self.analysis.record(data, label, digest, depth)
        if data.startswith(b"\x7fELF") and self.code_references is not None:
            self._inspect_elf(data, label, digest)
            kind = archive_kind(data, label)
            if kind is not None:
                self._inspect_container(data, label, depth, kind, digest)
            return
        if digest in self.fingerprints:
            entry = self.fingerprints[digest]
            independent = entry.get("issue_relation") == "analogous_independent_implementation"
            status = "fixed_source" if entry["state"] == "fixed" else "vulnerable_source"
            if independent:
                status = (
                    "fixed_port_source" if entry["state"] == "fixed" else "affected_port_source"
                )
            self.findings.append(
                finding(
                    label,
                    "exact_source_match",
                    status,
                    (
                        "Bytes match a reviewed port decoder's block-switch fix state; "
                        "C advisory impact is not inferred. Build and runtime remain unverified."
                        if independent
                        else "Bytes match a reviewed decoder file; surrounding tree/build "
                        "and runtime remain unverified."
                    ),
                    sha256=digest,
                    git_blob=entry["git_blob"],
                    sources=entry["sources"],
                    **{
                        key: entry[key]
                        for key in ("implementation", "component", "issue_relation", "upstream_fix")
                        if key in entry
                    },
                )
            )
            return
        kind = archive_kind(data, label)
        if kind is not None:
            first_finding = len(self.findings)
            self._inspect_container(data, label, depth, kind, digest)
            if len(self.findings) == first_finding:
                self.record_name_fallback(label, len(data))
            return
        self._inspect_noncontainer(data, label, digest)

    def _text(self, data: Buffer, label: str) -> str:
        if b"\0" in data[: min(TEXT_PROBE_BYTES, len(data))]:
            return ""
        if len(data) > self.max_text_bytes:
            self.gap(
                label,
                f"Text classification exceeds the {self.max_text_bytes}-byte text limit; "
                "binary analysis still completed.",
            )
            return ""
        raw = data if isinstance(data, bytes) else data[:]
        if b"\0" in raw:
            return ""
        return raw.decode("utf-8", errors="replace")

    def _recognize_data(self, data: Buffer, label: str) -> dict:
        recognition = recognize_decoder_data(data)
        if self.analysis is not None:
            self.analysis.enrich(
                data, label, {"detection_status": recognition["status"], "recognition": recognition}
            )
        if self.flirt_catalog is not None and recognition["scope"] == "loader_data_ranges":
            self.gap(label, "FLIRT executable mapping is unsupported for this non-ELF binary.")
        if recognition["limited"]:
            self.gap(label, recognition["reason"])
        return recognition

    def _inspect_noncontainer(self, data: Buffer, label: str, digest: str) -> None:
        recognition = self._recognize_data(data, label)
        if recognition["matches"]:
            self.findings.append(
                finding(
                    label,
                    "decoder_data_signature",
                    "unknown",
                    "Brotli decoder table signatures detected in file bytes; executable use "
                    "and patch state require code review.",
                    sha256=digest,
                    recognition=recognition,
                    detection_status=recognition["status"],
                )
            )
            return
        name = leaf_name(label)
        text = self._text(data, label)
        if self._inspect_source(text, label, digest):
            return
        first_finding = len(self.findings)
        self._inspect_fetch(text, label)
        self._inspect_language_sources(text, label)
        indicators = []
        if text and dependency_manifest(name):
            self._inspect_manifest(text, label)
        elif not python_bytecode(data, name):
            indicators = binary_indicators(data)
            self._inspect_symbols(indicators, text, label, digest)
        if is_binary_name_candidate(label) and len(self.findings) == first_finding:
            self.findings.append(
                finding(
                    label,
                    "artifact_name_candidate",
                    "unknown",
                    "Filename suggests Brotli; implementation and patch status unresolved.",
                    sha256=digest,
                    indicators=indicators,
                    detection_status="name_or_string_only",
                )
            )

    def _inspect_elf(self, data: Buffer, label: str, digest: str) -> None:
        references = self.code_references
        if references is None:
            return
        assessment = assess_binary(data, references, self.flirt_catalog)
        analysis = (
            self.analysis.enrich(data, label, assessment) if self.analysis is not None else {}
        )
        for reason in assessment["gaps"]:
            self.gap(label, reason)
        self.findings.append(
            finding(
                label,
                assessment["kind"],
                assessment["patch_status"],
                assessment["reason"],
                sha256=digest,
                code_matches=assessment["code_matches"],
                code_assessment=assessment["code_assessment"],
                indicators=assessment["indicators"],
                decoder_metadata=assessment["decoder_metadata"],
                recognition=assessment["recognition"],
                flirt=assessment["flirt"],
                detection_status=assessment["detection_status"],
                linkage=assessment["linkage"],
                analysis=analysis,
            )
        )

    def _inspect_source(self, text: str, label: str, digest: str) -> bool:
        if not text or Path(leaf_name(label)).suffix not in SOURCE_SUFFIXES:
            return False
        code = COMMENTS.sub("", text)
        if not all(
            marker in code
            for marker in (
                "DecodeBlockTypeAndLength",
                "ProcessCommandsInternal",
                "BrotliDecoderDecompressStream",
            )
        ):
            return False
        old = len(OLD_CALL.findall(code))
        new = len(NEW_CALL.findall(code))
        bad_guard = bool(BAD_GUARD.search(code))
        potential = bool(old and bad_guard)
        self.findings.append(
            finding(
                label,
                "modified_decoder_source",
                "potentially_vulnerable" if potential else "unknown",
                "Old block-switch error handling detected; review the source against the fix."
                if potential
                else "Unrecognized decoder source; fix markers alone do not validate a backport.",
                sha256=digest,
                old_switch_calls=old,
                status_switch_calls=new,
                false_on_invalid_switch=bad_guard,
                format_error_marker="BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH" in code,
            )
        )
        return True

    def _inspect_fetch(self, text: str, label: str) -> None:
        if not text or Path(leaf_name(label)).suffix not in JS_SUFFIXES:
            return
        matches, truncated = fetch_references(text)
        if matches:
            self.findings.append(
                finding(
                    label,
                    "node_fetch_candidate",
                    "unknown",
                    "Fetch/Undici source reference; execution runtime, fetch binding, "
                    "Node patch status, and attacker control of responses remain unverified.",
                    matches=matches,
                    matches_truncated=truncated,
                    detection="javascript_typescript_reference_heuristic",
                    required_checks=[
                        "Identify the fetch implementation and executing Node.js build.",
                        "Verify that runtime's security fix or vendor backport.",
                        "Trace URL inputs, redirects, and who controls response bytes.",
                    ],
                )
            )

    def _inspect_language_sources(self, text: str, label: str) -> None:
        if not text:
            return
        matches, truncated = source_references(text, Path(leaf_name(label)).suffix)
        if matches:
            self.findings.append(
                finding(
                    label,
                    "decoder_source_candidate",
                    "unknown",
                    "Language import, decoder API, or FFI reference; selected implementation, "
                    "shipped provider, patch state, and input ownership remain unresolved.",
                    matches=matches,
                    matches_truncated=truncated,
                    detection="language_scoped_source_heuristic",
                    required_checks=[
                        "Resolve the import, alias, build flags, and actual package or runtime.",
                        "Identify native bindings versus independent ports; inspect shipped code.",
                        "Check provider advisories; wrapper and C versions are distinct.",
                        "Trace active decoding calls and who controls their input bytes.",
                    ],
                )
            )

    def _inspect_manifest(self, text: str, label: str) -> None:
        matches = dependency_matches(text, leaf_name(label))
        if any(row.get("parse_incomplete") for row in matches):
            self.gap(label, "Dependency metadata parsing incomplete; selection remains unresolved.")
        if matches:
            self.findings.append(
                finding(
                    label,
                    "dependency_candidate",
                    "unknown",
                    "Declaration or metadata only; resolve the selected implementation "
                    "and embedded version.",
                    matches=matches[:MAX_DEPENDENCY_MATCHES],
                    matching_lines=len(matches),
                    matches_truncated=len(matches) > MAX_DEPENDENCY_MATCHES,
                    matching_lines_is_lower_bound=len(matches) > MAX_DEPENDENCY_MATCHES,
                    possible_node_http_client=any(UNDICI.search(row["text"]) for row in matches),
                )
            )

    def _inspect_symbols(self, indicators: list[str], text: str, label: str, digest: str) -> None:
        name = leaf_name(label)
        if text and Path(name).suffix not in NATIVE_SUFFIXES and ".so." not in name:
            return
        if {symbol.decode("ascii") for symbol in DECODER_SYMBOLS}.intersection(indicators):
            self.findings.append(
                finding(
                    label,
                    "decoder_symbol_candidate",
                    "unknown",
                    "Decoder symbol/string may identify imports, exports, or embedded code; "
                    "patch status unknown.",
                    sha256=digest,
                    detection_status="name_or_string_only",
                )
            )

    def _inspect_container(
        self, data: Buffer, label: str, depth: int, kind: str, digest: str
    ) -> None:
        previous_gaps = self.gap_count
        if kind == "unsupported":
            self.gap(label, "Unsupported archive or compression format; provide unpacked files.")
        elif depth >= self.archive_depth:
            self.gap(label, "Archive nesting limit reached; members not inspected.")
        else:
            self.inspect_archive(data, label, depth, kind)
        indicators = binary_indicators(data) if self.gap_count > previous_gaps else []
        if {symbol.decode("ascii") for symbol in DECODER_SYMBOLS}.intersection(indicators):
            self.findings.append(
                finding(
                    label,
                    "container_symbol_candidate",
                    "unknown",
                    "Decoder marker in container bytes with incomplete member coverage; "
                    "it may come from a member already reported, not an independent decoder copy.",
                    sha256=digest,
                    indicators=indicators,
                    evidence_scope="container",
                    member_coverage="incomplete",
                )
            )

    def inspect_archive(self, data: Buffer, label: str, depth: int, kind: str) -> None:
        self.archives_attempted += 1
        try:
            if kind == "zip":
                self._inspect_zip(data, label, depth)
            elif kind == "tar":
                self._inspect_tar(data, label, depth)
            elif kind in {"ar", "deb", "zstd", "rpm", "cpio", "oci"}:
                if kind == "oci":
                    if not self._inspect_oci(data, label, depth):
                        message = "tar is not a Docker save or OCI image layout"
                        raise PayloadError(message)
                else:
                    self._inspect_payload_members(data, label, depth, kind)
            else:
                self._inspect_compressed(data, label, depth, kind)
        except (
            OSError,
            EOFError,
            ValueError,
            tarfile.TarError,
            zipfile.BadZipFile,
            zlib.error,
            lzma.LZMAError,
        ) as error:
            self.gap(label, f"Cannot inspect archive: {error}")

    def _payload_limits(self) -> PayloadLimits:
        member_limits = [self.max_expanded_bytes]
        total_limits = [max(0, self.max_total_expanded_bytes - self.expanded_bytes_read)]
        if self.max_file_bytes is not None:
            member_limits.append(self.max_file_bytes)
        if self.max_total_bytes is not None:
            total_limits.append(max(0, self.max_total_bytes - self.bytes_read))
        total_bytes = min(total_limits)
        return PayloadLimits(
            max_members=max(0, self.max_files - self.files_seen),
            max_member_bytes=min(*member_limits, total_bytes),
            max_total_bytes=total_bytes,
        )

    def _inspect_payload_members(self, data: Buffer, label: str, depth: int, kind: str) -> None:
        limits = self._payload_limits()
        detected = payload_kind(data, label, limits)
        if detected is not None:
            kind = detected
        if kind == "rpm":
            payload = rpm_payload(data)
            if self.analysis is not None:
                self.analysis.register_package_archive(label, payload.metadata)
            members = iter_rpm_members(payload, limits)
        else:
            members = iter_payload_members(data, kind, limits)
        self.archives_opened += 1
        for info in members:
            member = f"{label}!{info.name}"
            if self.exhausted():
                self.gap(label, "Budget exhausted; remaining archive members not inspected.")
                break
            if info.kind != "file":
                self.record_name_fallback(member, info.size)
                self.gap(member, "Nonregular archive member not followed.")
                continue
            with info.open() as member_stream:
                self.read(
                    cast("BinaryIO", member_stream),
                    info.size,
                    member,
                    depth + 1,
                    expanded=True,
                )

    def _inspect_oci(self, data: Buffer, label: str, depth: int) -> bool:
        try:
            images_context = open_oci_filesystems(data, self._payload_limits())
            with images_context as images:
                layer_count = 0
                for image_index, image in enumerate(images):
                    layer_count += len(
                        {row["layer"] for row in image.history if isinstance(row.get("layer"), str)}
                    )
                    image_label = f"{label}!image[{image_index}]"
                    if self.analysis is not None:
                        self.analysis.register_image(
                            image_label,
                            label,
                            depth,
                            image.manifest,
                            image.history,
                        )
                    for reason in image.gaps:
                        self.gap(image_label, reason)
                    for info in image.members:
                        member = f"{image_label}!{info.name}"
                        if self.exhausted():
                            self.gap(
                                image_label,
                                "Budget exhausted; remaining image files not inspected.",
                            )
                            break
                        with info.open() as member_stream:
                            self.read(
                                cast("BinaryIO", member_stream),
                                info.size,
                                member,
                                depth + 1,
                                expanded=True,
                            )
                self.archives_opened += 1 + layer_count
        except NotOciImageError:
            return False
        else:
            return True

    def _inspect_zip(self, data: Buffer, label: str, depth: int) -> None:
        with buffer_stream(data) as stream, zipfile.ZipFile(stream) as archive:
            self.archives_opened += 1
            for info in archive.infolist():
                if info.is_dir():
                    continue
                member = f"{label}!{info.filename}"
                if self.exhausted():
                    self.gap(label, "Budget exhausted; remaining archive members not inspected.")
                    break
                if stat.S_ISLNK(info.external_attr >> 16):
                    self.record_name_fallback(member, info.file_size)
                    self.gap(member, "Archive symlink not followed.")
                    continue
                try:
                    with archive.open(info) as member_stream:
                        self.read(
                            cast("BinaryIO", member_stream),
                            info.file_size,
                            member,
                            depth + 1,
                            expanded=True,
                        )
                except (
                    OSError,
                    RuntimeError,
                    ValueError,
                    zipfile.BadZipFile,
                    NotImplementedError,
                    zlib.error,
                    lzma.LZMAError,
                ) as error:
                    self.record_name_fallback(member, info.file_size)
                    self.gap(member, f"Cannot inspect archive member: {error}")

    def _inspect_compressed(self, data: Buffer, label: str, depth: int, kind: str) -> None:
        open_compressed = {"gzip": gzip.open, "bzip2": bz2.open, "xz": lzma.open}[kind]
        with (
            buffer_stream(data) as source,
            open_compressed(source, "rb") as expanded_stream,
            self._load_data(
                cast("BinaryIO", expanded_stream),
                -1,
                label,
                expanded=True,
                record_fallback=False,
            ) as expanded,
        ):
            if expanded is None:
                return
            self.archives_opened += 1
            name = leaf_name(label)
            if tar_content(expanded) or name.endswith(
                (
                    ".tar.gz",
                    ".tar.bz2",
                    ".tar.xz",
                    ".tgz",
                    ".txz",
                    ".tbz",
                    ".tbz2",
                )
            ):
                self._inspect_tar(expanded, label, depth, count_open=False)
                return
            member = f"{label}!{Path(name).stem or 'decompressed'}"
            self.files_seen += 1
            if self.files_seen > self.max_files:
                self.record_name_fallback(member, len(expanded))
                self.gap(member, "File/member count limit reached.")
                return
            self.files_read += 1
            self.inspect(expanded, member, depth + 1)

    def _inspect_tar(
        self, data: Buffer, label: str, depth: int, *, count_open: bool = True
    ) -> None:
        if count_open and self._inspect_oci_tar(data, label, depth):
            return
        with buffer_stream(data) as stream, tarfile.open(fileobj=stream, mode="r|") as archive:
            if count_open:
                self.archives_opened += 1
            for info in archive:
                if info.isdir():
                    continue
                member = f"{label}!{info.name}"
                if self.exhausted():
                    self.gap(label, "Budget exhausted; remaining archive members not inspected.")
                    break
                if not info.isfile():
                    self.record_name_fallback(member, info.size)
                    self.gap(member, "Nonregular archive member not followed.")
                    continue
                member_stream = archive.extractfile(info)
                if member_stream is not None:
                    with member_stream:
                        self.read(
                            cast("BinaryIO", member_stream),
                            info.size,
                            member,
                            depth + 1,
                            expanded=True,
                        )

    def _inspect_oci_tar(self, data: Buffer, label: str, depth: int) -> bool:
        if not oci_archive_candidate(data, self._payload_limits()):
            return False
        if not self._inspect_oci(data, label, depth):
            message = "OCI marker probe and parser classification disagree"
            raise PayloadError(message)
        return True

    def scan_file(self, path: Path) -> None:  # noqa: C901 -- Stable-fd lifecycle is one operation.
        label = str(path)
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                self._record_symlink(path)
                return
            if not stat.S_ISREG(metadata.st_mode):
                self.record_name_fallback(label)
                self.gap(label, "Nonregular file not read.")
                return
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            )
            with os.fdopen(descriptor, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    self.record_name_fallback(label)
                    self.gap(label, "Nonregular file not read.")
                    return
                analysis_checkpoint = (
                    self.analysis.checkpoint() if self.analysis is not None else None
                )
                checkpoint = (
                    len(self.findings),
                    len(self.gaps),
                    self.gap_count,
                    self.files_seen,
                    self.files_read,
                    self.bytes_read,
                    self.expanded_items_read,
                    self.expanded_bytes_read,
                    self.archives_attempted,
                    self.archives_opened,
                )
                self.files_seen += 1
                if self.files_seen > self.max_files:
                    self.record_name_fallback(label, metadata.st_size)
                    self.gap(label, "File/member count limit reached.")
                    return
                limit = self._read_limit(expanded=False)
                if limit is not None and metadata.st_size > limit:
                    self.record_name_fallback(label, metadata.st_size)
                    self._limit_gap(label, limit, expanded=False)
                    return
                try:
                    with file_data(stream, limit) as data:
                        self._account_read(len(data), expanded=False)
                        self.files_read += 1
                        self.inspect(data, label, 0)
                except (DataChangedError, DataLimitError) as error:
                    (
                        findings,
                        gaps,
                        self.gap_count,
                        seen,
                        self.files_read,
                        self.bytes_read,
                        self.expanded_items_read,
                        self.expanded_bytes_read,
                        self.archives_attempted,
                        self.archives_opened,
                    ) = checkpoint
                    if self.analysis is not None and analysis_checkpoint is not None:
                        self.analysis.rollback(analysis_checkpoint)
                    del self.findings[findings:]
                    del self.gaps[gaps:]
                    self.files_seen = seen + 1
                    self.record_name_fallback(label, metadata.st_size)
                    if isinstance(error, DataLimitError):
                        self._limit_gap(label, error.limit, expanded=False)
                    else:
                        self.gap(label, str(error))
                    return
                self.checked_paths.add(path.resolve())
        except OSError as error:
            self.record_name_fallback(label)
            self.gap(label, f"Cannot read file: {error}")

    def scan_root(self, root: Path) -> None:
        self.scan_roots([root])

    def scan_roots(self, roots: list[Path]) -> None:
        try:
            for root in roots:
                if self.exhausted():
                    self.gap(str(root), "Budget exhausted; root not inspected.")
                else:
                    self._scan_root(root)
        finally:
            self._check_symlinks()

    def _record_symlink(self, path: Path) -> None:
        self.files_seen += 1
        if self.files_seen > self.max_files:
            self.gap(str(path), "File count limit reached; symlink target not checked.")
        else:
            self.pending_symlinks.append(path)

    def _check_symlinks(self) -> None:
        for path in self.pending_symlinks:
            try:
                target = path.resolve(strict=True)
            except (OSError, RuntimeError):
                target = None
            if target in self.checked_paths:
                self.covered_symlinks += 1
            else:
                self.gap(
                    str(path),
                    "Symlink target was not checked directly; scan the real target separately.",
                )
        self.pending_symlinks.clear()

    def _scan_root(self, root: Path) -> None:
        if root.is_symlink() or not root.is_dir():
            self.scan_file(root)
            return

        def walk_error(error: OSError) -> None:
            self.gap(str(error.filename), f"Cannot walk directory: {error}")

        for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            if self.exhausted():
                self.gap(
                    str(root),
                    "Budget exhausted; remaining filesystem paths not inspected.",
                )
                break
            self.checked_paths.add(Path(directory).resolve())
            dirs[:] = self._filter_directories(Path(directory), dirs)
            for name in sorted(files):
                if name == ".git":
                    continue
                if self.exhausted():
                    self.gap(
                        str(root),
                        "Budget exhausted; remaining filesystem paths not inspected.",
                    )
                    return
                self.scan_file(Path(directory) / name)

    def _filter_directories(self, directory: Path, names: list[str]) -> list[str]:
        kept = []
        for name in sorted(names):
            path = directory / name
            if name == ".git":
                continue
            if path.is_symlink():
                self._record_symlink(path)
            else:
                kept.append(name)
        return kept


def positive(value: str) -> int:
    number = int(value)
    if number <= 0:
        message = "must be positive"
        raise argparse.ArgumentTypeError(message)
    return number


def explain_possible(item: dict) -> dict:
    evidence = item["evidence"]
    if item["kind"] == "binary_version_candidate":
        versions = evidence["decoder_metadata"]["versions"]
        affected = [v for v in versions if v["upstream_status"] == "potentially_vulnerable"]
        labels = ", ".join(sorted({v["version"] for v in affected}))
        fixes = ", ".join(sorted({v["fixed_branch_version"] for v in affected}))
        return {
            "result": f"Embedded decoder reports Brotli {labels}; update review needed",
            "next_action": (
                f"Update to the corresponding fixed branch release ({fixes}) or verify a "
                "vendor backport for this exact build. The version was read statically, "
                "not by running the binary; it does not prove vulnerable behavior."
            ),
        }
    if item["kind"] == "supplied_version":
        component = "Node.js" if evidence["component"] == "node" else "Brotli"
        minimum = evidence["fixed_branch_version"]
        return {
            "result": f"The supplied {component} version may need an update",
            "next_action": (
                f"Ask the maintainer to update {component} to {minimum} or a later "
                "fixed release on that branch, or confirm a vendor-supplied fix. "
                "Check the version actually used by the running app."
            ),
        }
    return {
        "result": "Possible vulnerable Brotli source",
        "next_action": (
            "Ask the maintainer to check the changes in this copy against the "
            "Brotli fix and update it if needed. Confirm whether the running app "
            "uses this copy."
        ),
    }


def explain_source_warning(item: dict) -> dict:
    if item["evidence"].get("issue_relation") == "analogous_independent_implementation":
        return {
            "result": "Analogous decoder error-handling bug found in port source",
            "next_action": (
                "Check this implementation's linked upstream fix and update selected affected "
                "copies. This exact source match does not establish the C advisory's memory "
                "corruption impact or runtime exploitability."
            ),
        }
    return {
        "result": "Vulnerable Brotli source found",
        "next_action": (
            "Have the app's maintainer check whether this copy is used. If it "
            "is, update its Brotli dependency, rebuild and deploy the app, and "
            "confirm the running app has the fix."
        ),
    }


def explain_finding(item: dict) -> dict:  # noqa: PLR0911 -- Explicit per-evidence guidance.
    status = item["patch_status"]
    if status in {"vulnerable_code_match", "mixed_code_matches", "fixed_code_match"}:
        return {
            "result": "Affected decoder code matched in this binary"
            if status != "fixed_code_match"
            else "Fixed decoder code matched in this binary",
            "next_action": (
                "Review the matched build evidence and rebuild affected embedded copies. "
                "Confirm runtime use and check other copies; a fixed match does not clear "
                "the whole binary."
            ),
        }
    if status in {"vulnerable_source", "affected_port_source"}:
        return explain_source_warning(item)
    if status == "potentially_vulnerable":
        return explain_possible(item)
    if status in {"fixed_source", "fixed_port_source"}:
        return {
            "result": "Fix identified in this source file",
            "next_action": (
                "Confirm that the running app uses this fixed copy. Other copies "
                "listed here need their own checks."
            ),
        }
    if status == "upstream_fixed_version":
        return {
            "result": "Supplied version meets a known fix",
            "next_action": (
                "Confirm that this version belongs to the running app, and check any "
                "additional Brotli copies bundled inside it."
            ),
        }
    if item["kind"] == "decoder_import_candidate":
        return {
            "result": "Brotli decoder imported from another library",
            "next_action": (
                "Scan the actual library providing this decoder in the deployment; "
                "an import does not identify its patch state."
            ),
        }
    if item["evidence"].get("decoder_metadata", {}).get("defined_symbols"):
        return {
            "result": "Brotli decoder definitions found; patch state unresolved",
            "next_action": (
                "Verify a vendor fix for this exact build or provide matching code references. "
                "A reported fixed version alone does not clear embedded copies."
            ),
        }
    return (
        end_of_life_advice()
        if item["evidence"].get("support_status") == "end_of_life"
        else explain_lead(item)
    )


def end_of_life_advice() -> dict:
    return {
        "result": "This Node.js release is end of life",
        "next_action": (
            "Upgrade to a supported Node.js branch: 22.23.4, 24.22.1, or 26.12.1 "
            "or a later fixed release on that branch. Confirm the running app uses "
            "the new build. This version alone does not identify its embedded Brotli."
        ),
    }


def fetch_related(item: dict) -> bool:
    return item["kind"] == "node_fetch_candidate" or item["evidence"].get(
        "possible_node_http_client", False
    )


def fetch_advice() -> dict:
    return {
        "result": "Possible Node.js fetch response-decoding path",
        "next_action": (
            "Confirm whether this uses Node's built-in fetch or Undici, a browser, or a "
            "custom implementation. Identify the running app's Node.js build and check it "
            "with --node-version and vendor patch records. Trace URL inputs and redirects "
            "to establish who can supply response bytes. Node's built-in fetch and Undici's "
            "fetch can decode Brotli responses through node:zlib without a Brotli package "
            "declaration. "
            "Update the actual Node.js runtime if affected; adding a Brotli npm package "
            "does not patch that runtime. Review any other dependencies listed in this file."
        ),
    }


def explain_lead(item: dict) -> dict:
    if fetch_related(item):
        return fetch_advice()
    if item["kind"] == "supplied_version":
        return {
            "result": "Supplied version needs verification",
            "next_action": (
                f"{item['reason']} Obtain the running app's exact component build and vendor "
                "security-patch records. A vendor suffix or prerelease cannot be assessed "
                "as an upstream stable release."
            ),
        }
    advice = {
        "decoder_function_signature": (
            "Brotli functions recognized with FLIRT; patch review required",
            (
                "Inspect the matched executable windows, candidate names, and build provenance. "
                "Resolve caller/callee relationships and review patch-bearing error handling; "
                "a signature from a fixed source build does not clear this binary."
            ),
        ),
        "decoder_data_signature": (
            "Brotli decoder tables detected; patch state not established",
            (
                "Use the recorded table offsets to locate code references and review the decoder. "
                "These tables occur in both affected and fixed versions; "
                "they do not prove that the tables are used at runtime."
            ),
        ),
        "decoder_source_candidate": (
            "Possible decoder integration in source",
            (
                "Follow the recorded import, decoder API, or FFI reference to the selected "
                "package/runtime and shipped provider. Distinguish native bindings from "
                "independent ports; wrapper versions are not C decoder versions. Check the "
                "implementation's advisory and trace who controls the decoded input."
            ),
        ),
        "binary_candidate": (
            "Unclassified native binary",
            (
                "No supported decoder code matched. Use build records or scoped disassembly "
                "if this binary may embed Brotli; this is not evidence of absence."
            ),
        ),
        "dependency_candidate": (
            "Dependency or metadata mention",
            (
                "Check the matching declaration to see whether it selects a Brotli decoder. "
                "Descriptions and package names alone do not establish an installed decoder. "
                "If selected, identify its implementation and the build used by the running app."
            ),
        ),
        "decoder_symbol_candidate": (
            "Possible decoder in a binary",
            (
                "Have the maintainer identify the library that provides this decoder symbol "
                "and its patch status, using build records or binary analysis. Confirm whether "
                "the running app loads or embeds it."
            ),
        ),
        "container_symbol_candidate": (
            "Decoder marker in an incompletely checked container",
            (
                "Resolve this container's scan gaps or inspect its unpacked contents. "
                "The marker may belong to members already listed; do not count the container "
                "as another decoder copy. Identify the decoder and patch status in its members."
            ),
        ),
        "artifact_name_candidate": (
            "Possible Brotli component by filename",
            (
                "Check this package or library's contents and build records to identify its "
                "decoder and patch status. The filename alone does not establish its version."
            ),
        ),
        "modified_decoder_source": (
            "Modified decoder source needs review",
            (
                "Compare this source and its surrounding headers against the upstream fix. "
                "Fix markers alone do not validate a backport. Confirm whether the app builds it."
            ),
        ),
    }
    result, action = advice.get(
        item["kind"],
        (
            "More information needed",
            (
                "Ask the maintainer to identify the decoder used by this component "
                "and its patch status."
            ),
        ),
    )
    return {
        "result": result,
        "next_action": action,
    }


def end_of_life_summary() -> dict:
    return {
        "status": "needs_attention",
        "title": "The supplied Node.js release is end of life",
        "meaning": (
            "This Node.js branch no longer receives upstream security fixes. Its version "
            "alone does not establish the patch status of the embedded Brotli decoder."
        ),
        "next_steps": [
            (
                "Upgrade to Node.js 22.23.4, 24.22.1, or 26.12.1 or a later fixed release "
                "on that branch, and confirm the running app uses it."
            ),
            "Resolve any unchecked files and review any other Brotli copies listed below.",
        ],
    }


def attention_summary(statuses: set[str]) -> dict:
    if statuses & {"vulnerable_code_match", "mixed_code_matches"}:
        return {
            "status": "needs_attention",
            "title": "Affected Brotli decoder code matched in a binary",
            "meaning": (
                "Executable code matches an affected decoder reference. This is code "
                "identity evidence, not proof of runtime use or exploitability."
            ),
            "next_steps": [
                (
                    "Review the reference build evidence, update affected copies, "
                    "rebuild and redeploy."
                ),
                "Check all other copies, source findings, and scan gaps separately.",
            ],
        }
    if "vulnerable_source" in statuses:
        return {
            "status": "needs_attention",
            "title": "Vulnerable Brotli source found",
            "meaning": (
                "Affected Brotli code is present. We still need to check whether "
                "your running app uses it to process data supplied by other people."
            ),
            "next_steps": [
                (
                    "Ask the app's maintainer to check the flagged copies below and "
                    "update any that the app uses."
                ),
                (
                    "If the copy is included inside the app, rebuild and deploy the app "
                    "after updating it. Updating the computer's Brotli package alone may "
                    "leave the copy inside the app unchanged."
                ),
                (
                    "Confirm the updated copy is in the running app. The fixed copies "
                    "listed here do not clear other copies."
                ),
            ],
        }
    if "affected_port_source" in statuses:
        return {
            "status": "needs_attention",
            "title": "Analogous error-handling bug found in an independent decoder",
            "meaning": (
                "Source bytes match a reviewed Go or Rust decoder before its own block-switch "
                "fix. This does not establish the C advisory's corruption impact or runtime use."
            ),
            "next_steps": [
                "Follow the implementation-specific upstream fix recorded for each matched file.",
                "Update selected affected copies and verify the deployed artifact and input path.",
                "Review other copies and coverage gaps independently.",
            ],
        }
    if "potentially_vulnerable" in statuses:
        return {
            "status": "needs_attention",
            "title": "A Brotli update may be needed",
            "meaning": (
                "Some checked code or decoder versions may be affected. A "
                "maintainer needs to confirm which copy the app uses and whether its "
                "vendor has already fixed it."
            ),
            "next_steps": [
                "Follow the update or verification step for each flagged item below.",
                "Confirm the running app uses the fixed copy after the update.",
            ],
        }
    return {}


def fetch_summary() -> dict:
    return {
        "status": "needs_more_information",
        "title": "Check the runtime used for fetch responses",
        "meaning": (
            "Fetch or Undici references were found. If they run through Node.js, Brotli "
            "responses can reach the runtime's native decoder. These references alone "
            "do not identify the runtime, its patch status, or who controls responses."
        ),
        "next_steps": [
            (
                "Identify the actual fetch implementation and running Node.js build. "
                "Supply that build's version with --node-version and check vendor patch records."
            ),
            "Trace URL inputs and redirects to determine who can supply response bytes.",
            (
                "If affected, update and redeploy the Node.js runtime, then confirm the "
                "app uses it. A fixed standalone Brotli package does not clear this path."
            ),
        ],
    }


def fixed_summary(statuses: set[str]) -> dict:
    if statuses == {"fixed_port_source"}:
        return {
            "status": "checked_port_sources_include_fix",
            "title": "Independent-port fix identified in the checked source files",
            "meaning": (
                "These source files match reviewed Go/Rust fixes for analogous error handling. "
                "This is not a C advisory verdict or proof about deployed binaries or other copies."
            ),
            "next_steps": [
                "Confirm the deployed application builds these sources and their required context.",
                "Review other decoder copies and actual input reachability separately.",
            ],
        }
    return {
        "status": "checked_items_include_fix",
        "title": "Fix identified in the checked items",
        "meaning": (
            "The checked source files or supplied versions match a known fix. "
            "This does not yet confirm what your running app uses or cover "
            "copies outside this check."
        ),
        "next_steps": [
            "Confirm the running app uses these fixed copies or versions.",
            "Check any additional copies bundled inside the app or its packages.",
        ],
    }


def summarize(report: dict) -> dict:
    findings = report["findings"]
    statuses = {item["patch_status"] for item in findings}
    attention = attention_summary(statuses)
    if attention:
        return attention
    if any(item["evidence"].get("support_status") == "end_of_life" for item in findings):
        return end_of_life_summary()
    if report["coverage"]["gap_count"]:
        return {
            "status": "needs_more_information",
            "title": "Some files could not be checked",
            "meaning": (
                "This check is incomplete. Any fixes identified in other files do "
                "not tell us what is inside the skipped files."
            ),
            "next_steps": [
                (
                    "For byte, file-count, or depth limits, rerun a smaller relevant folder "
                    "or raise the named limit shown in --help."
                ),
                "For unsupported packages, provide unpacked files and scan them again.",
                "For symlinks, scan the real target separately if it was not checked directly.",
                "Ask the app's maintainer for any files or build records you cannot obtain.",
            ],
        }
    if findings and statuses <= GOOD:
        return fixed_summary(statuses)
    return unresolved_summary(findings)


def unresolved_summary(findings: list[dict]) -> dict:
    if any(item["kind"] == "decoder_function_signature" for item in findings):
        return {
            "status": "decoder_recognized_patch_unresolved",
            "title": "Brotli functions recognized; patch review required",
            "meaning": (
                "FLIRT identifies code windows matching trusted decoder functions. "
                "Function recognition does not establish patch state, call targets, or runtime use."
            ),
            "next_steps": [
                "Use the recorded function offsets to collect bounded disassembly.",
                "Review the patch-bearing functions and actual control flow together.",
                "Resolve the shipped provider and input ownership independently.",
            ],
        }
    if any(item["kind"] == "decoder_data_signature" for item in findings):
        return {
            "status": "decoder_detected_patch_unresolved",
            "title": "Brotli decoder tables detected; patch review required",
            "meaning": (
                "The binary contains decoder-specific data signatures, not just a name. "
                "Those tables are shared by affected and fixed builds and may be unused data."
            ),
            "next_steps": [
                "Use table offsets and ELF addresses to locate references in trusted static tools.",
                "Review the decoding and error-propagation code or obtain exact build provenance.",
                "Keep runtime use, other decoder copies, and patch status separate.",
            ],
        }
    if any(fetch_related(item) for item in findings):
        return fetch_summary()
    return {
        "status": "needs_more_information",
        "title": "More information needed",
        "meaning": "This check could not confirm whether the app's Brotli decoder includes the fix."
        if findings
        else (
            "No matching Brotli decoder was identified in the files checked. It "
            "may be inside a built application or outside the folders checked."
        ),
        "next_steps": [
            (
                "Ask the app's maintainer or hosting provider to identify the Brotli "
                "copies used by the running app and confirm whether they include the "
                "fix. Share the findings below if available."
            )
        ],
    }


def display_copies(findings: list[dict]) -> list[dict]:
    # Merge evidence about the same file for display; full evidence stays in JSON.
    priorities = {
        "vulnerable_code_match": 0,
        "mixed_code_matches": 0,
        "fixed_code_match": 2,
        "vulnerable_source": 0,
        "affected_port_source": 0,
        "potentially_vulnerable": 1,
        "unknown": 2,
        "fixed_source": 3,
        "fixed_port_source": 3,
        "upstream_fixed_version": 3,
    }
    copies = {}
    for item in findings:
        previous = copies.get(item["path"])
        if (
            previous is None
            or priorities[item["patch_status"]] < priorities[previous["patch_status"]]
        ):
            copies[item["path"]] = item
    return sorted(copies.values(), key=lambda item: priorities[item["patch_status"]])


def display_location(item: dict) -> str:
    if item["kind"] == "supplied_version" and "supplied_version" in item["evidence"]:
        evidence = item["evidence"]
        component = "Node.js" if evidence["component"] == "node" else "Brotli"
        return safe_text(f"{component} {evidence['supplied_version']} (version supplied)")
    return safe_text(item["path"])


def render_copies(findings: list[dict], *, containers: bool = False) -> list[str]:
    ordered = display_copies(
        [item for item in findings if (item["kind"] == "container_symbol_candidate") == containers]
    )
    if not ordered:
        return []
    lines = ["", "Containers needing inspection:" if containers else "Files and versions checked:"]
    for item in ordered[:MAX_DISPLAY_COPIES]:
        explanation = explain_finding(item)
        lines.extend(
            [
                f"- {explanation['result']}: {display_location(item)}",
                f"  Next: {explanation['next_action']}",
            ]
        )
    if len(ordered) > MAX_DISPLAY_COPIES:
        lines.append(
            f"- {len(ordered) - MAX_DISPLAY_COPIES} more items are included "
            "in the full report (--json)."
        )
    return lines


def render_gaps(coverage: dict) -> list[str]:
    gaps = coverage["gaps"]
    if not gaps:
        return []
    lines = ["", "Could not check:"]
    lines.extend(
        f"- {safe_text(gap['path'])}: {safe_text(gap['reason'])}" for gap in gaps[:MAX_DISPLAY_GAPS]
    )
    remaining = len(gaps) - min(MAX_DISPLAY_GAPS, len(gaps))
    if remaining:
        lines.append(f"- {remaining} more recorded gap details are available with --json.")
    omitted = coverage["gap_count"] - len(gaps)
    if omitted:
        lines.append(
            f"- {omitted} additional gaps have no retained details "
            f"({MAX_RECORDED_GAPS}-record limit). Rerun a smaller scope to inspect them."
        )
    return lines


def render_text(report: dict) -> str:
    summary = report["user_summary"]
    lines = [
        f"Brotli check: {summary['title']}",
        "",
        summary["meaning"],
        "",
        "What to do next:",
    ]
    lines.extend(f"- {step}" for step in summary["next_steps"])
    lines.extend(render_copies(report["findings"]))
    lines.extend(render_copies(report["findings"], containers=True))
    lines.extend(render_gaps(report["coverage"]))
    lines.extend(
        [
            "",
            (
                f"Checked {report['coverage']['files_read']} files and archive entries. "
                f"{report['cve']}; advisory data: {report['snapshot_date']}."
            ),
            "Full technical evidence for a maintainer: run with --json.",
        ]
    )
    return "\n".join(lines)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check local files for Brotli copies that may need a security update.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "roots",
        nargs="*",
        type=Path,
        help="project folders or app packages to check; defaults to the current folder",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="show full technical evidence for maintainers and automation",
    )
    parser.add_argument(
        "--brotli-version",
        action="append",
        default=[],
        help="upstream Brotli version obtained separately; repeat for multiple copies",
    )
    parser.add_argument(
        "--node-version",
        action="append",
        default=[],
        help="upstream Node.js version obtained separately; repeat for multiple copies",
    )
    parser.add_argument(
        "--code-references",
        type=Path,
        default=REFERENCES,
        help="compiled ELF decoder references; unmatched code remains unidentified",
    )
    flirt_options = parser.add_mutually_exclusive_group()
    flirt_options.add_argument(
        "--flirt", action="store_true", default=True, help="enable automatic FLIRT (default)"
    )
    flirt_options.add_argument(
        "--no-flirt",
        dest="flirt",
        action="store_false",
        help="explicitly disable FLIRT for a faster scan",
    )
    parser.add_argument(
        "--flirt-references",
        type=Path,
        help="trusted FLIRT bundle manifest (implies --flirt; otherwise use the packaged bundle)",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=positive,
        default=DEFAULT_MAX_FILE_BYTES,
        help="optional maximum bytes read from one file/member (default: no cap)",
    )
    parser.add_argument(
        "--max-total-bytes",
        type=positive,
        default=DEFAULT_MAX_TOTAL_BYTES,
        help="optional maximum cumulative bytes read (default: no cap)",
    )
    parser.add_argument(
        "--max-expanded-bytes",
        type=positive,
        default=DEFAULT_MAX_EXPANDED_BYTES,
        help="maximum expanded bytes read from one archive member/stream",
    )
    parser.add_argument(
        "--max-total-expanded-bytes",
        type=positive,
        default=DEFAULT_MAX_TOTAL_EXPANDED_BYTES,
        help="maximum cumulative expanded archive/member bytes",
    )
    parser.add_argument(
        "--max-text-bytes",
        type=positive,
        default=DEFAULT_MAX_TEXT_BYTES,
        help="maximum bytes decoded for source/manifest text classification",
    )
    parser.add_argument(
        "--max-files",
        type=positive,
        default=50000,
        help="maximum filesystem files, symlinks, and archive members checked",
    )
    parser.add_argument(
        "--archive-depth",
        type=int,
        choices=range(6),
        default=2,
        help="maximum nested containers opened; 0 disables archive traversal",
    )
    add_analysis_arguments(parser)
    add_reporting_arguments(parser)
    args = parser.parse_args(argv)
    if not args.flirt and args.flirt_references is not None:
        parser.error("--no-flirt cannot be combined with --flirt-references")
    return args


def load_optional_flirt(path: Path | None) -> tuple[FlirtCatalog | None, str | None]:
    if path is None:
        return None, None
    try:
        return load_flirt_bundle(path), None
    except FlirtUnavailableError as error:
        return None, str(error)


def configure_flirt(
    references: Path | None, *, enabled: bool
) -> tuple[FlirtCatalog | FlirtSession | None, str | None]:
    if not enabled:
        return None, None
    if references is not None:
        return load_optional_flirt(references)
    return FlirtSession(), None


def flirt_configuration(value: FlirtCatalog | FlirtSession | None) -> dict:
    if isinstance(value, FlirtSession):
        return value.describe()
    return {"status": "enabled" if value is not None else "explicitly_disabled"}


def scan_result(statuses: set[str], gap_count: int) -> tuple[str, int]:
    if statuses & (WARNING - {"affected_port_source"}):
        result, code = "affected_evidence_found", 1
    elif "affected_port_source" in statuses:
        result, code = "affected_port_evidence_found", 1
    elif gap_count or not statuses or statuses - GOOD:
        result, code = "review_required", 3
    elif statuses == {"fixed_port_source"}:
        result, code = "reported_port_sources_include_fix", 0
    else:
        result, code = "reported_items_meet_fix_rules", 0
    return result, code


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    roots = args.roots or (
        []
        if args.brotli_version or args.node_version or args.deployment_root or args.sbom
        else [Path.cwd()]
    )
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    try:
        evidence = CliEvidence(args, REGISTRY)
        code_references = load_references(args.code_references)
        flirt_catalog, flirt_error = configure_flirt(args.flirt_references, enabled=args.flirt)
    except (OSError, ValueError) as error:
        print(f"Invalid binary references: {error}", file=sys.stderr)
        return 2
    inventory = Inventory(
        registry,
        args.max_file_bytes,
        args.max_total_bytes,
        args.max_files,
        args.archive_depth,
        max_expanded_bytes=args.max_expanded_bytes,
        max_total_expanded_bytes=args.max_total_expanded_bytes,
        max_text_bytes=args.max_text_bytes,
        code_references=code_references,
        flirt_catalog=flirt_catalog,
    )
    if flirt_error is not None:
        inventory.gap("<FLIRT>", flirt_error)
    roots = [root.expanduser().absolute() for root in [*roots, *args.deployment_root, *args.sbom]]
    try:
        analysis_report = scan_with_analysis(inventory, roots, args)
        identities = evidence.check_inputs(inventory)
    except (OSError, ValueError) as error:
        print(f"Invalid analysis input: {error}", file=sys.stderr)
        return 2
    for component, versions in (
        ("brotli", args.brotli_version),
        ("node", args.node_version),
    ):
        inventory.findings.extend(assess_version(component, value) for value in versions)
    result, code = scan_result(
        {item["patch_status"] for item in inventory.findings}, inventory.gap_count
    )
    report = make_report(inventory, roots, args, registry, result)
    report.update(analysis_report)
    report["user_summary"] = summarize(report)
    try:
        finalized = evidence.finalize(report, identities)
    except (OSError, ValueError) as error:
        print(f"Invalid report input: {error}", file=sys.stderr)
        return 2
    if args.sarif or args.json:
        print(
            json.dumps(
                finalized.sarif if args.sarif else finalized.report, indent=2, ensure_ascii=True
            )
        )
    else:
        print(render_text(finalized.report))
    return policy_exit(code, finalized, args.fail_on)


def make_report(
    inventory: Inventory,
    roots: list[Path],
    args: argparse.Namespace,
    registry: dict,
    result: str,
) -> dict:
    port_only = bool(inventory.findings) and all(
        item["evidence"].get("issue_relation") == "analogous_independent_implementation"
        for item in inventory.findings
    )
    return {
        "schema_version": 1,
        "cve": None if port_only else "CVE-2026-111497",
        "result": result,
        "snapshot_date": registry.get(
            "related_implementations_verified_on", registry["verified_on"]
        )
        if port_only
        else registry["verified_on"],
        "related_implementation_snapshot_date": registry.get("related_implementations_verified_on"),
        "advisory_freshness": "not_checked_offline",
        "scope": [str(root.expanduser().absolute()) for root in roots],
        "flirt_requested": args.flirt,
        "flirt_configuration": flirt_configuration(inventory.flirt_catalog),
        "findings": inventory.findings,
        "coverage": {
            "files_seen": inventory.files_seen,
            "files_read": inventory.files_read,
            "bytes_read": inventory.bytes_read,
            "expanded_items_read": inventory.expanded_items_read,
            "expanded_bytes_read": inventory.expanded_bytes_read,
            "archives_attempted": inventory.archives_attempted,
            "archives_opened": inventory.archives_opened,
            "gap_count": inventory.gap_count,
            "gap_details_retained": len(inventory.gaps),
            "gap_details_omitted": inventory.gap_count - len(inventory.gaps),
            "gaps": inventory.gaps,
            "excluded": [".git"],
            "symlinks_followed": False,
            "symlink_targets_checked_directly": inventory.covered_symlinks,
            "limits": {
                key: getattr(args, key)
                for key in (
                    "max_file_bytes",
                    "max_total_bytes",
                    "max_expanded_bytes",
                    "max_total_expanded_bytes",
                    "max_text_bytes",
                    "max_files",
                    "archive_depth",
                )
            },
            "limitations": [
                "No absence-of-Brotli guarantee.",
                (
                    "Compiled code matches exclude relocation targets/data "
                    "and do not clear other copies."
                ),
                "Unrecognized or signature-free container/compression formats can be missed.",
                (
                    "OCI final filesystems use whiteout semantics; "
                    "raw layer archives remain standalone scope."
                ),
                (
                    "Static/stripped binaries, encrypted archives, remote build inputs, "
                    "and unprovided artifacts require review."
                ),
                (
                    "Build selection, shipment, runtime identity, reachability, and "
                    "exploitability are not established."
                ),
            ],
        },
    }


# gremlin: pardon[out_of_scope] CLI bootstrap guard; imports must not launch argparse.
if __name__ == "__main__":
    sys.exit(main())
