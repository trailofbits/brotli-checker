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
import hashlib
import io
import json
import lzma
import os
import re
import stat
import sys
import tarfile
import tomllib
import zipfile
import zlib
from itertools import islice
from pathlib import Path
from typing import Protocol

from brotli_binary_match import (
    REFERENCES,
    CodeAssessment,
    CodeReference,
    load_references,
    match_code,
)
from brotli_binary_metadata import decoder_metadata

REGISTRY = Path(__file__).resolve().parent.parent / "references" / "fingerprints.json"
SOURCE_SUFFIXES = {"", ".c", ".cc", ".cpp", ".cxx", ".h", ".inc", ".inl", ".unbr"}
JS_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
NATIVE_SUFFIXES = {".so", ".dylib", ".dll", ".node", ".a", ".lib", ".wasm", ".exe"}
ZIP_SUFFIXES = {".zip", ".jar", ".war", ".ear", ".whl", ".nupkg", ".apk"}
BINARY_SYMBOLS = (
    b"BrotliDecoderDecompress",
    b"BrotliDecoderCreateInstance",
    b"BrotliDecoderVersion",
    b"BrotliEncoderCompress",
    b"BrotliEncoderVersion",
    b"libbrotlidec",
    b"libbrotlicommon",
    b"libbrotlienc",
    b"org/brotli/dec/",
    b"com/aayushatharva/brotli4j/",
)
COMPRESSED_SUFFIXES = {".gz": "gzip", ".bz2": "bzip2", ".xz": "xz"}
TAR_SUFFIXES = (".tar", ".tgz", ".txz", ".tbz", ".tbz2")
UNSUPPORTED_SUFFIXES = {
    ".deb",
    ".rpm",
    ".zst",
    ".zstd",
    ".tzst",
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
    ".cpio",
    ".ar",
}
ARCHIVE_SIGNATURES = (
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\0", "xz"),
    (b"!<arch>\n", "unsupported"),
    (b"!<thin>\n", "unsupported"),
    (b"\xed\xab\xee\xdb", "unsupported"),
    (b"\x28\xb5\x2f\xfd", "unsupported"),
    (b"7z\xbc\xaf\x27\x1c", "unsupported"),
    (b"Rar!\x1a\x07", "unsupported"),
    (b"\x04\x22\x4d\x18", "unsupported"),
    (b"LZIP", "unsupported"),
    (b"\x1f\x9d", "unsupported"),
    (b"MSCF", "unsupported"),
    (b"xar!", "unsupported"),
    (b"070701", "unsupported"),
    (b"070702", "unsupported"),
    (b"070707", "unsupported"),
)
NODE_FIXES = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
# Frozen from the Node.js release schedule on the advisory snapshot date.
NODE_EOL_BRANCHES = {0, *range(4, 22), 23, 25}
SKIPPABLE_FRAMES = tuple(bytes((first, 0x2A, 0x4D, 0x18)) for first in range(0x50, 0x60))
MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "cargo.toml",
    "cargo.lock",
    "go.mod",
    "go.sum",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
    "poetry.lock",
    "cmakelists.txt",
    "cmakecache.txt",
    "module.bazel",
    "module.bazel.lock",
    "workspace",
    "workspace.bazel",
    "deps",
    ".gitmodules",
    "vcpkg.json",
    "conanfile.txt",
    "conanfile.py",
    "bom.json",
    "metadata",
    "pkg-info",
}
UNDICI = re.compile(r"(?<![\w-])undici(?![\w-])", re.IGNORECASE)
DEPENDENCY = re.compile(
    r"brotli(?:4j|dec|common|enc)?|woff2|workerd|(?<![\w-])undici(?![\w-])",
    re.IGNORECASE,
)
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
GOOD = {"fixed_source", "upstream_fixed_version"}
WARNING = {
    "vulnerable_source",
    "potentially_vulnerable",
    "vulnerable_code_match",
    "mixed_code_matches",
}
MAX_RECORDED_GAPS = 200
MAX_DISPLAY_COPIES = 10
MAX_DISPLAY_GAPS = 5
DEFAULT_MAX_FILE_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_SOURCE_MATCHES = 20
PYC_HEADER_BYTES = 16
DECODER_SYMBOLS = (
    b"BrotliDecoderDecompress",
    b"BrotliDecoderCreateInstance",
    b"DecoderJNI",
)


def leaf_name(label: str) -> str:
    return label.rsplit("!", 1)[-1].replace("\\", "/").rsplit("/", 1)[-1].lower()


def tar_content(data: bytes) -> bool:
    if data[257:262] == b"ustar":
        return True
    try:
        tarfile.TarInfo.frombuf(data[: tarfile.BLOCKSIZE], "utf-8", "surrogateescape")
    except tarfile.HeaderError:
        return False
    return True


def archive_kind(data: bytes, label: str) -> str | None:
    """Recognize containers by bytes, then use names to catch damaged/opaque ones."""
    for signature, kind in ARCHIVE_SIGNATURES:
        if data.startswith(signature):
            return kind
    if data.startswith(SKIPPABLE_FRAMES):
        return "unsupported"  # Zstandard/LZ4 skippable frames.
    if tar_content(data):
        return "tar"
    if zipfile.is_zipfile(io.BytesIO(data)):
        return "zip"  # Also recognizes ZIPs with a prepended executable stub.
    return named_archive_kind(label)


def named_archive_kind(label: str) -> str | None:
    name = leaf_name(label)
    suffix = Path(name).suffix
    if suffix in ZIP_SUFFIXES:
        return "zip"
    if suffix in COMPRESSED_SUFFIXES:
        return COMPRESSED_SUFFIXES[suffix]
    if name.endswith(TAR_SUFFIXES):
        return {".tgz": "gzip", ".txz": "xz", ".tbz": "bzip2", ".tbz2": "bzip2"}.get(suffix, "tar")
    return "unsupported" if suffix in UNSUPPORTED_SUFFIXES else None


def safe_text(value: str) -> str:
    """Quote untrusted display fields, escaping controls, bidi marks, and surrogates."""
    return json.dumps(value, ensure_ascii=True)


def python_bytecode(data: bytes, name: str) -> bool:
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


def dependency_matches(text: str, name: str) -> list[dict]:
    if name != "pyproject.toml":
        return [
            {"line": i, "text": line[:300]}
            for i, line in enumerate(text.splitlines(), 1)
            if DEPENDENCY.search(line)
        ]
    try:
        metadata = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        # Preserve a lead when malformed metadata cannot be parsed.
        return (
            [{"text": "Unparseable Python metadata mentioning Brotli-related components."}]
            if DEPENDENCY.search(text)
            else []
        )
    sections = (
        "project.dependencies",
        "project.optional-dependencies",
        "dependency-groups",
        "build-system.requires",
        "tool.poetry.dependencies",
        "tool.poetry.dev-dependencies",
        "tool.poetry.group",
        "tool.pdm.dev-dependencies",
        "tool.uv.sources",
    )
    matches = []
    for field in sections:
        value = metadata
        for key in field.split("."):
            value = value.get(key, {}) if isinstance(value, dict) else {}
        rendered = json.dumps(value, ensure_ascii=True)
        if DEPENDENCY.search(rendered):
            matches.append({"field": field, "text": rendered[:300]})
    return matches


class BinaryReader(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


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


def binary_indicators(data: bytes) -> list[str]:
    indicators = [symbol.decode("ascii") for symbol in BINARY_SYMBOLS if symbol in data]
    if b"DecoderJNI" in data:
        indicators.append("DecoderJNI")
    return indicators


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


def assess_binary(data: bytes, references: list[CodeReference]) -> dict:
    is_elf = data.startswith(b"\x7fELF")
    code = (
        match_code(data, references)
        if is_elf
        else CodeAssessment([], "Code matching supports linked ELF64 x86_64/AArch64 only")
    )
    metadata = decoder_metadata(data) if is_elf else {}
    versions = metadata.get("versions", [])
    for version in versions:
        rule = assess_version("brotli", version["version"])
        version["upstream_status"] = rule["patch_status"]
        version["fixed_branch_version"] = rule["evidence"].get("fixed_branch_version")
    old_version = any(v["upstream_status"] == "potentially_vulnerable" for v in versions)
    indicators = binary_indicators(data)
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
        "code_matches": code.matches,
        "code_assessment": code.reason,
        "gaps": ([code.reason] if code.limited else [])
        + ([metadata["reason"]] if metadata.get("limited") else []),
    }


class Inventory:
    def __init__(  # noqa: PLR0913 -- Traversal limits plus optional code references.
        self,
        registry: dict,
        max_file_bytes: int,
        max_total_bytes: int,
        max_files: int,
        archive_depth: int,
        *,
        code_references: list[CodeReference] | None = None,
    ) -> None:
        self.fingerprints = {entry["sha256"]: entry for entry in registry["fingerprints"]}
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.max_files = max_files
        self.archive_depth = archive_depth
        self.findings: list[dict] = []
        self.gaps: list[dict] = []
        self.gap_count = 0
        self.files_seen = 0
        self.files_read = 0
        self.bytes_read = 0
        self.archives_attempted = 0
        self.archives_opened = 0
        self.code_references = code_references
        self.checked_paths: set[Path] = set()
        self.pending_symlinks: list[Path] = []
        self.covered_symlinks = 0

    def gap(self, path: str, reason: str) -> None:
        self.gap_count += 1
        if len(self.gaps) < MAX_RECORDED_GAPS:
            self.gaps.append({"path": path, "reason": reason})

    def exhausted(self) -> bool:
        return self.files_seen >= self.max_files or self.bytes_read >= self.max_total_bytes

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
                )
            )

    def read(self, stream: BinaryReader, size: int, label: str, depth: int) -> None:
        self.files_seen += 1
        if self.files_seen > self.max_files:
            self.record_name_fallback(label, size)
            self.gap(label, "File/member count limit reached.")
            return
        remaining = min(self.max_file_bytes, self.max_total_bytes - self.bytes_read)
        if size > remaining:
            self.record_name_fallback(label, size)
            self.gap(label, "File/member exceeds size or remaining total-byte limit.")
            return
        data = stream.read(remaining + 1)
        self.bytes_read += len(data)
        if len(data) > remaining:
            self.record_name_fallback(label, size)
            self.gap(label, "Expanded content exceeded the byte limit.")
            return
        self.files_read += 1
        self.inspect(data, label, depth)

    def inspect(self, data: bytes, label: str, depth: int) -> None:
        digest = hashlib.sha256(data).hexdigest()
        if data.startswith(b"\x7fELF") and self.code_references is not None:
            self._inspect_elf(data, label, digest)
            kind = archive_kind(data, label)
            if kind is not None:
                self._inspect_container(data, label, depth, kind)
            return
        if digest in self.fingerprints:
            entry = self.fingerprints[digest]
            self.findings.append(
                finding(
                    label,
                    "exact_source_match",
                    "fixed_source" if entry["state"] == "fixed" else "vulnerable_source",
                    "Bytes match a reviewed decoder file; surrounding tree/build "
                    "and runtime remain unverified.",
                    sha256=digest,
                    git_blob=entry["git_blob"],
                    sources=entry["sources"],
                )
            )
            return
        kind = archive_kind(data, label)
        if kind is not None:
            self._inspect_container(data, label, depth, kind)
            return
        self._inspect_noncontainer(data, label, digest)

    def _inspect_noncontainer(self, data: bytes, label: str, digest: str) -> None:
        name = leaf_name(label)
        text = data.decode("utf-8", errors="replace") if b"\0" not in data else ""
        if self._inspect_source(text, label, digest):
            return
        first_finding = len(self.findings)
        self._inspect_fetch(text, label)
        if text and (
            name in MANIFEST_NAMES or name.endswith((".cmake", ".spdx.json", ".cdx.json"))
        ):
            self._inspect_manifest(text, label)
        elif not python_bytecode(data, name):
            self._inspect_symbols(data, text, label, digest)
        if is_binary_name_candidate(label) and len(self.findings) == first_finding:
            self.findings.append(
                finding(
                    label,
                    "artifact_name_candidate",
                    "unknown",
                    "Filename suggests Brotli; implementation and patch status unresolved.",
                    sha256=digest,
                    indicators=binary_indicators(data),
                )
            )

    def _inspect_elf(self, data: bytes, label: str, digest: str) -> None:
        references = self.code_references
        if references is None:
            return
        assessment = assess_binary(data, references)
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
                linkage=assessment["linkage"],
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

    def _inspect_manifest(self, text: str, label: str) -> None:
        matches = dependency_matches(text, leaf_name(label))
        if matches:
            self.findings.append(
                finding(
                    label,
                    "dependency_candidate",
                    "unknown",
                    "Declaration or metadata only; resolve the selected implementation "
                    "and embedded version.",
                    matches=matches[:20],
                    matching_lines=len(matches),
                    possible_node_http_client=any(UNDICI.search(row["text"]) for row in matches),
                )
            )

    def _inspect_symbols(self, data: bytes, text: str, label: str, digest: str) -> None:
        name = leaf_name(label)
        if text and Path(name).suffix not in NATIVE_SUFFIXES and ".so." not in name:
            return
        if any(symbol in data for symbol in DECODER_SYMBOLS):
            self.findings.append(
                finding(
                    label,
                    "decoder_symbol_candidate",
                    "unknown",
                    "Decoder symbol/string may identify imports, exports, or embedded code; "
                    "patch status unknown.",
                    sha256=digest,
                )
            )

    def _inspect_container(self, data: bytes, label: str, depth: int, kind: str) -> None:
        previous_gaps = self.gap_count
        if kind == "unsupported":
            self.gap(label, "Unsupported archive or compression format; provide unpacked files.")
        elif depth >= self.archive_depth:
            self.gap(label, "Archive nesting limit reached; members not inspected.")
        else:
            self.inspect_archive(data, label, depth, kind)
        if self.gap_count > previous_gaps and any(symbol in data for symbol in DECODER_SYMBOLS):
            self.findings.append(
                finding(
                    label,
                    "container_symbol_candidate",
                    "unknown",
                    "Decoder marker in container bytes with incomplete member coverage; "
                    "it may come from a member already reported, not an independent decoder copy.",
                    sha256=hashlib.sha256(data).hexdigest(),
                    evidence_scope="container",
                    member_coverage="incomplete",
                )
            )

    def inspect_archive(self, data: bytes, label: str, depth: int, kind: str) -> None:
        self.archives_attempted += 1
        try:
            if kind == "zip":
                self._inspect_zip(data, label, depth)
            elif kind == "tar":
                self._inspect_tar(data, label, depth)
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

    def _inspect_zip(self, data: bytes, label: str, depth: int) -> None:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
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
                    with archive.open(info) as stream:
                        self.read(stream, info.file_size, member, depth + 1)
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

    def _expand_compressed(self, data: bytes, label: str, kind: str) -> bytes | None:
        open_compressed = {"gzip": gzip.open, "bzip2": bz2.open, "xz": lzma.open}[kind]
        remaining = min(self.max_file_bytes, self.max_total_bytes - self.bytes_read)
        with open_compressed(io.BytesIO(data), "rb") as stream:
            expanded = stream.read(remaining + 1)
        self.archives_opened += 1
        self.bytes_read += len(expanded)
        if len(expanded) > remaining:
            self.gap(label, "Expanded content exceeds size or remaining total-byte limit.")
            return None
        return expanded

    def _inspect_compressed(self, data: bytes, label: str, depth: int, kind: str) -> None:
        expanded = self._expand_compressed(data, label, kind)
        if expanded is None:
            return
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
        else:
            member = f"{label}!{Path(name).stem or 'decompressed'}"
            self.read(io.BytesIO(expanded), len(expanded), member, depth + 1)

    def _inspect_tar(self, data: bytes, label: str, depth: int, *, count_open: bool = True) -> None:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|") as archive:
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
                stream = archive.extractfile(info)
                if stream is not None:
                    with stream:
                        self.read(stream, info.size, member, depth + 1)

    def scan_file(self, path: Path) -> None:
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
                self.read(stream, metadata.st_size, label, 0)
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
    if status == "vulnerable_source":
        return {
            "result": "Vulnerable Brotli source found",
            "next_action": (
                "Have the app's maintainer check whether this copy is used. If it "
                "is, update its Brotli dependency, rebuild and deploy the app, and "
                "confirm the running app has the fix."
            ),
        }
    if status == "potentially_vulnerable":
        return explain_possible(item)
    if status == "fixed_source":
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
        "potentially_vulnerable": 1,
        "unknown": 2,
        "fixed_source": 3,
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
        help="compiled ELF decoder references; unmatched binaries remain unknown",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=positive,
        default=DEFAULT_MAX_FILE_BYTES,
        help="maximum bytes read from one file/member (default: 128 MiB)",
    )
    parser.add_argument(
        "--max-total-bytes",
        type=positive,
        default=DEFAULT_MAX_TOTAL_BYTES,
        help="maximum cumulative bytes read (default: 1 GiB)",
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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    roots = args.roots or ([] if args.brotli_version or args.node_version else [Path.cwd()])
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    try:
        code_references = load_references(args.code_references)
    except (OSError, ValueError) as error:
        print(f"Invalid code references: {error}", file=sys.stderr)
        return 2
    inventory = Inventory(
        registry,
        args.max_file_bytes,
        args.max_total_bytes,
        args.max_files,
        args.archive_depth,
        code_references=code_references,
    )
    inventory.scan_roots([root.expanduser().absolute() for root in roots])
    for component, versions in (
        ("brotli", args.brotli_version),
        ("node", args.node_version),
    ):
        inventory.findings.extend(assess_version(component, value) for value in versions)
    statuses = {item["patch_status"] for item in inventory.findings}
    if statuses & WARNING:
        result, code = "affected_evidence_found", 1
    elif inventory.gap_count or not statuses or statuses - GOOD:
        result, code = "review_required", 3
    else:
        result, code = "reported_items_meet_fix_rules", 0
    report = make_report(inventory, roots, args, registry, result)
    report["user_summary"] = summarize(report)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=True))
    else:
        print(render_text(report))
    return code


def make_report(
    inventory: Inventory,
    roots: list[Path],
    args: argparse.Namespace,
    registry: dict,
    result: str,
) -> dict:
    return {
        "schema_version": 1,
        "cve": "CVE-2026-111497",
        "result": result,
        "snapshot_date": registry["verified_on"],
        "advisory_freshness": "not_checked_offline",
        "scope": [str(root.expanduser().absolute()) for root in roots],
        "findings": inventory.findings,
        "coverage": {
            "files_seen": inventory.files_seen,
            "files_read": inventory.files_read,
            "bytes_read": inventory.bytes_read,
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
                "Container layers are inspected without reconstructing the final image filesystem.",
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


if __name__ == "__main__":
    sys.exit(main())
