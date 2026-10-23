#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12,<3.16"
# dependencies = []
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
import zipfile
import zlib
from pathlib import Path
from typing import Protocol

REGISTRY = Path(__file__).resolve().parent.parent / "references" / "fingerprints.json"
SOURCE_SUFFIXES = {"", ".c", ".cc", ".cpp", ".cxx", ".h", ".inc", ".inl", ".unbr"}
NATIVE_SUFFIXES = {".so", ".dylib", ".dll", ".node", ".a", ".lib", ".wasm", ".exe"}
ZIP_SUFFIXES = {".zip", ".jar", ".war", ".ear", ".whl", ".nupkg", ".apk"}
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
DEPENDENCY = re.compile(r"brotli(?:4j|dec|common|enc)?|woff2|workerd", re.IGNORECASE)
SWITCH_CALL = r"Decode(?:Literal|Command|Distance)BlockSwitch\s*\("
OLD_CALL = re.compile(r"\bBROTLI_SAFE\s*\(\s*(" + SWITCH_CALL + r")")
NEW_CALL = re.compile(r"\bBROTLI_SAFE_WITH_STATUS\s*\(\s*(" + SWITCH_CALL + r")")
BAD_GUARD = re.compile(r"if\s*\(\s*max_block_type\s*<=\s*1\s*\)\s*\{\s*return\s+BROTLI_FALSE\s*;")
COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
GOOD = {"fixed_source", "upstream_fixed_version"}
WARNING = {"vulnerable_source", "potentially_vulnerable"}
MAX_RECORDED_GAPS = 200
MAX_DISPLAY_COPIES = 10
MAX_DISPLAY_GAPS = 5


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


def assess_version(component: str, value: str) -> dict:
    match = re.fullmatch(r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", value.strip())
    path = f"supplied:{component}:{value}"
    if not match:
        return finding(
            path,
            "supplied_version",
            "unknown",
            "Not an unambiguous upstream stable version.",
        )
    version = tuple(map(int, match.groups()))
    if component == "brotli":
        branch = (version[0], version[1])
        fixes = {(1, 0): 10, (1, 1): 1, (1, 2): 1}
        if branch not in fixes or version < (1, 0, 3):
            return finding(
                path,
                "supplied_version",
                "unknown",
                "Outside snapshot patch rules; inspect the actual decoder.",
            )
        fixed = version[2] >= fixes[branch]
        minimum = f"{branch[0]}.{branch[1]}.{fixes[branch]}"
    else:
        fixes = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
        if version[0] not in fixes:
            return finding(
                path,
                "supplied_version",
                "unknown",
                "No patch rule for this Node branch; inspect embedded Brotli or vendor guidance.",
            )
        fixed = version >= fixes[version[0]]
        minimum = ".".join(map(str, fixes[version[0]]))
    return finding(
        path,
        "supplied_version",
        "upstream_fixed_version" if fixed else "potentially_vulnerable",
        "Supplied upstream version meets the branch fix; installed build unverified."
        if fixed
        else "Supplied upstream version precedes the branch fix; vendor backport status unknown.",
        component=component,
        supplied_version=value,
        fixed_branch_version=minimum,
    )


class Inventory:
    def __init__(
        self,
        registry: dict,
        max_file_bytes: int,
        max_total_bytes: int,
        max_files: int,
        archive_depth: int,
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
        self.archives_opened = 0

    def gap(self, path: str, reason: str) -> None:
        self.gap_count += 1
        if len(self.gaps) < MAX_RECORDED_GAPS:
            self.gaps.append({"path": path, "reason": reason})

    def exhausted(self) -> bool:
        return self.files_seen >= self.max_files or self.bytes_read >= self.max_total_bytes

    def candidate_name(self, label: str) -> None:
        name = label.rsplit("!", 1)[-1].replace("\\", "/").rsplit("/", 1)[-1].lower()
        if "brotli" in name and (
            Path(name).suffix in NATIVE_SUFFIXES | ZIP_SUFFIXES or ".so." in name
        ):
            self.findings.append(
                finding(
                    label,
                    "artifact_name_candidate",
                    "unknown",
                    (
                        "Artifact name suggests a Brotli component; contents, linkage, and "
                        "patch status need review."
                    ),
                )
            )

    def read(self, stream: BinaryReader, size: int, label: str, depth: int) -> None:
        self.files_seen += 1
        self.candidate_name(label)
        if self.files_seen > self.max_files:
            self.gap(label, "File/member count limit reached.")
            return
        remaining = min(self.max_file_bytes, self.max_total_bytes - self.bytes_read)
        if size > remaining:
            self.gap(label, "File/member exceeds size or remaining total-byte limit.")
            return
        data = stream.read(remaining + 1)
        self.bytes_read += len(data)
        if len(data) > remaining:
            self.gap(label, "Expanded content exceeded the byte limit.")
            return
        self.files_read += 1
        self.inspect(data, label, depth)

    def inspect(self, data: bytes, label: str, depth: int) -> None:
        digest = hashlib.sha256(data).hexdigest()
        if digest in self.fingerprints:
            entry = self.fingerprints[digest]
            fixed = entry["state"] == "fixed"
            self.findings.append(
                finding(
                    label,
                    "exact_source_match",
                    "fixed_source" if fixed else "vulnerable_source",
                    (
                        "Bytes match a reviewed decoder file; surrounding tree/build and "
                        "runtime remain unverified."
                    ),
                    sha256=digest,
                    git_blob=entry["git_blob"],
                    sources=entry["sources"],
                )
            )
            return
        name = label.rsplit("!", 1)[-1].replace("\\", "/").rsplit("/", 1)[-1].lower()
        suffix = Path(name).suffix
        text = data.decode("utf-8", errors="replace") if b"\0" not in data else ""
        if text and suffix in SOURCE_SUFFIXES and "DecodeBlockTypeAndLength" in text:
            code = COMMENTS.sub("", text)
            if "ProcessCommandsInternal" in code and "BrotliDecoderDecompressStream" in code:
                old = len(OLD_CALL.findall(code))
                new = len(NEW_CALL.findall(code))
                bad_guard = bool(BAD_GUARD.search(code))
                potential = bool(old and bad_guard)
                self.findings.append(
                    finding(
                        label,
                        "modified_decoder_source",
                        "potentially_vulnerable" if potential else "unknown",
                        (
                            "Old block-switch error handling detected; review the source against "
                            "the fix."
                        )
                        if potential
                        else (
                            "Unrecognized decoder source; fix markers alone do not validate a "
                            "backport."
                        ),
                        sha256=digest,
                        old_switch_calls=old,
                        status_switch_calls=new,
                        false_on_invalid_switch=bad_guard,
                        format_error_marker="BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH" in code,
                    )
                )
                return
        if text and (
            name in MANIFEST_NAMES or name.endswith((".cmake", ".spdx.json", ".cdx.json"))
        ):
            lines = [
                {"line": i, "text": line[:300]}
                for i, line in enumerate(text.splitlines(), 1)
                if DEPENDENCY.search(line)
            ]
            if lines:
                self.findings.append(
                    finding(
                        label,
                        "dependency_candidate",
                        "unknown",
                        (
                            "Declaration or metadata only; resolve the selected implementation "
                            "and embedded version."
                        ),
                        matches=lines[:20],
                        matching_lines=len(lines),
                    )
                )
        elif any(
            symbol in data
            for symbol in (
                b"BrotliDecoderDecompress",
                b"BrotliDecoderCreateInstance",
                b"DecoderJNI",
            )
        ):
            if not text or suffix in NATIVE_SUFFIXES or ".so." in name:
                self.findings.append(
                    finding(
                        label,
                        "decoder_symbol_candidate",
                        "unknown",
                        (
                            "Decoder symbol/string may identify imports, exports, or embedded "
                            "code; patch status unknown."
                        ),
                        sha256=digest,
                    )
                )
        archive = suffix in ZIP_SUFFIXES or name.endswith(
            (".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2")
        )
        if not archive:
            return
        if depth >= self.archive_depth:
            self.gap(label, "Archive nesting limit reached; members not inspected.")
            return
        self.inspect_archive(data, label, depth)

    def inspect_archive(self, data: bytes, label: str, depth: int) -> None:
        self.archives_opened += 1
        try:
            if Path(label).suffix.lower() in ZIP_SUFFIXES:
                self._inspect_zip(data, label, depth)
            else:
                self._inspect_tar(data, label, depth)
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
            for info in archive.infolist():
                if info.is_dir():
                    continue
                member = f"{label}!{info.filename}"
                if self.exhausted():
                    self.gap(label, "Budget exhausted; remaining archive members not inspected.")
                    break
                if stat.S_ISLNK(info.external_attr >> 16):
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
                    self.gap(member, f"Cannot inspect archive member: {error}")

    def _expand_tar(self, data: bytes, label: str) -> bytes | None:
        name = label.lower()
        if name.endswith((".tar.gz", ".tgz")):
            open_compressed = gzip.open
        elif name.endswith((".tar.xz", ".txz")):
            open_compressed = lzma.open
        elif name.endswith(".tar.bz2"):
            open_compressed = bz2.open
        else:
            return data
        remaining = min(self.max_file_bytes, self.max_total_bytes - self.bytes_read)
        with open_compressed(io.BytesIO(data), "rb") as stream:
            expanded = stream.read(remaining + 1)
        self.bytes_read += len(expanded)
        if len(expanded) > remaining:
            self.gap(label, "Expanded TAR exceeds size or remaining total-byte limit.")
            return None
        return expanded

    def _inspect_tar(self, data: bytes, label: str, depth: int) -> None:
        expanded = self._expand_tar(data, label)
        if expanded is None:
            return
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r|") as archive:
            for info in archive:
                if info.isdir():
                    continue
                member = f"{label}!{info.name}"
                if self.exhausted():
                    self.gap(label, "Budget exhausted; remaining archive members not inspected.")
                    break
                if not info.isfile():
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
            if not stat.S_ISREG(metadata.st_mode):
                self.gap(label, "Symlink or nonregular file not followed.")
                return
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            )
            with os.fdopen(descriptor, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    self.gap(label, "Nonregular file not read.")
                    return
                self.read(stream, metadata.st_size, label, 0)
        except OSError as error:
            self.gap(label, f"Cannot read file: {error}")

    def scan_root(self, root: Path) -> None:
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
                self.gap(str(path), "Directory symlink not followed.")
            else:
                kept.append(name)
        return kept


def positive(value: str) -> int:
    number = int(value)
    if number <= 0:
        message = "must be positive"
        raise argparse.ArgumentTypeError(message)
    return number


def explain_finding(item: dict) -> dict:
    status = item["patch_status"]
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
        evidence = item["evidence"]
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
    return {
        "result": "More information needed",
        "next_action": (
            "Share this finding with the app's maintainer or hosting provider. "
            "Ask them to identify the Brotli copy inside this component and "
            "confirm whether it includes the fix."
        ),
    }


def summarize(report: dict) -> dict:
    findings = report["findings"]
    statuses = {item["patch_status"] for item in findings}
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
                "Some checked code or supplied versions may be affected. A "
                "maintainer needs to confirm which copy the app uses and whether its "
                "vendor has already fixed it."
            ),
            "next_steps": [
                "Follow the update or verification step for each flagged item below.",
                "Confirm the running app uses the fixed copy after the update.",
            ],
        }
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
                    "Share the skipped-file list with the app's maintainer and ask them "
                    "to check those files or provide the app package for inspection."
                )
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
    # Merge evidence about the same file for display; full evidence stays in JSON.
    priorities = {
        "vulnerable_source": 0,
        "potentially_vulnerable": 1,
        "unknown": 2,
        "fixed_source": 3,
        "upstream_fixed_version": 3,
    }
    copies = {}
    for item in report["findings"]:
        previous = copies.get(item["path"])
        if (
            previous is None
            or priorities[item["patch_status"]] < priorities[previous["patch_status"]]
        ):
            copies[item["path"]] = item
    if copies:
        lines.extend(["", "Files and versions checked:"])
        ordered = sorted(copies.values(), key=lambda item: priorities[item["patch_status"]])
        for item in ordered[:MAX_DISPLAY_COPIES]:
            explanation = explain_finding(item)
            location = item["path"]
            if item["kind"] == "supplied_version" and "supplied_version" in item["evidence"]:
                evidence = item["evidence"]
                component = "Node.js" if evidence["component"] == "node" else "Brotli"
                location = f"{component} {evidence['supplied_version']} (version supplied)"
            lines.extend(
                [
                    f"- {explanation['result']}: {location}",
                    f"  Next: {explanation['next_action']}",
                ]
            )
        if len(ordered) > MAX_DISPLAY_COPIES:
            lines.append(
                f"- {len(ordered) - MAX_DISPLAY_COPIES} more items are included "
                "in the full report (--json)."
            )
    gaps = report["coverage"]["gaps"]
    if gaps:
        lines.extend(["", "Could not check:"])
        lines.extend(f"- {gap['path']}: {gap['reason']}" for gap in gaps[:MAX_DISPLAY_GAPS])
        remaining = report["coverage"]["gap_count"] - min(MAX_DISPLAY_GAPS, len(gaps))
        if remaining:
            lines.append(f"- {remaining} more gaps are included in the full report (--json).")
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check local files for Brotli copies that may need a security update."
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
    parser.add_argument("--brotli-version", action="append", default=[])
    parser.add_argument("--node-version", action="append", default=[])
    parser.add_argument("--max-file-bytes", type=positive, default=16 * 1024 * 1024)
    parser.add_argument("--max-total-bytes", type=positive, default=256 * 1024 * 1024)
    parser.add_argument("--max-files", type=positive, default=50000)
    parser.add_argument("--archive-depth", type=int, choices=range(6), default=2)
    args = parser.parse_args(argv)
    roots = args.roots or ([] if args.brotli_version or args.node_version else [Path.cwd()])
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    inventory = Inventory(
        registry,
        args.max_file_bytes,
        args.max_total_bytes,
        args.max_files,
        args.archive_depth,
    )
    for root in roots:
        if inventory.exhausted():
            inventory.gap(str(root), "Budget exhausted; root not inspected.")
        else:
            inventory.scan_root(root.expanduser().absolute())
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
    report = {
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
            "archives_opened": inventory.archives_opened,
            "gap_count": inventory.gap_count,
            "gaps": inventory.gaps,
            "excluded": [".git"],
            "symlinks_followed": False,
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
    report["user_summary"] = summarize(report)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=True))
    else:
        print(render_text(report))
    return code


if __name__ == "__main__":
    sys.exit(main())
