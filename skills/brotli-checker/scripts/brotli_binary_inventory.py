#!/usr/bin/env python3

"""Read-only binary inventory with compiled ELF decoder code matching."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from brotli_binary_data import Buffer, sha256_data
from brotli_binary_match import (
    REFERENCES,
    CodeReference,
    load_references,
)
from brotli_inventory import (
    DEFAULT_MAX_EXPANDED_BYTES,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_TOTAL_BYTES,
    DEFAULT_MAX_TOTAL_EXPANDED_BYTES,
    Inventory,
    archive_kind,
    assess_binary,
    is_binary_name_candidate,
    positive,
)

MAGICS = {
    b"\x7fELF": "ELF",
    b"MZ": "PE candidate",
    b"\xfe\xed\xfa\xce": "Mach-O",
    b"\xce\xfa\xed\xfe": "Mach-O",
    b"\xfe\xed\xfa\xcf": "Mach-O",
    b"\xcf\xfa\xed\xfe": "Mach-O",
    b"\xca\xfe\xba\xbe": "Mach-O fat or Java class",
    b"\xbe\xba\xfe\xca": "Mach-O fat",
    b"\xca\xfe\xba\xbf": "Mach-O fat",
    b"\xbf\xba\xfe\xca": "Mach-O fat",
    b"\0asm": "WebAssembly",
    b"!<arch>\n": "ar static library",
}


class BinaryInventory(Inventory):
    def __init__(  # noqa: PLR0913 -- Traversal and expansion limits are public CLI controls.
        self,
        catalog: dict[str, str],
        references: list[CodeReference],
        *,
        max_file_bytes: int | None,
        max_total_bytes: int | None,
        max_files: int,
        archive_depth: int,
        max_expanded_bytes: int = DEFAULT_MAX_EXPANDED_BYTES,
        max_total_expanded_bytes: int = DEFAULT_MAX_TOTAL_EXPANDED_BYTES,
    ) -> None:
        super().__init__(
            {"fingerprints": []},
            max_file_bytes,
            max_total_bytes,
            max_files,
            archive_depth,
            max_expanded_bytes=max_expanded_bytes,
            max_total_expanded_bytes=max_total_expanded_bytes,
            code_references=None,
        )
        self.catalog = catalog
        self.references = references

    def record_name_fallback(self, label: str, size_bytes: int | None = None) -> None:
        if not is_binary_name_candidate(label):
            return
        self.findings.append(
            self._finding(
                label,
                kind="artifact_name_candidate",
                size_bytes=size_bytes,
                code_assessment="Content was not inspected; filename only",
                detection_status="name_or_string_only",
            )
        )

    @staticmethod
    def _finding(  # noqa: PLR0913 -- Stable schema has independent evidence fields.
        path: str,
        *,
        kind: str,
        sha256: str | None = None,
        size_bytes: int | None = None,
        format_hint: str | None = None,
        indicators: list[str] | None = None,
        catalog_label: str | None = None,
        patch_status: str = "not_assessed",
        linkage: str = "unknown",
        code_matches: list[dict] | None = None,
        decoder_metadata: dict | None = None,
        recognition: dict | None = None,
        detection_status: str = "not_detected",
        code_assessment: str,
    ) -> dict:
        return {
            "path": path,
            "kind": kind,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "format_hint": format_hint,
            "indicators": indicators or [],
            "catalog_label": catalog_label,
            "patch_status": patch_status,
            "linkage": linkage,
            "code_matches": code_matches or [],
            "decoder_metadata": decoder_metadata or {},
            "recognition": recognition or {},
            "detection_status": detection_status,
            "code_assessment": code_assessment,
        }

    def inspect(self, data: Buffer, label: str, depth: int) -> None:
        digest = sha256_data(data)
        file_format = next((name for magic, name in MAGICS.items() if data.startswith(magic)), None)
        catalog_label = self.catalog.get(digest)
        assessment = assess_binary(data, self.references)
        for reason in assessment["gaps"]:
            self.gap(label, reason)
        named = is_binary_name_candidate(label)
        if file_format or named or catalog_label is not None:
            self.findings.append(
                self._finding(
                    label,
                    kind="exact_artifact_match"
                    if catalog_label is not None
                    else assessment["kind"],
                    sha256=digest,
                    size_bytes=len(data),
                    format_hint=file_format,
                    indicators=assessment["indicators"],
                    catalog_label=catalog_label,
                    patch_status="not_assessed"
                    if assessment["patch_status"] == "unknown"
                    else assessment["patch_status"],
                    linkage=assessment["linkage"],
                    code_matches=assessment["code_matches"],
                    decoder_metadata=assessment["decoder_metadata"],
                    recognition=assessment["recognition"],
                    detection_status=assessment["detection_status"],
                    code_assessment=assessment["reason"],
                )
            )
        kind = archive_kind(data, label)
        if kind is not None:
            self._inspect_container(data, label, depth, kind, digest)


def load_catalog(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    catalog = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(catalog, dict) or any(
        not isinstance(key, str)
        or len(key) != hashlib.sha256().digest_size * 2
        or any(character not in "0123456789abcdef" for character in key)
        or not isinstance(value, str)
        or not value.strip()
        for key, value in catalog.items()
    ):
        message = "Catalog must map lowercase SHA-256 hex digests to nonempty artifact labels."
        raise ValueError(message)
    return catalog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+", type=Path)
    parser.add_argument(
        "--catalog", type=Path, help="JSON mapping of SHA-256 to known artifact labels"
    )
    parser.add_argument(
        "--code-references",
        type=Path,
        default=REFERENCES,
        help="Compiled decoder reference catalog (defaults to packaged references)",
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
        "--max-files",
        type=positive,
        default=100000,
        help="maximum files/archive members considered (default: 100000)",
    )
    parser.add_argument(
        "--archive-depth",
        type=int,
        choices=range(6),
        default=2,
        help="maximum nested archive levels, from 0 to 5 (default: 2)",
    )
    args = parser.parse_args(argv)
    try:
        catalog = load_catalog(args.catalog)
        references = load_references(args.code_references)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    inventory = BinaryInventory(
        catalog,
        references,
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
        max_files=args.max_files,
        archive_depth=args.archive_depth,
        max_expanded_bytes=args.max_expanded_bytes,
        max_total_expanded_bytes=args.max_total_expanded_bytes,
    )
    roots = [root.expanduser().absolute() for root in args.roots]
    inventory.scan_roots(roots)
    report = {
        "schema_version": 2,
        "scope": [str(root) for root in roots],
        "findings": inventory.findings,
        "coverage": {
            "files_read": inventory.files_read,
            "files_seen": inventory.files_seen,
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
            "limits": {
                key: getattr(args, key)
                for key in (
                    "max_file_bytes",
                    "max_total_bytes",
                    "max_expanded_bytes",
                    "max_total_expanded_bytes",
                    "max_files",
                    "archive_depth",
                )
            },
        },
        "limitations": [
            "Old reported versions support warnings, not proof of vulnerable code or a fix.",
            "Strings and artifact catalog labels do not establish code patch status.",
            "Code matches cover reference decoder text only, not all copies or runtime use.",
            "Relocation targets and referenced data are not verified by masked code matching.",
            "Unmatched code remains unidentified; decoder metadata may still support warnings.",
            "Code reference provenance/state is trusted input; custom references require review.",
            "No matches does not establish absence of Brotli, especially in stripped binaries.",
            "Catalog matches identify exact bytes only; supplied labels are not verified.",
            "Archive member paths use ! notation and must not be passed to filesystem commands.",
            "No files are executed, loaded, extracted, moved, or quarantined.",
        ],
    }
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return 3 if inventory.gap_count else (1 if inventory.findings else 0)


# gremlin: pardon[out_of_scope] CLI bootstrap guard; imports must not launch argparse.
if __name__ == "__main__":
    sys.exit(main())
