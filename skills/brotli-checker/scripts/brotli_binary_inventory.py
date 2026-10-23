#!/usr/bin/env python3

"""Read-only binary inventory with compiled ELF decoder code matching."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from brotli_binary_match import (
    REFERENCES,
    CodeAssessment,
    CodeReference,
    load_references,
    match_code,
)
from brotli_inventory import Inventory, archive_kind, positive

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
SYMBOLS = (
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


class BinaryInventory(Inventory):
    def __init__(
        self, catalog: dict[str, str], references: list[CodeReference], **limits: int
    ) -> None:
        super().__init__({"fingerprints": []}, code_references=None, **limits)
        self.catalog = catalog
        self.references = references

    def inspect(self, data: bytes, label: str, depth: int) -> None:
        digest = hashlib.sha256(data).hexdigest()
        file_format = next((name for magic, name in MAGICS.items() if data.startswith(magic)), None)
        indicators = [symbol.decode("ascii") for symbol in SYMBOLS if symbol in data]
        catalog_label = self.catalog.get(digest)
        assessment = (
            match_code(data, self.references)
            if data.startswith(b"\x7fELF")
            else CodeAssessment([], "Code matching supports linked ELF64 x86_64/AArch64 only")
        )
        matches = assessment.matches
        if assessment.limited:
            self.gap(label, assessment.reason)
        # Include named candidates even when the binary has been stripped.
        named = any(
            item["path"] == label and item["kind"] == "artifact_name_candidate"
            for item in self.findings[-1:]
        )
        if file_format or named or catalog_label is not None:
            self.findings.append(
                {
                    "path": label,
                    "kind": "exact_artifact_match"
                    if catalog_label is not None
                    else "decoder_code_match"
                    if matches
                    else "binary_candidate",
                    "sha256": digest,
                    "size_bytes": len(data),
                    "format_hint": file_format,
                    "indicators": indicators,
                    "catalog_label": catalog_label,
                    "patch_status": assessment.patch_status if matches else "not_assessed",
                    "linkage": "embedded_code" if matches else "unknown",
                    "code_matches": matches,
                    "code_assessment": assessment.reason,
                }
            )
        kind = archive_kind(data, label)
        if kind is not None:
            self._inspect_container(data, label, depth, kind)


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
    parser.add_argument("--max-file-bytes", type=positive, default=64 * 1024 * 1024)
    parser.add_argument("--max-total-bytes", type=positive, default=1024 * 1024 * 1024)
    parser.add_argument("--max-files", type=positive, default=100000)
    parser.add_argument("--archive-depth", type=int, choices=range(6), default=2)
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
            "archives_attempted": inventory.archives_attempted,
            "archives_opened": inventory.archives_opened,
            "gap_count": inventory.gap_count,
            "gap_details_retained": len(inventory.gaps),
            "gap_details_omitted": inventory.gap_count - len(inventory.gaps),
            "gaps": inventory.gaps,
            "excluded": [".git"],
            "symlinks_followed": False,
        },
        "limitations": [
            "Strings, versions, and artifact catalog labels do not determine patch status.",
            "Code matches cover reference decoder text only, not all copies or runtime use.",
            "Relocation targets and referenced data are not verified by masked code matching.",
            "Unmatched builds, LTO, alternate compilers, and unsupported formats remain unknown.",
            "Code reference provenance/state is trusted input; custom references require review.",
            "No matches does not establish absence of Brotli, especially in stripped binaries.",
            "Catalog matches identify exact bytes only; supplied labels are not verified.",
            "Archive member paths use ! notation and must not be passed to filesystem commands.",
            "No files are executed, loaded, extracted, moved, or quarantined.",
        ],
    }
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return 3 if inventory.gap_count else (1 if inventory.findings else 0)


if __name__ == "__main__":
    sys.exit(main())
