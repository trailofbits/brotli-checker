#!/usr/bin/env python3
"""Record one native Brotli build candidate without assigning patch state."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))
from brotli_binary_data import file_data, sha256_data  # noqa: E402
from brotli_binary_layout import inspect_layout  # noqa: E402
from brotli_binary_signatures import CODE_LENGTH_TABLES, recognize_decoder_data  # noqa: E402

if TYPE_CHECKING:
    from brotli_binary_data import Buffer

MAX_BINARY_BYTES = 8 * 1024 * 1024 * 1024
MAX_VERSION_BYTES = 64 * 1024


def digest(data: Buffer) -> str:
    return sha256_data(data)


def file_digest(path: Path) -> str:
    with path.open("rb") as stream, file_data(stream, None) as data:
        return sha256_data(data)


def reviewed_source(source: Path) -> dict:
    registry = json.loads(
        (ROOT / "skills/brotli-checker/references/fingerprints.json").read_text(encoding="utf-8")
    )
    source_sha256 = digest(source.read_bytes())
    matches = [
        item
        for item in registry["fingerprints"]
        if item["sha256"] == source_sha256
        and item.get("implementation", "google_brotli_c") == "google_brotli_c"
    ]
    if len(matches) != 1:
        msg = f"Native candidate source is not uniquely reviewed: {source_sha256}"
        raise ValueError(msg)
    return matches[0]


def header_digest(tree: Path) -> str:
    result = hashlib.sha256()
    headers = sorted((tree / "c").rglob("*.h"))
    if not headers:
        msg = "Native candidate source tree has no headers"
        raise ValueError(msg)
    for path in headers:
        result.update(path.relative_to(tree).as_posix().encode() + b"\0")
        result.update(hashlib.sha256(path.read_bytes()).digest())
    return result.hexdigest()


def layout_summary(item: dict) -> dict:
    return {
        "kind": item["kind"],
        "machine": item["machine"],
        "bits": item["bits"],
        "byteorder": item["byteorder"],
        "mapped_ranges": len(item["ranges"]["mapped"]),
        "executable_ranges": len(item["ranges"]["executable"]),
        "data_ranges": len(item["ranges"]["data"]),
        "function_count": len(item["functions"]),
        "dependency_count": len(item["dependencies"]),
    }


def candidate_manifest(
    binary: Buffer,
    tree: Path,
    compiler: str,
    flags: str,
    objects: tuple[Path, ...] = (),
) -> dict:
    source = tree / "c/dec/decode.c"
    source_entry = reviewed_source(source)
    layout = inspect_layout(binary)
    layouts = layout["slices"] or [layout]
    if layout["kind"] not in {"pe", "mach_o", "mach_o_universal"}:
        msg = f"Native candidate has an unsupported linked format: {layout['kind']}"
        raise ValueError(msg)
    if any(item["gaps"] for item in layouts):
        msg = "Native candidate layout has unresolved gaps"
        raise ValueError(msg)
    recognition = recognize_decoder_data(binary)
    if recognition["limited"] or recognition["scope"] != "loader_data_ranges":
        msg = "Native candidate decoder-table scope is incomplete"
        raise ValueError(msg)
    expected = {"command_lut_le", *CODE_LENGTH_TABLES}
    tables = []
    for index, item in enumerate(layouts):
        matches = [
            row
            for row in recognition["matches"]
            if not layout["slices"] or row.get("slice_index") == index
        ]
        actual = {row["id"] for row in matches}
        if actual != expected:
            msg = f"Native candidate slice lacks complete decoder tables: {item['machine']}"
            raise ValueError(msg)
        tables.append({"machine": item["machine"], "signature_ids": sorted(actual)})
    return {
        "schema_version": 1,
        "source": source_entry["sources"][0]["url"],
        "source_sha256": source_entry["sha256"],
        "source_state_provenance": source_entry["state"],
        "target_patch_status": "unknown",
        "headers_sha256": header_digest(tree),
        "compiler": compiler,
        "flags": flags,
        "binary_sha256": digest(binary),
        "binary_size": len(binary),
        "objects": [
            {"name": path.name, "sha256": file_digest(path), "size": path.stat().st_size}
            for path in objects
        ],
        "layouts": [layout_summary(item) for item in layouts],
        "decoder_tables": tables,
    }


def read_bounded(path: Path, limit: int, label: str) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        msg = f"{label} exceeds the {limit}-byte limit"
        raise ValueError(msg)
    return data


def nonempty(value: str, label: str) -> str:
    if not value:
        msg = f"{label} is empty"
        raise ValueError(msg)
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--source-tree", required=True, type=Path)
    parser.add_argument("--compiler-version-file", required=True, type=Path)
    parser.add_argument("--flags", required=True)
    parser.add_argument("--object", action="append", default=[], type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        compiler = nonempty(
            read_bounded(args.compiler_version_file, MAX_VERSION_BYTES, "Compiler version")
            .decode("utf-8")
            .strip(),
            "Compiler version",
        )
        with args.binary.open("rb") as stream, file_data(stream, MAX_BINARY_BYTES) as binary:
            manifest = candidate_manifest(
                binary,
                args.source_tree.resolve(),
                compiler,
                args.flags,
                tuple(args.object),
            )
        args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    except (OSError, UnicodeDecodeError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
