#!/usr/bin/env python3
# ruff: noqa: E402
"""Development fuzz entry point for structured provenance/package parsers.

Run a retained corpus without dependencies:

    uv run python scripts/fuzz_package_provenance.py corpus/*

Coverage-guided runners can import ``fuzz_one`` and pass arbitrary bytes. The
first byte selects a parser. Expected malformed-input ``ValueError`` and text
decoding failures are ignored; every other exception escapes as a finding.
The harness performs no package-manager commands, network access, or writes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))

from brotli_package_provenance import (
    apk_version_compare,
    debian_version_compare,
    load_vendor_snapshot,
    parse_apk_database,
    parse_dpkg_database,
    rpm_version_compare,
)
from brotli_provenance import parse_provenance_json

MAX_FUZZ_INPUT_BYTES = 64 * 1024 * 1024


def _pair(data: bytes) -> tuple[str, str]:
    left, separator, right = data.partition(b"\0")
    if not separator:
        right = left
    return left.decode("utf-8"), right.decode("utf-8")


def _provenance(data: bytes) -> None:
    parse_provenance_json(data.decode("utf-8"), "fuzz.json")


def _snapshot(data: bytes) -> None:
    load_vendor_snapshot(data.decode("utf-8"))


def _dpkg(data: bytes) -> None:
    parse_dpkg_database(data, ())


def _apk(data: bytes) -> None:
    parse_apk_database(data)


def _debian_version(data: bytes) -> None:
    debian_version_compare(*_pair(data))


def _rpm_version(data: bytes) -> None:
    rpm_version_compare(*_pair(data))


def _apk_version(data: bytes) -> None:
    apk_version_compare(*_pair(data))


FUZZ_TARGETS = (
    _provenance,
    _snapshot,
    _dpkg,
    _apk,
    _debian_version,
    _rpm_version,
    _apk_version,
)


def seed_corpus() -> dict[str, bytes]:
    values = (
        (
            "cyclonedx",
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []},
        ),
        (
            "vendor-snapshot",
            {
                "schema_version": 1,
                "snapshot_date": "2026-10-30",
                "vendor": "debian",
                "release": "13",
                "assertions": [],
            },
        ),
    )
    seeds = {
        values[0][0]: b"\0" + json.dumps(values[0][1], separators=(",", ":")).encode(),
        values[1][0]: b"\1" + json.dumps(values[1][1], separators=(",", ":")).encode(),
        "dpkg-status": b"\2Package: brotli\nStatus: install ok installed\nVersion: 1.2.1-1\n\n",
        "apk-installed": b"\3P:brotli\nV:1.2.1-r0\nA:x86_64\n\n",
        "debian-version": bytes((4,)) + b"1.2.1-1\0" + b"0:1.2.0-1",
        "rpm-version": bytes((5,)) + b"2:1.2.1-4.el10\0" + b"1:1.2.1-4.el10",
        "apk-version": bytes((6,)) + b"1.2.1-r1\0" + b"1.2.1-r0",
    }
    if any(len(value) > MAX_FUZZ_INPUT_BYTES for value in seeds.values()):
        message = "generated package fuzz seed exceeds input limit"
        raise ValueError(message)
    return seeds


def fuzz_one(data: bytes) -> None:
    if not data or len(data) > MAX_FUZZ_INPUT_BYTES:
        return
    selector, payload = data[0] % len(FUZZ_TARGETS), data[1:]
    try:
        FUZZ_TARGETS[selector](payload)
    except (UnicodeError, ValueError):
        return


def _write_seeds(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=False)
    rows = []
    for name, data in sorted(seed_corpus().items()):
        (directory / name).write_bytes(data)
        rows.append({"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    (directory / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "seeds": rows}, indent=2) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", type=Path)
    parser.add_argument("--write-seeds", type=Path)
    args = parser.parse_args(argv)
    if (args.write_seeds is None) == (not args.inputs):
        parser.error("provide corpus inputs or exactly one --write-seeds directory")
    if args.write_seeds is not None:
        _write_seeds(args.write_seeds)
        return 0
    for path in args.inputs:
        with path.open("rb") as stream:
            data = stream.read(MAX_FUZZ_INPUT_BYTES + 1)
        if len(data) > MAX_FUZZ_INPUT_BYTES:
            parser.error(f"fuzz input exceeds limit: {path}")
        fuzz_one(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
