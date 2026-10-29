#!/usr/bin/env python3
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
import sys
from pathlib import Path

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


def fuzz_one(data: bytes) -> None:
    if not data or len(data) > MAX_FUZZ_INPUT_BYTES:
        return
    selector, payload = data[0] % len(FUZZ_TARGETS), data[1:]
    try:
        FUZZ_TARGETS[selector](payload)
    except (UnicodeError, ValueError):
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path)
    args = parser.parse_args(argv)
    for path in args.inputs:
        with path.open("rb") as stream:
            data = stream.read(MAX_FUZZ_INPUT_BYTES + 1)
        if len(data) > MAX_FUZZ_INPUT_BYTES:
            parser.error(f"fuzz input exceeds limit: {path}")
        fuzz_one(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
