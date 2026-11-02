#!/usr/bin/env python3
"""Compare retained binary fixtures against independent parser oracles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))
WORKER = ROOT / "scripts/parser_oracle_worker.py"

from brotli_parser_oracles import inspect_fixture, stable_snapshot  # noqa: E402


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="+", type=Path)
    parser.add_argument("--llvm-readobj", type=Path)
    parser.add_argument("--output", type=Path, help="atomic JSON evidence output")
    return parser.parse_args(arguments)


def _write_output(path: Path, raw: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix="parser-differential.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(raw)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main(arguments: list[str] | None = None) -> int:
    args = parse_args(arguments)
    reports = []
    try:
        with tempfile.TemporaryDirectory(prefix="brotli-parser-oracles-") as temporary:
            directory = Path(temporary)
            for source in args.fixture:
                with stable_snapshot(source, directory) as (snapshot, sha256, size):
                    report = inspect_fixture(
                        snapshot,
                        sha256,
                        size,
                        args.llvm_readobj,
                        worker=WORKER,
                    )
                report["source"] = str(source.expanduser().absolute())
                reports.append(report)
    except (OSError, ValueError) as error:
        print(f"parser differential error: {error}", file=sys.stderr)
        return 2
    envelope = {
        "schema_version": 1,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "fixtures": reports,
        "summary": {
            status: sum(item["status"] == status for item in reports)
            for status in ("agreement", "disagreement", "inconclusive")
        },
    }
    raw = json.dumps(envelope, indent=2, sort_keys=True)
    if args.output is not None:
        try:
            _write_output(args.output.expanduser().absolute(), raw)
        except OSError as error:
            print(f"parser differential output error: {error}", file=sys.stderr)
            return 2
    print(raw)
    if envelope["summary"]["disagreement"]:
        return 1
    if envelope["summary"]["inconclusive"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
