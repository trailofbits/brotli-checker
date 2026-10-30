#!/usr/bin/env python3
"""Run one bounded, serialized Atheris campaign with hash-bound evidence."""

from __future__ import annotations

import argparse
import importlib.metadata
import platform
import re
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path

from fuzz_with_atheris import HARNESSES, PINNED_VERSION
from run_fuzz_corpus import (
    ROOT,
    SupervisedCommand,
    _acquire_lock,
    _input_identity,
    _run_supervised,
    _snapshot_sources,
    _stage_input,
    _write_manifest,
)

DEFAULT_MEMORY_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_INPUT_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_TOTAL_SEED_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_SEEDS = 1024
DEFAULT_MAX_RETAINED_FILES = 4096
DEFAULT_MAX_RETAINED_BYTES = 512 * 1024 * 1024
DEFAULT_RUNS = 10_000
DEFAULT_SECONDS = 60
MAX_CAMPAIGN_SECONDS = 3600
TIMEOUT_EXIT_CODE = 124
METRICS = re.compile(
    rb"#(?P<executions>\d+).*?cov:\s*(?P<coverage>\d+)\s+ft:\s*(?P<features>\d+)\s+"
    rb"corp:\s*(?P<corpus_files>\d+)/(?P<corpus_bytes>\d+)(?P<unit>[A-Za-z]*)"
)


def _seed_files(directory: Path, limit: int) -> tuple[Path, ...]:
    metadata = directory.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        message = "Atheris seed corpus must be a regular non-symlink directory"
        raise ValueError(message)
    values = []
    for path in sorted(directory.iterdir()):
        if path.name == "manifest.json":
            continue
        item = path.lstat()
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
            message = f"Atheris seed is not a regular non-symlink file: {path}"
            raise ValueError(message)
        values.append(path)
    if not 1 <= len(values) <= limit:
        message = "Atheris seed corpus population is empty or over limit"
        raise ValueError(message)
    return tuple(values)


def _stage_corpus(source: Path, destination: Path, max_input: int) -> list[dict]:
    destination.mkdir()
    rows = []
    total = 0
    for index, path in enumerate(_seed_files(source, DEFAULT_MAX_SEEDS)):
        staged = destination / f"{index:04d}"
        size, digest = _stage_input(path, staged, max_input)
        total += size
        if total > DEFAULT_MAX_TOTAL_SEED_BYTES:
            message = "Atheris seed corpus exceeds cumulative byte limit"
            raise ValueError(message)
        rows.append({"name": path.name, "size": size, "sha256": digest})
    return rows


def _retained_corpus(directory: Path, max_input: int) -> list[dict]:
    rows = []
    total = 0
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.is_symlink():
            message = "Atheris produced a nonregular corpus entry"
            raise ValueError(message)
        if len(rows) >= DEFAULT_MAX_RETAINED_FILES:
            message = "Atheris retained corpus file limit reached"
            raise ValueError(message)
        size, digest = _input_identity(path, max_input)
        total += size
        if total > DEFAULT_MAX_RETAINED_BYTES:
            message = "Atheris retained corpus byte limit reached"
            raise ValueError(message)
        rows.append({"name": path.name, "size": size, "sha256": digest})
    return rows


def _tool_versions() -> dict[str, str]:
    result = {"python": platform.python_version()}
    for name in ("atheris", "capstone", "pyelftools", "zstandard"):
        try:
            result[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            result[name] = "unavailable"
    return result


def _metrics(log: bytes) -> dict | None:
    matches = tuple(METRICS.finditer(log))
    if not matches:
        return None
    values = matches[-1].groupdict()
    multiplier = {b"": 1, b"b": 1, b"Kb": 1024, b"Mb": 1024 * 1024}.get(values["unit"])
    if multiplier is None:
        return None
    return {
        "executions": int(values["executions"]),
        "coverage": int(values["coverage"]),
        "features": int(values["features"]),
        "corpus_files": int(values["corpus_files"]),
        "corpus_bytes": int(values["corpus_bytes"]) * multiplier,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("harness", choices=sorted(HARNESSES))
    parser.add_argument("seeds", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--seconds", type=int, default=DEFAULT_SECONDS)
    parser.add_argument("--memory-bytes", type=int, default=DEFAULT_MEMORY_BYTES)
    parser.add_argument("--max-input-bytes", type=int, default=DEFAULT_MAX_INPUT_BYTES)
    args = parser.parse_args(argv)
    if (
        min(args.runs, args.seconds, args.memory_bytes, args.max_input_bytes) <= 0
        or args.seconds > MAX_CAMPAIGN_SECONDS
    ):
        parser.error("campaign limits must be positive and within the maintained time bound")
    try:
        version = importlib.metadata.version("atheris")
    except importlib.metadata.PackageNotFoundError as error:
        parser.error(f"Atheris {PINNED_VERSION} is required: {error}")
    if version != PINNED_VERSION:
        parser.error(f"Atheris {PINNED_VERSION} is required; found {version}")
    timeout_name = shutil.which("timeout")
    if timeout_name is None:
        parser.error("GNU timeout is required to supervise Atheris")
    output = args.output.expanduser().absolute()
    if output.exists():
        parser.error(f"output directory already exists: {output}")
    lock_path = Path(tempfile.gettempdir()) / "brotli-checker-fuzz-corpus.lock"
    with lock_path.open("a+") as lock:
        _acquire_lock(lock, parser)
        output.mkdir(parents=True)
        corpus = output / "corpus"
        crashes = output / "crashes"
        crashes.mkdir()
        try:
            seed_rows = _stage_corpus(
                args.seeds.expanduser().absolute(), corpus, args.max_input_bytes
            )
            snapshot = _snapshot_sources(ROOT / "scripts/fuzz_with_atheris.py")
        except (OSError, ValueError) as error:
            parser.error(str(error))
        temporary = Path(tempfile.mkdtemp(prefix="fuzz-campaign-"))
        log = output / "atheris.log"
        try:
            command = (
                sys.executable,
                str(snapshot.harness),
                args.harness,
                str(corpus),
                f"-atheris_runs={args.runs}",
                f"-max_total_time={args.seconds}",
                f"-max_len={args.max_input_bytes}",
                f"-rss_limit_mb={args.memory_bytes // (1024 * 1024)}",
                f"-artifact_prefix={crashes}/",
                "-print_final_stats=1",
            )
            started = time.monotonic()
            code, _, peak = _run_supervised(
                SupervisedCommand(
                    command=command,
                    guard=snapshot.guard,
                    working_directory=snapshot.root,
                    log=log,
                    temporary=temporary,
                    timeout=Path(timeout_name),
                    timeout_seconds=args.seconds + 15,
                    memory_bytes=args.memory_bytes,
                    lock_descriptor=lock.fileno(),
                )
            )
            elapsed = time.monotonic() - started
            observed = _metrics(log.read_bytes())
            status = (
                "complete"
                if code == 0 and observed is not None
                else "time_limit"
                if code == TIMEOUT_EXIT_CODE
                else "failed_or_invalid_output"
            )
            manifest = {
                "schema_version": 1,
                "harness": args.harness,
                "atheris_version": version,
                "tool_versions": _tool_versions(),
                "source_snapshot_sha256": snapshot.sha256,
                "seed_inputs": seed_rows,
                "retained_corpus": _retained_corpus(corpus, args.max_input_bytes),
                "runs_limit": args.runs,
                "time_limit_seconds": args.seconds,
                "memory_bytes_per_process": args.memory_bytes,
                "max_input_bytes": args.max_input_bytes,
                "workers": 1,
                "returncode": code,
                "status": status,
                "elapsed_seconds": round(elapsed, 6),
                "peak_child_rss_kib_upper_bound": peak,
                "metrics": observed,
                "log": log.name,
                "crashes": _retained_corpus(crashes, args.max_input_bytes),
            }
            _write_manifest(output, manifest)
        finally:
            shutil.rmtree(temporary)
            shutil.rmtree(snapshot.root)
    return int(manifest["status"] != "complete")


if __name__ == "__main__":
    sys.exit(main())
