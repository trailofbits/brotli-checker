#!/usr/bin/env python3
"""Run one retained fuzz corpus serially with isolated, bounded subprocesses."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

ROOT = Path(__file__).resolve().parents[1]
HARNESSES = {
    "binary": ROOT / "scripts/fuzz_binary_analysis.py",
    "package": ROOT / "scripts/fuzz_package_provenance.py",
}
DEFAULT_MEMORY_BYTES = 1024 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_INPUT_BYTES = 64 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
TIMEOUT_EXIT_CODE = 124
MIN_GUARD_ARGUMENTS = 4
AUXILIARY_SOURCES = (ROOT / "skills/brotli-checker/references/elf-relocations.json",)


@dataclass(frozen=True)
class RunSpec:
    harness: Path
    guard: Path
    working_directory: Path
    source: Path
    log: Path
    temporary: Path
    timeout: Path
    timeout_seconds: int
    memory_bytes: int
    lock_descriptor: int


@dataclass(frozen=True)
class SupervisedCommand:
    command: tuple[str, ...]
    guard: Path
    working_directory: Path
    log: Path
    temporary: Path
    timeout: Path
    timeout_seconds: int
    memory_bytes: int
    lock_descriptor: int


@dataclass(frozen=True)
class CorpusContext:
    parser: argparse.ArgumentParser
    harness: Path
    output: Path
    timeout: Path
    lock_descriptor: int
    memory_bytes: int
    timeout_seconds: int
    max_input_bytes: int


@dataclass(frozen=True)
class SourceSnapshot:
    root: Path
    harness: Path
    guard: Path
    sha256: str


def _stat_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _stage_input(path: Path, destination: Path, limit: int) -> tuple[int, str]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        msg = f"fuzz input is not a regular non-symlink file: {path}"
        raise ValueError(msg)
    if metadata.st_size > limit:
        msg = f"fuzz input exceeds the {limit}-byte runner limit: {path}"
        raise ValueError(msg)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if _stat_signature(metadata) != _stat_signature(before):
            msg = f"fuzz input changed while opening: {path}"
            raise ValueError(msg)
        digest = hashlib.sha256()
        offset = 0
        with destination.open("xb") as staged:
            while offset < before.st_size:
                chunk = os.pread(
                    descriptor,
                    min(HASH_CHUNK_BYTES, before.st_size - offset),
                    offset,
                )
                if not chunk:
                    msg = f"fuzz input changed while staging: {path}"
                    raise ValueError(msg)
                digest.update(chunk)
                staged.write(chunk)
                offset += len(chunk)
            staged.flush()
            os.fsync(staged.fileno())
        after = os.fstat(descriptor)
        if _stat_signature(before) != _stat_signature(after):
            msg = f"fuzz input changed while staging: {path}"
            raise ValueError(msg)
        return before.st_size, digest.hexdigest()
    finally:
        os.close(descriptor)


def _input_identity(path: Path, limit: int) -> tuple[int, str]:
    with tempfile.TemporaryDirectory(prefix="fuzz-identity-") as directory:
        return _stage_input(path, Path(directory) / "input", limit)


def _snapshot_sources(harness: Path) -> SourceSnapshot:
    destination = Path(tempfile.mkdtemp(prefix="fuzz-source-"))
    try:
        files = (
            tuple(sorted((ROOT / "scripts").glob("*.py")))
            + tuple(sorted((ROOT / "skills/brotli-checker/scripts").glob("*.py")))
            + AUXILIARY_SOURCES
        )
        identities = []
        for source in files:
            relative = source.relative_to(ROOT)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            size, digest = _stage_input(source, target, DEFAULT_MAX_INPUT_BYTES)
            identities.append((relative.as_posix(), size, digest))
        for source, expected in zip(files, identities, strict=True):
            if _input_identity(source, DEFAULT_MAX_INPUT_BYTES) != (expected[1], expected[2]):
                msg = f"fuzz source changed while snapshotting: {source}"
                raise ValueError(msg)  # noqa: TRY301 -- Snapshot invariant boundary.
        aggregate = hashlib.sha256(
            json.dumps(identities, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
        return SourceSnapshot(
            root=destination,
            harness=destination / harness.relative_to(ROOT),
            guard=destination / "scripts/run_fuzz_corpus.py",
            sha256=aggregate,
        )
    except BaseException:
        shutil.rmtree(destination)
        raise


def _write_manifest(output: Path, value: dict) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix="manifest.", suffix=".json", dir=output)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(output / "manifest.json")
    finally:
        Path(temporary).unlink(missing_ok=True)


def _limit_process(memory_bytes: int) -> None:
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _guard_process(memory_bytes: int, command: list[str]) -> None:
    if not command or not Path(command[0]).is_absolute():
        message = "Guarded fuzz command requires an absolute executable"
        raise ValueError(message)
    _limit_process(memory_bytes)
    os.execv(  # noqa: S606 -- Fixed interpreter and checked-in harness path.
        command[0],
        tuple(command),
    )


def _run_supervised(spec: SupervisedCommand) -> tuple[int, float, int]:
    environment = {
        **os.environ,
        "TMPDIR": str(spec.temporary),
        "OPENBLAS_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
    }
    command = [
        str(spec.timeout),
        "--signal=TERM",
        "--kill-after=5s",
        f"{spec.timeout_seconds}s",
        sys.executable,
        str(spec.guard),
        "--guard-process",
        str(spec.memory_bytes),
        *spec.command,
    ]
    started = time.monotonic()
    with spec.log.open("wb") as output:
        process = subprocess.Popen(  # noqa: S603 -- Fixed checked-in harness and local input.
            command,
            cwd=spec.working_directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            pass_fds=(spec.lock_descriptor,),
        )
        try:
            returncode = process.wait(timeout=spec.timeout_seconds + 10)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
    elapsed = time.monotonic() - started
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return returncode, elapsed, peak


def _run_one(spec: RunSpec) -> tuple[int, float, int]:
    return _run_supervised(
        SupervisedCommand(
            command=(sys.executable, str(spec.harness), str(spec.source)),
            guard=spec.guard,
            working_directory=spec.working_directory,
            log=spec.log,
            temporary=spec.temporary,
            timeout=spec.timeout,
            timeout_seconds=spec.timeout_seconds,
            memory_bytes=spec.memory_bytes,
            lock_descriptor=spec.lock_descriptor,
        )
    )


def _acquire_lock(lock: TextIO, parser: argparse.ArgumentParser) -> None:
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error("another fuzz corpus job is active")


def find_timeout() -> str | None:
    """Return GNU timeout under its common Linux or Homebrew name."""
    return shutil.which("timeout") or shutil.which("gtimeout")


def memory_limit_supported() -> bool:
    """Return whether this runner can enforce the configured address-space cap."""
    return sys.platform.startswith("linux")


def _initial_manifest(args: argparse.Namespace, snapshot: SourceSnapshot) -> dict:
    return {
        "schema_version": 1,
        "harness": args.harness,
        "harness_sha256": hashlib.sha256(snapshot.harness.read_bytes()).hexdigest(),
        "source_snapshot_sha256": snapshot.sha256,
        "memory_bytes_per_process": args.memory_bytes,
        "timeout_seconds_per_input": args.timeout_seconds,
        "max_input_bytes": args.max_input_bytes,
        "workers": 1,
        "results": [],
    }


def _run_input(context: CorpusContext, index: int, input_path: Path) -> dict:
    original = input_path.absolute()
    temporary = Path(tempfile.mkdtemp(prefix="fuzz-input-"))
    source = temporary / "input"
    log = context.output / f"{index:04d}.log"
    try:
        try:
            size, digest = _stage_input(original, source, context.max_input_bytes)
        except (OSError, ValueError) as error:
            context.parser.error(str(error))
        code, elapsed, peak = _run_one(
            RunSpec(
                harness=context.harness,
                guard=context.harness.parent / "run_fuzz_corpus.py",
                working_directory=context.harness.parents[1],
                source=source,
                log=log,
                temporary=temporary,
                timeout=context.timeout,
                timeout_seconds=context.timeout_seconds,
                memory_bytes=context.memory_bytes,
                lock_descriptor=context.lock_descriptor,
            )
        )
    finally:
        shutil.rmtree(temporary)
    if code == 0:
        status = "complete"
    elif code == TIMEOUT_EXIT_CODE:
        status = "time_limit"
    else:
        status = "failed"
    return {
        "input": str(original),
        "input_size": size,
        "input_sha256": digest,
        "log": log.name,
        "returncode": code,
        "status": status,
        "elapsed_seconds": round(elapsed, 6),
        "peak_child_rss_kib_upper_bound": peak,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("harness", choices=sorted(HARNESSES))
    parser.add_argument("output", type=Path)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--memory-bytes", type=int, default=DEFAULT_MEMORY_BYTES)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--max-input-bytes", type=int, default=DEFAULT_MAX_INPUT_BYTES)
    args = parser.parse_args(argv)
    if min(args.memory_bytes, args.timeout_seconds, args.max_input_bytes) <= 0:
        parser.error("resource limits must be positive integers")
    if not memory_limit_supported():
        parser.error(f"per-process address-space limits are unsupported on {sys.platform}")
    timeout_name = find_timeout()
    if timeout_name is None:
        parser.error("GNU timeout is required to supervise fuzz subprocesses")
    output = args.output.absolute()
    if output.exists():
        parser.error(f"output directory already exists: {output}")
    lock_path = Path(tempfile.gettempdir()) / "brotli-checker-fuzz-corpus.lock"
    harness = HARNESSES[args.harness]
    failed = False
    with lock_path.open("a+") as lock:
        _acquire_lock(lock, parser)
        try:
            output.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            parser.error(f"output directory already exists: {output}")
        try:
            snapshot = _snapshot_sources(harness)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        try:
            manifest = _initial_manifest(args, snapshot)
            _write_manifest(output, manifest)
            context = CorpusContext(
                parser=parser,
                harness=snapshot.harness,
                output=output,
                timeout=Path(timeout_name),
                lock_descriptor=lock.fileno(),
                memory_bytes=args.memory_bytes,
                timeout_seconds=args.timeout_seconds,
                max_input_bytes=args.max_input_bytes,
            )
            for index, source in enumerate(args.inputs):
                result = _run_input(context, index, source)
                manifest["results"].append(result)
                _write_manifest(output, manifest)
                failed = failed or result["returncode"] != 0
        finally:
            shutil.rmtree(snapshot.root)
    return int(failed)


if __name__ == "__main__":
    if len(sys.argv) >= MIN_GUARD_ARGUMENTS and sys.argv[1] == "--guard-process":
        _guard_process(int(sys.argv[2]), sys.argv[3:])
    sys.exit(main())
