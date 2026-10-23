#!/usr/bin/env python3
"""Download reference source and verify the registry and decoder classifications.

This optional maintainer check needs internet access. Downloaded source is
inspected in memory and never executed or added to the repository.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.request import Request, urlopen

if TYPE_CHECKING:
    from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "skills/brotli-checker/scripts/brotli_inventory.py"
sys.path.insert(0, str(CHECKER_PATH.parent))
BLOCK_SWITCH_CALLS = 3


def verify_identity(entry: dict, data: bytes) -> str | None:
    if len(data) != entry["size"]:
        return "source size mismatch"
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        return "SHA-256 mismatch"
    blob = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    if hashlib.sha1(blob, usedforsecurity=False).hexdigest() != entry["git_blob"]:
        return "Git blob mismatch"
    return None


def verify_pattern(entry: dict, data: bytes, checker: ModuleType) -> str | None:
    code = checker.COMMENTS.sub("", data.decode("utf-8"))
    old_calls = len(checker.OLD_CALL.findall(code))
    new_calls = len(checker.NEW_CALL.findall(code))
    bad_guard = bool(checker.BAD_GUARD.search(code))
    has_error = "BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH" in code
    if entry["state"] == "vulnerable":
        if not (old_calls >= BLOCK_SWITCH_CALLS and bad_guard and not has_error):
            return "vulnerable block-switch pattern not found"
    elif entry["state"] == "fixed":
        if not (new_calls >= BLOCK_SWITCH_CALLS and old_calls == 0 and not bad_guard and has_error):
            return "fixed block-switch pattern not found"
    else:
        return "unsupported registry state"
    return None


def verify_classifications(
    entry: dict, data: bytes, checker: ModuleType, registry: dict
) -> str | None:
    expected, modified_expected = (
        ("vulnerable_source", "potentially_vulnerable")
        if entry["state"] == "vulnerable"
        else ("fixed_source", "unknown")
    )
    for content, status in (
        (data, expected),
        (data + b"\n/* Verification-only annotation. */\n", modified_expected),
    ):
        result = checker.Inventory(registry, 1 << 24, 1 << 28, 100, 2)
        result.inspect(content, entry["sources"][0]["label"] + ".c", 0)
        if len(result.findings) != 1 or result.findings[0]["patch_status"] != status:
            return "unexpected decoder classification"
        if result.findings[0]["reachability"] != "unknown":
            return "source evidence incorrectly established reachability"
    return None


def verify_reference(entry: dict, *, checker: ModuleType, registry: dict) -> str | None:
    label = entry["sources"][0]["label"]
    try:
        url = entry["sources"][0]["url"]
        if not url.startswith("https://raw.githubusercontent.com/"):
            return f"{label}: expected a public GitHub HTTPS source URL"
        request = Request(  # noqa: S310 -- The registry URL is restricted to GitHub HTTPS above.
            url,
            headers={"User-Agent": "trailofbits-brotli-checker-verification"},
        )
        with urlopen(request, timeout=30) as response:  # noqa: S310 -- Restricted HTTPS registry URL.
            data = response.read(1024 * 1024 + 1)
        error = (
            verify_identity(entry, data)
            or verify_pattern(entry, data, checker)
            or verify_classifications(entry, data, checker, registry)
        )
        if error:
            return f"{label}: {error}"
    except (OSError, ValueError, KeyError, TypeError) as error:
        return f"{label}: {type(error).__name__}: {error}"
    else:
        return None


def main() -> int:
    spec = importlib.util.spec_from_file_location("brotli_inventory", CHECKER_PATH)
    if spec is None or spec.loader is None:
        message = f"Cannot load the inventory helper at {CHECKER_PATH}"
        raise ImportError(message)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    registry = json.loads(checker.REGISTRY.read_text(encoding="utf-8"))
    verify = partial(verify_reference, checker=checker, registry=registry)
    with ThreadPoolExecutor(max_workers=4) as pool:
        errors = [error for error in pool.map(verify, registry["fingerprints"]) if error]
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    count = len(registry["fingerprints"])
    print(f"Verified {count} source fingerprints and {count} modified-source classifications.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
