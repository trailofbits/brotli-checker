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
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "skills/brotli-checker/scripts/brotli_inventory.py"


def main() -> int:
    spec = importlib.util.spec_from_file_location("brotli_inventory", CHECKER_PATH)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    registry = json.loads(checker.REGISTRY.read_text(encoding="utf-8"))

    def verify(entry: dict) -> str | None:
        label = entry["sources"][0]["label"]
        try:
            request = Request(
                entry["sources"][0]["url"],
                headers={"User-Agent": "trailofbits-brotli-checker-verification"},
            )
            with urlopen(request, timeout=30) as response:
                data = response.read(1024 * 1024 + 1)
            if len(data) != entry["size"]:
                return f"{label}: source size mismatch"
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                return f"{label}: SHA-256 mismatch"
            blob = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
            if (
                hashlib.sha1(blob, usedforsecurity=False).hexdigest()
                != entry["git_blob"]
            ):
                return f"{label}: Git blob mismatch"
            code = checker.COMMENTS.sub("", data.decode("utf-8"))
            old_calls = len(checker.OLD_CALL.findall(code))
            new_calls = len(checker.NEW_CALL.findall(code))
            bad_guard = bool(checker.BAD_GUARD.search(code))
            has_error = "BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH" in code
            if entry["state"] == "vulnerable":
                if not (old_calls >= 3 and bad_guard and not has_error):
                    return f"{label}: vulnerable block-switch pattern not found"
                expected, modified_expected = (
                    "vulnerable_source",
                    "potentially_vulnerable",
                )
            elif entry["state"] == "fixed":
                if not (
                    new_calls >= 3 and old_calls == 0 and not bad_guard and has_error
                ):
                    return f"{label}: fixed block-switch pattern not found"
                expected, modified_expected = "fixed_source", "unknown"
            else:
                return f"{label}: unsupported registry state"
            for content, status in (
                (data, expected),
                (data + b"\n/* Verification-only annotation. */\n", modified_expected),
            ):
                result = checker.Inventory(registry, 1 << 24, 1 << 28, 100, 2)
                result.inspect(content, label + ".c", 0)
                if (
                    len(result.findings) != 1
                    or result.findings[0]["patch_status"] != status
                ):
                    return f"{label}: unexpected decoder classification"
                if result.findings[0]["reachability"] != "unknown":
                    return (
                        f"{label}: source evidence incorrectly established reachability"
                    )
            return None
        except (OSError, ValueError, KeyError, TypeError) as error:
            return f"{label}: {type(error).__name__}: {error}"

    with ThreadPoolExecutor(max_workers=4) as pool:
        errors = [
            error for error in pool.map(verify, registry["fingerprints"]) if error
        ]
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    count = len(registry["fingerprints"])
    print(
        f"Verified {count} source fingerprints and {count} modified-source classifications."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
