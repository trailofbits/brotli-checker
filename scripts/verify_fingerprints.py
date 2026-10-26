#!/usr/bin/env python3
"""Download reference source and verify the registry and decoder classifications.

This optional maintainer check needs internet access. Downloaded source is
inspected in memory and never executed or added to the repository.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "skills/brotli-checker/scripts/brotli_inventory.py"
sys.path.insert(0, str(CHECKER_PATH.parent))
import brotli_inventory as checker  # noqa: E402

BLOCK_SWITCH_CALLS = 3
GO_STATUS_CALLS = 4
LEGACY_C = "google_brotli_c"
GO_PORT = "andybalholm_brotli_go"
RUST_PORT = "dropbox_brotli_decompressor_rust"
PORT_METADATA = {
    GO_PORT: {
        "component": "github.com/andybalholm/brotli",
        "upstream_fix": (
            "https://github.com/andybalholm/brotli/commit/33c2a9884269798192b5ecf171288f98939dbe42"
        ),
    },
    RUST_PORT: {
        "component": "brotli-decompressor",
        "upstream_fix": (
            "https://github.com/dropbox/rust-brotli-decompressor/commit/"
            "cc7ee0edae39870daa7f0d7c1456e113b759e752"
        ),
    },
}
ISSUE_RELATION = "analogous_independent_implementation"
ROLES = ("Literal", "Command", "Distance")


def verify_identity(entry: dict, data: bytes) -> str | None:
    if len(data) != entry["size"]:
        return "source size mismatch"
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        return "SHA-256 mismatch"
    blob = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    if hashlib.sha1(blob, usedforsecurity=False).hexdigest() != entry["git_blob"]:
        return "Git blob mismatch"
    return None


def implementation(entry: dict) -> str:
    return entry.get("implementation", LEGACY_C)


def verify_metadata(entry: dict) -> str | None:
    selected = implementation(entry)
    if selected == LEGACY_C:
        return None
    expected = PORT_METADATA.get(selected)
    if expected is None:
        return "unsupported registry implementation"
    if entry.get("component") != expected["component"]:
        return "implementation component mismatch"
    if entry.get("issue_relation") != ISSUE_RELATION:
        return "implementation issue relation mismatch"
    if entry.get("upstream_fix") != expected["upstream_fix"]:
        return "implementation upstream fix mismatch"
    return None


def verify_c_pattern(entry: dict, data: bytes) -> str | None:
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


def verify_go_pattern(entry: dict, data: bytes) -> str | None:
    code = data.decode("utf-8")
    normalized = " ".join(code.split())
    old_helper = "func decodeBlockTypeAndLength(safe int, s *Reader, tree_type int) bool {"
    fixed_helper = "func decodeBlockTypeAndLength(safe int, s *Reader, tree_type int) int {"
    old_guard = "if max_block_type <= 1 { return false"
    fixed_guard = "if max_block_type <= 1 { return decoderErrorFormatBlockSwitch"
    old_wrappers = all(
        f"func decode{role}BlockSwitchInternal(safe int, s *Reader) bool {{" in normalized
        for role in ROLES
    )
    fixed_wrappers = all(
        f"func decode{role}BlockSwitchInternal(safe int, s *Reader) int {{" in normalized
        for role in ROLES
    )
    if entry["state"] == "vulnerable":
        old_callers = all(
            f"if !safeDecode{role}BlockSwitch(s) {{ result = decoderNeedsMoreInput" in normalized
            and f"}} else {{ decode{role}BlockSwitch(s) }}" in normalized
            for role in ROLES
        )
        if not (
            old_helper in normalized and old_guard in normalized and old_wrappers and old_callers
        ):
            return "vulnerable Go block-switch pattern not found"
    elif entry["state"] == "fixed":
        fixed_callers = all(
            f"status = safeDecode{role}BlockSwitch(s)" in normalized
            and f"status = decode{role}BlockSwitch(s)" in normalized
            for role in ROLES
        )
        if not (
            fixed_helper in normalized
            and fixed_guard in normalized
            and fixed_wrappers
            and fixed_callers
            and normalized.count("if status != decoderSuccess") >= GO_STATUS_CALLS
        ):
            return "fixed Go block-switch propagation not found"
    else:
        return "unsupported registry state"
    return None


def rust_function_returns(normalized: str, name: str, return_type: str) -> bool:
    pattern = re.compile(
        rf"\bfn\s+{name}\b.{{0,1200}}?input\s*:\s*&\[u8\]\s*\)\s*"
        rf"->\s*{re.escape(return_type)}\s*\{{"
    )
    return pattern.search(normalized) is not None


def verify_rust_pattern(entry: dict, data: bytes) -> str | None:
    normalized = " ".join(data.decode("utf-8").split())
    old_helper = rust_function_returns(normalized, "DecodeBlockTypeAndLength", "bool")
    fixed_helper = rust_function_returns(
        normalized, "DecodeBlockTypeAndLength", "BrotliDecoderErrorCode"
    )
    old_wrappers = all(
        rust_function_returns(normalized, f"Decode{role}BlockSwitchInternal", "bool")
        for role in ROLES
    )
    fixed_wrappers = all(
        rust_function_returns(
            normalized, f"Decode{role}BlockSwitchInternal", "BrotliDecoderErrorCode"
        )
        for role in ROLES
    )
    old_guard = "if max_block_type <= 1 { return false"
    fixed_guard = "return BrotliDecoderErrorCode::BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH"
    if entry["state"] == "vulnerable":
        old_calls = (
            "if !DecodeCommandBlockSwitchInternal(safe, s, input)",
            "if (!DecodeLiteralBlockSwitchInternal(safe, s, input)) && safe",
            "if (!DecodeDistanceBlockSwitchInternal(safe, s, input)) && safe",
        )
        if not (
            old_helper
            and old_guard in normalized
            and old_wrappers
            and all(call in normalized for call in old_calls)
        ):
            return "vulnerable Rust block-switch pattern not found"
    elif entry["state"] == "fixed":
        fixed_calls = tuple(
            f"match Decode{role}BlockSwitchInternal(safe, s, input)" for role in ROLES
        )
        if not (
            fixed_helper
            and fixed_guard in normalized
            and fixed_wrappers
            and all(call in normalized for call in fixed_calls)
        ):
            return "fixed Rust block-switch propagation not found"
    else:
        return "unsupported registry state"
    return None


def verify_pattern(entry: dict, data: bytes) -> str | None:
    """Check reviewed source-shape provenance; exact hashes own scanner classification."""
    selected = implementation(entry)
    if selected == LEGACY_C:
        return verify_c_pattern(entry, data)
    if selected == GO_PORT:
        return verify_go_pattern(entry, data)
    if selected == RUST_PORT:
        return verify_rust_pattern(entry, data)
    return "unsupported registry implementation"


def source_suffix(entry: dict) -> str:
    return {GO_PORT: ".go", RUST_PORT: ".rs"}.get(implementation(entry), ".c")


def expected_source_status(entry: dict) -> str:
    if implementation(entry) == LEGACY_C:
        return "vulnerable_source" if entry["state"] == "vulnerable" else "fixed_source"
    return "affected_port_source" if entry["state"] == "vulnerable" else "fixed_port_source"


def verify_classifications(entry: dict, data: bytes, registry: dict) -> str | None:
    selected = implementation(entry)
    expected = expected_source_status(entry)
    modified_expected = (
        "potentially_vulnerable"
        if selected == LEGACY_C and entry["state"] == "vulnerable"
        else "unknown"
    )
    for content, status, modified in (
        (data, expected, False),
        (data + b"\n/* Verification-only annotation. */\n", modified_expected, True),
    ):
        result = checker.Inventory(registry, 1 << 24, 1 << 28, 100, 2)
        result.inspect(content, entry["sources"][0]["label"] + source_suffix(entry), 0)
        statuses = {finding["patch_status"] for finding in result.findings}
        if status not in statuses:
            return "expected decoder classification not found"
        if selected != LEGACY_C and statuses.intersection({"fixed_source", "vulnerable_source"}):
            return "independent port source received a Google C classification"
        if modified and statuses.intersection(
            {"fixed_source", "vulnerable_source", "affected_port_source", "fixed_port_source"}
        ):
            return "modified source retained an exact classification"
        if (
            modified
            and selected != LEGACY_C
            and not any(
                finding["kind"] == "decoder_source_candidate"
                and finding["patch_status"] == "unknown"
                for finding in result.findings
            )
        ):
            return "modified port source lead not found"
        if any(finding["reachability"] != "unknown" for finding in result.findings):
            return "source evidence incorrectly established reachability"
    return None


def verify_reference(entry: dict, *, registry: dict) -> str | None:
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
            verify_metadata(entry)
            or verify_identity(entry, data)
            or verify_pattern(entry, data)
            or verify_classifications(entry, data, registry)
        )
        if error:
            return f"{label}: {error}"
    except (OSError, ValueError, KeyError, TypeError) as error:
        return f"{label}: {type(error).__name__}: {error}"
    else:
        return None


def main() -> int:
    registry = json.loads(checker.REGISTRY.read_text(encoding="utf-8"))
    verify = partial(verify_reference, registry=registry)
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
