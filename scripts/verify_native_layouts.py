#!/usr/bin/env python3
# ruff: noqa: C901, EM101, EM102, PLR2004, S310, TRY003
"""Explicitly download and verify SHA-pinned PE/Mach-O parser fixtures; never execute them."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))
from brotli_binary_layout import inspect_layout  # noqa: E402
from brotli_binary_signatures import CODE_LENGTH_TABLES, recognize_decoder_data  # noqa: E402

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_INDEX_BYTES = 8 * 1024 * 1024
MAX_WHEEL_BYTES = 16 * 1024 * 1024
FIELDS = {
    "id",
    "project_json_url",
    "filename",
    "size",
    "sha256",
    "member",
    "member_size",
    "member_sha256",
    "release",
    "reviewed_source_state",
    "target_patch_status",
    "expected_layouts",
}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_manifest(path: Path) -> list[dict]:
    raw = path.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("native fixture manifest exceeds byte limit")
    document = json.loads(raw)
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 1
        or not isinstance(document.get("fixtures"), list)
        or not document["fixtures"]
    ):
        raise ValueError("invalid native fixture manifest")
    ids = set()
    for fixture in document["fixtures"]:
        if not isinstance(fixture, dict) or set(fixture) != FIELDS:
            raise ValueError("invalid native fixture fields")
        if fixture["id"] in ids or fixture["target_patch_status"] != "unknown":
            raise ValueError("duplicate fixture or unsafe binary patch-state claim")
        ids.add(fixture["id"])
        for field in ("sha256", "member_sha256"):
            value = fixture[field]
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)
            ):
                raise ValueError(f"invalid native fixture {field}")
        if fixture["reviewed_source_state"] not in ("fixed", "vulnerable"):
            raise ValueError("invalid reviewed source provenance")
        if not isinstance(fixture["expected_layouts"], list) or not fixture["expected_layouts"]:
            raise ValueError("native fixture lacks expected layouts")
    return document["fixtures"]


def _download(url: str, limit: int) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": "brotli-checker-layout-verifier/1"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"download exceeds {limit}-byte limit")
    return data


def acquire(fixture: dict, cache: Path, *, download: bool) -> bytes:
    target = cache / fixture["filename"]
    if target.is_file():
        data = target.read_bytes()
    elif download:
        index = json.loads(_download(fixture["project_json_url"], MAX_INDEX_BYTES))
        candidates = [
            row for row in index.get("urls", []) if row.get("filename") == fixture["filename"]
        ]
        if (
            len(candidates) != 1
            or candidates[0].get("digests", {}).get("sha256") != fixture["sha256"]
        ):
            raise ValueError("PyPI metadata does not bind expected wheel")
        data = _download(candidates[0]["url"], MAX_WHEEL_BYTES)
        cache.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    else:
        raise ValueError(f"missing cached fixture: {target}; pass --download explicitly")
    if len(data) != fixture["size"] or _digest(data) != fixture["sha256"]:
        raise ValueError(f"wheel identity mismatch: {fixture['id']}")
    return data


def summarize(item: dict) -> dict:
    return {
        "machine": item["machine"],
        "mapped": len(item["ranges"]["mapped"]),
        "executable": len(item["ranges"]["executable"]),
        "data": len(item["ranges"]["data"]),
        "resources": len(item["ranges"]["resources"]),
        "imports": len(item["imports"]),
        "exports": len(item["exports"]),
        "functions": len(item["functions"]),
        "dependencies": len(item["dependencies"]),
    }


def verify_fixture(fixture: dict, wheel: bytes) -> dict:
    from io import BytesIO  # noqa: PLC0415 -- Keep verifier imports minimal.

    with zipfile.ZipFile(BytesIO(wheel)) as archive:
        if archive.namelist().count(fixture["member"]) != 1:
            raise ValueError("wheel does not contain exactly one expected native member")
        member = archive.read(fixture["member"])
    if len(member) != fixture["member_size"] or _digest(member) != fixture["member_sha256"]:
        raise ValueError("native member identity mismatch")
    layout = inspect_layout(member)
    layouts = layout["slices"] or [layout]
    actual = [summarize(item) for item in layouts]
    if actual != fixture["expected_layouts"] or any(item["gaps"] for item in layouts):
        raise ValueError(f"native layout mismatch: {fixture['id']}")
    recognition = recognize_decoder_data(member)
    if recognition["limited"] or recognition["scope"] != "loader_data_ranges":
        raise ValueError(f"decoder table layout scope incomplete: {fixture['id']}")
    table_results = []
    for index, item in enumerate(layouts):
        rows = [
            row
            for row in recognition["matches"]
            if not layout["slices"] or row.get("slice_index") == index
        ]
        accepted = {row["id"] for row in rows}
        if accepted != {"command_lut_le", *CODE_LENGTH_TABLES}:
            raise ValueError(f"decoder table scope mismatch: {fixture['id']}:{item['machine']}")
        table_results.append({"machine": item["machine"], "signatures": sorted(accepted)})
    return {"id": fixture["id"], "layouts": actual, "table_signatures": table_results}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "tests/native_fixtures.json")
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument(
        "--download", action="store_true", help="explicitly permit primary-source downloads"
    )
    args = parser.parse_args()
    fixtures = load_manifest(args.manifest)
    results = [
        verify_fixture(item, acquire(item, args.cache_dir, download=args.download))
        for item in fixtures
    ]
    print(json.dumps({"verified": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
