import contextlib
import gzip
import io
import json
import struct
import subprocess
import sys
from pathlib import Path

import brotli_binary_inventory as binary
import brotli_binary_match as matcher
import brotli_inventory as scanner
import pytest
from test_binary_match import elf, reference


def test_elf_slices_enforce_exact_file_bounds():
    assert matcher.checked_slice(b"abc", 0, 3) == b"abc"
    assert matcher.checked_slice(b"abc", 3, 0) == b""
    assert matcher.checked_slice(b"abc", 0, 0) == b""
    for offset, size in ((-1, 1), (0, -1), (4, 0), (3, 1), (0, 4)):
        with pytest.raises(ValueError, match="outside file"):
            matcher.checked_slice(b"abc", offset, size)


@pytest.mark.parametrize(
    ("offset", "encoding", "value"),
    [(4, "B", 1), (5, "B", 2), (6, "B", 2), (18, "H", 3), (20, "I", 2), (52, "H", 63)],
)
def test_each_unsupported_elf_header_field_is_rejected(offset, encoding, value):
    data = bytearray(elf(b"instructions"))
    struct.pack_into("<" + encoding, data, offset, value)
    with pytest.raises(ValueError, match="Only little-endian"):
        matcher.elf_header(bytes(data))


def test_reference_size_and_mask_density_boundaries():
    entry = reference()
    entry.update(code=entry["code"][:512], mask="ff" * 256)
    assert len(matcher.CodeReference.from_json(entry).code) == 256
    for change in ({"code": entry["code"][:-2]}, {"mask": entry["mask"] + "ff"}):
        with pytest.raises(ValueError, match="equal code/mask"):
            matcher.CodeReference.from_json({**entry, **change})
    entry["mask"] = "ff" * 192 + "00" * 64
    assert matcher.CodeReference.from_json(entry).mask.count(255) == 192
    with pytest.raises(ValueError, match="masks too much"):
        matcher.CodeReference.from_json({**entry, "mask": "ff" * 191 + "00" * 65})


def test_nonzero_anchor_offset_stays_within_executable_range():
    entry = reference()
    entry["mask"] = "00" * 64 + "ff" * 448
    ref = matcher.CodeReference.from_json(entry)
    assert ref.anchor_offset == 64
    data = b"prefix" + ref.code + b"overlay"
    assert list(matcher.candidate_offsets(data, ref, 6, len(ref.code))) == [6]
    assert list(matcher.candidate_offsets(data, ref, 6, len(ref.code) - 1)) == []
    assert list(matcher.candidate_offsets(data, ref, 7, len(ref.code))) == []


def test_binary_name_only_candidates_and_escaped_catalog(tmp_path):
    named = tmp_path / "libbrotli.so"
    named.write_bytes(b"opaque stripped candidate")
    unrelated = tmp_path / "notes.txt"
    unrelated.write_text("ordinary text")
    inventory = binary.BinaryInventory(
        {},
        [],
        max_file_bytes=100,
        max_total_bytes=1000,
        max_files=100,
        archive_depth=2,
    )
    inventory.scan_roots([named, unrelated])
    evidence = [row for row in inventory.findings if row["kind"] == "binary_candidate"]
    assert len(evidence) == 1
    assert evidence[0]["path"] == str(named)
    assert evidence[0]["patch_status"] == "not_assessed"
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({evidence[0]["sha256"]: "\x1b[2Jfake\udcff"}))
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert binary.main([str(named), "--catalog", str(catalog)]) == 1
    assert "\x1b" not in output.getvalue()
    assert "\\u001b" in output.getvalue()
    report = json.loads(output.getvalue())
    assert report["coverage"]["symlinks_followed"] is False
    assert report["coverage"]["gap_details_omitted"] == 0


def test_stream_expansion_respects_remaining_total_budget():
    inventory = scanner.Inventory(
        {"fingerprints": []},
        max_file_bytes=100,
        max_total_bytes=20,
        max_files=10,
        archive_depth=2,
    )
    inventory.bytes_read = 10
    inventory.inspect_archive(gzip.compress(b"a" * 15), "layer.gz", 0, "gzip")
    assert inventory.expanded_items_read == 0
    assert inventory.bytes_read == 21  # One extra byte establishes that the bound was exceeded.
    assert inventory.gap_count == 1


@pytest.mark.parametrize(
    "script", ["brotli_inventory.py", "brotli_binary_inventory.py", "brotli_binary_triage.py"]
)
def test_standalone_cli_bootstrap_displays_help(script):
    path = Path(scanner.__file__).parent / script
    result = subprocess.run(  # noqa: S603 -- Trusted maintainer CLI, never target artifacts.
        [sys.executable, str(path), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "usage:" in result.stdout
    expected = "--max-range-bytes" if script == "brotli_binary_triage.py" else "--code-references"
    assert expected in result.stdout
