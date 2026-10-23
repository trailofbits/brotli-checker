import contextlib
import hashlib
import io
import json
import runpy
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1] / "skills/brotli-checker/scripts/brotli_binary_inventory.py"
)


def run_scan(*arguments):
    stdout, stderr = io.StringIO(), io.StringIO()
    with (
        patch.object(sys, "argv", [str(SCRIPT), *map(str, arguments)]),
        patch.object(sys, "path", [str(SCRIPT.parent), *sys.path]),
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
        pytest.raises(SystemExit) as result,
    ):
        runpy.run_path(str(SCRIPT), run_name="__main__")
    return SimpleNamespace(
        returncode=result.value.code, stdout=stdout.getvalue(), stderr=stderr.getvalue()
    )


@pytest.mark.parametrize("magic", [b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\0asm", b"!<arch>\n"])
def test_native_indicators_are_not_patch_verdicts(tmp_path, magic):
    artifact = tmp_path / "application"
    data = magic + b"\0BrotliDecoderDecompress\0"
    artifact.write_bytes(data)
    result = run_scan(artifact)
    assert result.returncode == 1
    finding = json.loads(result.stdout)["findings"][0]
    assert finding["sha256"] == hashlib.sha256(data).hexdigest()
    assert finding["patch_status"] == "not_assessed"
    assert finding["linkage"] == "unknown"
    assert artifact.read_bytes() == data


def test_catalog_matches_even_without_indicators(tmp_path):
    artifact = tmp_path / "application"
    artifact.write_bytes(b"exact known artifact")
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({hashlib.sha256(artifact.read_bytes()).hexdigest(): "build-123"}))
    result = run_scan(artifact, "--catalog", catalog)
    assert result.returncode == 1
    finding = json.loads(result.stdout)["findings"][0]
    assert finding["kind"] == "exact_artifact_match"
    assert finding["catalog_label"] == "build-123"
    artifact.write_bytes(b"different build")
    result = run_scan(artifact, "--catalog", catalog)
    assert result.returncode == 0
    assert json.loads(result.stdout)["findings"] == []


def test_bundled_named_stripped_library(tmp_path):
    archive = tmp_path / "app.whl"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("native/libbrotlidec.so.1", b"\x7fELF\0stripped")
    result = run_scan(archive)
    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert len(findings) == 1
    assert findings[0]["path"].endswith("app.whl!native/libbrotlidec.so.1")
    assert findings[0]["sha256"]
    assert list(tmp_path.iterdir()) == [archive]


def test_named_read_and_unread_findings_share_the_binary_schema(tmp_path):
    readable = tmp_path / "libbrotli.dll"
    readable.write_bytes(b"MZ")
    unread = tmp_path / "libbrotli.so"
    unread.write_bytes(b"too large")
    result = run_scan(tmp_path, "--max-file-bytes", "4")
    assert result.returncode == 3
    findings = json.loads(result.stdout)["findings"]
    assert len(findings) == 2
    assert set(findings[0]) == set(findings[1])
    by_path = {finding["path"]: finding for finding in findings}
    assert by_path[str(readable)]["sha256"] == hashlib.sha256(b"MZ").hexdigest()
    assert by_path[str(unread)]["sha256"] is None
    assert by_path[str(unread)]["code_assessment"] == "Content was not inspected; filename only"


def test_report_records_default_and_effective_limits(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("nothing to inventory")
    default_report = json.loads(run_scan(path).stdout)
    assert default_report["coverage"]["limits"] == {
        "max_file_bytes": 128 * 1024 * 1024,
        "max_total_bytes": 1024 * 1024 * 1024,
        "max_files": 100000,
        "archive_depth": 2,
    }
    custom_report = json.loads(
        run_scan(
            path,
            "--max-file-bytes",
            "10",
            "--max-total-bytes",
            "20",
            "--max-files",
            "30",
            "--archive-depth",
            "4",
        ).stdout
    )
    assert custom_report["coverage"]["limits"] == {
        "max_file_bytes": 10,
        "max_total_bytes": 20,
        "max_files": 30,
        "archive_depth": 4,
    }


@pytest.mark.parametrize("catalog", [[], {"bad": "build"}, {"a" * 64: 123}, {"a" * 64: ""}])
def test_invalid_catalog(tmp_path, catalog):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog))
    result = run_scan(tmp_path, "--catalog", path)
    assert result.returncode == 2
    assert "Catalog must map" in result.stderr


def test_limits_missing_roots_and_symlinks_are_gaps(tmp_path):
    artifact = tmp_path / "application"
    artifact.write_bytes(b"\x7fELF\0BrotliDecoderDecompress")
    link = tmp_path / "link"
    link.symlink_to(artifact)
    for arguments in ((artifact, "--max-file-bytes", "1"), (tmp_path / "missing",), (link,)):
        result = run_scan(*arguments)
        assert result.returncode == 3
        assert json.loads(result.stdout)["coverage"]["gap_count"] == 1


def test_text_mentions_are_not_native_binary_evidence(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("BrotliDecoderDecompress is an API")
    result = run_scan(path)
    assert result.returncode == 0
    assert json.loads(result.stdout)["findings"] == []


def test_corrupt_archive_and_depth_limit(tmp_path):
    path = tmp_path / "app.zip"
    path.write_bytes(b"broken archive")
    result = run_scan(path)
    assert result.returncode == 3
    assert "Cannot inspect archive" in json.loads(result.stdout)["coverage"]["gaps"][0]["reason"]
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("libbrotli.so", b"\x7fELF")
    result = run_scan(path, "--archive-depth", "0")
    assert result.returncode == 3
    assert "nesting limit" in json.loads(result.stdout)["coverage"]["gaps"][0]["reason"]


def test_nested_bundle_and_multiple_root_budget(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("application", b"\x7fELF\0BrotliDecoderVersion")
    outer = tmp_path / "app.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("nested.zip", inner.getvalue())
    result = run_scan(outer)
    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["findings"][0]["path"].endswith("app.zip!nested.zip!application")
    assert report["coverage"]["archives_opened"] == 2
    result = run_scan(outer, tmp_path / "second", "--max-files", "1")
    assert result.returncode == 3
    assert json.loads(result.stdout)["coverage"]["gap_count"] == 2
