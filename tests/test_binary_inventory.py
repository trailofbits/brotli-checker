import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import brotli_binary_inventory as binary_inventory
import pytest
from test_binary_layout import pe_fixture

SCRIPT = (
    Path(__file__).resolve().parents[1] / "skills/brotli-checker/scripts/brotli_binary_inventory.py"
)
sys.path.insert(0, str(SCRIPT.parent))
import brotli_binary_data as binary_data  # noqa: E402
import brotli_binary_match as binary_match  # noqa: E402


def _reference_temp_parent(arguments):
    scanned_directories = []
    for argument in arguments:
        path = Path(str(argument))
        if path.is_dir():
            scanned_directories.append(path.resolve())
    candidates = [Path(tempfile.gettempdir()).resolve(), SCRIPT.parents[3].parent.resolve()]
    for candidate in candidates:
        if not any(
            candidate == root or candidate.is_relative_to(root) for root in scanned_directories
        ):
            return candidate
    msg = "Cannot place the test reference catalog outside the scanned roots"
    raise RuntimeError(msg)


def _write_small_reference_catalog(path):
    references = []
    for machine, bits, byteorder in sorted(binary_match.TARGETS):
        identity = f"{machine}-{bits}-{byteorder}"
        digest = hashlib.sha256(("test-only-reference-" + identity).encode()).digest()
        references.append(
            {
                "id": "test-only-" + identity,
                "state": "fixed",
                "machine": machine,
                "elf_class": bits,
                "byteorder": byteorder,
                "source_sha256": "a" * 64,
                "object_sha256": "b" * 64,
                "source": "Synthetic test-only non-Brotli reference",
                "compiler": "test fixture",
                "flags": "test fixture",
                "code": (digest * 8).hex(),
                "mask": (b"\xff" * 256).hex(),
            }
        )
    path.write_text(json.dumps({"schema_version": 1, "references": references}))


def run_scan(*arguments):
    if not any(str(arg) in {"--flirt", "--flirt-references", "--no-flirt"} for arg in arguments):
        arguments = (*arguments, "--no-flirt")
    # Reference fixtures contain arbitrary bytes, not an instruction-decoding corpus.
    arguments = (*arguments, "--no-xrefs")
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.ExitStack() as stack:
        if "--code-references" not in map(str, arguments) and not any(
            str(argument).startswith("--code-references=") for argument in arguments
        ):
            directory = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(
                        prefix="brotli-test-references-",
                        dir=_reference_temp_parent(arguments),
                    )
                )
            )
            references = directory / "references.json"
            _write_small_reference_catalog(references)
            arguments = (*arguments, "--code-references", references)
        stack.enter_context(contextlib.redirect_stdout(stdout))
        stack.enter_context(contextlib.redirect_stderr(stderr))
        try:
            code = binary_inventory.main(list(map(str, arguments)))
        except SystemExit as result:
            code = result.code
    return SimpleNamespace(returncode=code, stdout=stdout.getvalue(), stderr=stderr.getvalue())


def test_default_test_references_are_outside_the_scan_and_ephemeral(tmp_path, monkeypatch):
    (tmp_path / "notes.txt").write_text("nothing to inventory")
    written = []
    original = _write_small_reference_catalog

    def tracked(path):
        written.append(path)
        assert not path.is_relative_to(tmp_path)
        original(path)

    monkeypatch.setattr(sys.modules[__name__], "_write_small_reference_catalog", tracked)
    assert run_scan(tmp_path).returncode == 0
    assert len(written) == 1
    assert not written[0].exists()


@pytest.mark.parametrize("magic", [b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\0asm", b"!<arch>\n"])
def test_native_indicators_are_not_patch_verdicts(tmp_path, magic):
    artifact = tmp_path / "application"
    data = magic + b"\0BrotliDecoderDecompress\0"
    artifact.write_bytes(data)
    result = run_scan(artifact)
    assert result.returncode == 3  # Magic plus a string is not a valid binary layout.
    assert json.loads(result.stdout)["coverage"]["gap_count"] > 0
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


def test_bundled_named_truncated_library_reports_uninspected_structure(tmp_path):
    archive = tmp_path / "app.whl"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("native/libbrotlidec.so.1", b"\x7fELF\0stripped")
    result = run_scan(archive)
    assert result.returncode == 3
    assert json.loads(result.stdout)["coverage"]["gap_count"] > 0
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
    assert default_report["coverage"]["expanded_items_read"] == 0
    assert default_report["coverage"]["expanded_bytes_read"] == 0
    assert default_report["coverage"]["limits"] == {
        "max_file_bytes": None,
        "max_total_bytes": None,
        "max_expanded_bytes": 8 * 1024 * 1024 * 1024,
        "max_total_expanded_bytes": 64 * 1024 * 1024 * 1024,
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
            "--max-expanded-bytes",
            "40",
            "--max-total-expanded-bytes",
            "50",
            "--max-files",
            "30",
            "--archive-depth",
            "4",
        ).stdout
    )
    assert custom_report["coverage"]["limits"] == {
        "max_file_bytes": 10,
        "max_total_bytes": 20,
        "max_expanded_bytes": 40,
        "max_total_expanded_bytes": 50,
        "max_files": 30,
        "archive_depth": 4,
    }


def test_native_file_larger_than_old_default_uses_sparse_file_view(tmp_path, monkeypatch):
    artifact = tmp_path / "libbrotli.dll"
    with artifact.open("wb") as stream:
        stream.write(pe_fixture())
        stream.write(b"\0BrotliDecoderDecompress\0")
        stream.truncate(129 * 1024 * 1024)
    assert artifact.stat().st_blocks * 512 < artifact.stat().st_size

    def no_spool(*args, **kwargs):
        del args, kwargs
        pytest.fail("regular files must not be copied to a temporary file")

    monkeypatch.setattr(binary_data.tempfile, "TemporaryFile", no_spool)
    result = run_scan(artifact)
    report = json.loads(result.stdout)
    assert result.returncode == 1
    assert report["coverage"]["gap_count"] == 0
    assert report["coverage"]["bytes_read"] == artifact.stat().st_size
    assert report["findings"][0]["size_bytes"] == artifact.stat().st_size


@pytest.mark.skipif(
    not os.environ.get("BROTLI_LARGE_FILE_TESTS"),
    reason="set BROTLI_LARGE_FILE_TESTS=1 for the optional >1 GiB sparse regression",
)
def test_default_total_reads_can_exceed_one_gibibyte(tmp_path):
    for name in ("libbrotli-a.dll", "libbrotli-b.dll"):
        path = tmp_path / name
        with path.open("wb") as stream:
            stream.write(pe_fixture())
            stream.truncate(513 * 1024 * 1024)
    result = run_scan(tmp_path)
    report = json.loads(result.stdout)
    assert result.returncode == 1
    assert report["coverage"]["gap_count"] == 0
    assert report["coverage"]["bytes_read"] > 1024 * 1024 * 1024


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
    assert result.returncode == 3  # Truncated ELF headers cannot scope structural recognition.
    report = json.loads(result.stdout)
    assert report["findings"][0]["path"].endswith("app.zip!nested.zip!application")
    assert report["coverage"]["archives_opened"] == 2
    assert report["coverage"]["expanded_items_read"] == 2
    assert report["coverage"]["expanded_bytes_read"] >= len(inner.getvalue())
    result = run_scan(outer, tmp_path / "second", "--max-files", "1")
    assert result.returncode == 3
    assert json.loads(result.stdout)["coverage"]["gap_count"] == 2
