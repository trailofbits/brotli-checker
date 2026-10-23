import hashlib
import io
import os
import stat
import struct
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import BinaryIO, cast

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/brotli-checker/scripts"
sys.path.insert(0, str(SCRIPTS))
import brotli_binary_data as binary_data  # noqa: E402
import brotli_binary_match as matcher  # noqa: E402
import brotli_binary_metadata as metadata  # noqa: E402
from test_binary_match import elf, reference  # noqa: E402
from test_binary_metadata import elf_with_symbols, encoded_version, x86_return  # noqa: E402


def high_offset_fixture(path):
    from test_binary_metadata import CODE_ADDRESS, CODE_OFFSET  # noqa: PLC0415

    entry = reference(machine=matcher.EM_X86_64)
    code = bytes.fromhex(entry["code"])
    version = x86_return(encoded_version(1, 2, 1))
    contents = bytearray(
        elf_with_symbols(
            code + version,
            matcher.EM_X86_64,
            [
                {
                    "name": "BrotliDecoderVersion",
                    "address": CODE_ADDRESS + len(code),
                    "size": len(version),
                }
            ],
        )
    )
    header = matcher.elf_header(bytes(contents))
    delta = 6 * 1024**3
    struct.pack_into("<Q", contents, 40, header[6] + delta)
    struct.pack_into("<Q", contents, header[5] + 8, CODE_OFFSET + delta)
    for index in range(1, header[12]):
        location = header[6] + index * matcher.SECTION_HEADER.size + 24
        offset = struct.unpack_from("<Q", contents, location)[0]
        struct.pack_into("<Q", contents, location, offset + delta)
    with path.open("wb") as stream:
        stream.write(contents[:CODE_OFFSET])
        stream.seek(CODE_OFFSET + delta)
        stream.write(contents[CODE_OFFSET:])
    return entry, CODE_OFFSET + delta, CODE_OFFSET + delta + len(code)


def test_code_and_symbols_past_six_gibibytes_use_sparse_reads(tmp_path, monkeypatch):
    target = tmp_path / "large.elf"
    entry, code_offset, version_offset = high_offset_fixture(target)
    original = os.pread
    requests = []

    def measured_read(descriptor, size, offset):
        requests.append((offset, size))
        return original(descriptor, size, offset)

    monkeypatch.setattr(os, "pread", measured_read)
    with target.open("rb") as stream, binary_data.file_data(stream) as data:
        assessment = matcher.match_code(data, [matcher.CodeReference.from_json(entry)])
        versions = metadata.decoder_metadata(data)["versions"]
    assert assessment.matches[0]["file_offset"] == code_offset
    assert versions[0]["file_offset"] == version_offset
    assert versions[0]["version"] == "1.2.1"
    assert target.stat().st_size > 6 * 1024**3
    assert sum(size for _, size in requests) < 1024 * 1024


@pytest.mark.skipif(
    not os.environ.get("BROTLI_LARGE_FILE_TESTS"), reason="optional full 6 GiB hash pass"
)
def test_cli_scans_six_gibibyte_file_without_spooling(tmp_path, monkeypatch):
    from test_binary_inventory import run_scan  # noqa: PLC0415
    from test_binary_match import write_catalog  # noqa: PLC0415

    target = tmp_path / "large.elf"
    entry, code_offset, version_offset = high_offset_fixture(target)
    catalog = write_catalog(tmp_path, [entry])

    def forbid_spool(*args, **kwargs):
        del args, kwargs
        pytest.fail("regular-file inspection must not spool the file")

    monkeypatch.setattr(binary_data.tempfile, "TemporaryFile", forbid_spool)
    result = run_scan(target, "--code-references", catalog)
    import json  # noqa: PLC0415

    report = json.loads(result.stdout)
    assert result.returncode == 1
    assert report["coverage"]["gap_count"] == 0
    finding = report["findings"][0]
    assert finding["code_matches"][0]["file_offset"] == code_offset
    assert finding["decoder_metadata"]["versions"][0]["file_offset"] == version_offset
    with target.open("rb") as stream:
        assert finding["sha256"] == hashlib.file_digest(stream, "sha256").hexdigest()


def test_regular_file_access_is_sparse_filelike_and_hash_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(binary_data, "SEARCH_CHUNK_BYTES", 8)
    content = b"ELF-prefix: BrotliDecoderVersion :suffix"
    path = tmp_path / "binary"
    path.write_bytes(content)
    with path.open("rb") as stream, binary_data.file_data(stream) as data:
        assert len(data) == len(content)
        assert data.startswith(b"ELF")
        assert data.startswith((b"bad", b"ELF"))
        assert data.find(b"prefix") == content.find(b"prefix")
        assert b"DecoderVersion" in data
        assert ord("E") in data
        assert data[4:10] == content[4:10]
        assert data.tell() == 0
        assert data.read(3) == b"ELF"
        data.seek(0)
        assert binary_data.sha256_data(data) == hashlib.sha256(content).hexdigest()
        assert data.tell() == 0
        owned_fd = data.fileno()
    assert data.closed
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(owned_fd)


def test_file_data_does_not_call_stream_read(tmp_path):
    path = tmp_path / "binary"
    path.write_bytes(b"content")

    class NoRead:
        def __init__(self, source: BinaryIO) -> None:
            self.source = source

        def fileno(self) -> int:
            return self.source.fileno()

        def read(self, size: int = -1) -> bytes:
            del size
            pytest.fail("regular file data must use pread, not stream.read")

    with path.open("rb") as stream, binary_data.file_data(cast("BinaryIO", NoRead(stream))) as data:
        assert data[:4] == b"cont"


def test_negative_seek_matches_regular_file_error(tmp_path):
    path = tmp_path / "short"
    path.write_bytes(b"x")
    with path.open("rb") as stream, binary_data.file_data(stream) as data:
        with pytest.raises(OSError, match="Invalid argument") as stopped:
            data.seek(-22, io.SEEK_END)
        assert stopped.value.errno == 22


def test_filelike_eof_and_slice_semantics_match_bytes(tmp_path):
    content = b"0123456789"
    path = tmp_path / "binary"
    path.write_bytes(content)
    with path.open("rb") as stream, binary_data.file_data(stream) as data:
        for key in (slice(None, None, -1), slice(8, 1, -2), slice(-2, None, -3), slice(1, 8, 2)):
            assert data[key] == content[key]
        data.seek(100)
        assert data.read() == b""
        assert data.read(1) == b""
        assert data.tell() == 100


def test_file_mutation_is_detected_on_context_exit(tmp_path):
    path = tmp_path / "binary"
    path.write_bytes(b"original")

    def inspect_and_mutate() -> None:
        with path.open("rb") as stream, binary_data.file_data(stream) as data:
            assert data[:] == b"original"
            path.write_bytes(b"modified")

    with pytest.raises(binary_data.DataChangedError, match="changed"):
        inspect_and_mutate()


def test_small_sequential_stream_stays_bytes_and_boundary_is_inclusive(monkeypatch):
    monkeypatch.setattr(binary_data, "SMALL_BYTES_LIMIT", 8)
    for content in (b"", b"12345678"):
        stream = io.BytesIO(content)
        with binary_data.read_data(stream) as data:
            assert type(data) is bytes
            assert data == content
            assert binary_data.sha256_data(data) == hashlib.sha256(content).hexdigest()
        assert not stream.closed


def test_large_sequential_stream_spools_to_file_data(monkeypatch):
    monkeypatch.setattr(binary_data, "SMALL_BYTES_LIMIT", 8)
    content = b"a stream larger than eight bytes"
    with binary_data.read_data(io.BytesIO(content)) as data:
        assert isinstance(data, binary_data.FileData)
        assert data[:] == content
        assert binary_data.sha256_data(data) == hashlib.sha256(content).hexdigest()
        temporary = data
    assert temporary.closed


def test_explicit_limits_report_actual_bytes_read(tmp_path):
    with (
        pytest.raises(binary_data.DataLimitError) as stopped,
        binary_data.read_data(io.BytesIO(b"123456"), max_bytes=4),
    ):
        pytest.fail("over-limit stream must not be yielded")
    assert (stopped.value.limit, stopped.value.bytes_read) == (4, 5)

    path = tmp_path / "binary"
    path.write_bytes(b"123456")
    with (
        path.open("rb") as stream,
        pytest.raises(binary_data.DataLimitError) as stopped,
        binary_data.file_data(stream, max_bytes=4),
    ):
        pytest.fail("known over-limit file must not be yielded")
    assert (stopped.value.limit, stopped.value.bytes_read) == (4, 0)


def test_zero_and_invalid_limits():
    with binary_data.read_data(io.BytesIO(b""), max_bytes=0) as data:
        assert data == b""
    with (
        pytest.raises(binary_data.DataLimitError) as stopped,
        binary_data.read_data(io.BytesIO(b"x"), max_bytes=0),
    ):
        pass
    assert stopped.value.bytes_read == 1
    with (
        pytest.raises(ValueError, match="nonnegative"),
        binary_data.read_data(io.BytesIO(), max_bytes=-1),
    ):
        pass


def test_file_data_is_consumable_by_zip_and_tar(tmp_path):
    zipped = tmp_path / "archive.zip"
    with zipfile.ZipFile(zipped, "w") as archive:
        archive.writestr("member.txt", b"zip member")
    with (
        zipped.open("rb") as stream,
        binary_data.file_data(stream) as data,
        zipfile.ZipFile(cast("BinaryIO", data)) as archive,
    ):
        assert archive.read("member.txt") == b"zip member"

    tarred = tmp_path / "archive.tar"
    with tarfile.open(tarred, "w") as archive:
        info = tarfile.TarInfo("member.txt")
        info.size = len(b"tar member")
        archive.addfile(info, io.BytesIO(b"tar member"))
    with (
        tarred.open("rb") as stream,
        binary_data.file_data(stream) as data,
        tarfile.open(fileobj=cast("BinaryIO", data), mode="r:") as archive,
    ):
        member = archive.extractfile("member.txt")
        assert member is not None
        assert member.read() == b"tar member"


def test_temp_spool_is_private(tmp_path, monkeypatch):
    monkeypatch.setattr(binary_data, "SMALL_BYTES_LIMIT", 1)
    monkeypatch.setattr(binary_data.tempfile, "tempdir", str(tmp_path))
    with binary_data.read_data(io.BytesIO(b"spooled")) as data:
        assert isinstance(data, binary_data.FileData)
        metadata = os.fstat(data.fileno())
        assert stat.S_ISREG(metadata.st_mode)
        assert not metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)


def test_matcher_and_metadata_accept_sparse_file_data(tmp_path):
    entry = reference(machine=matcher.EM_AARCH64)
    reference_code = bytes.fromhex(entry["code"])
    target = tmp_path / "matched"
    target.write_bytes(elf(reference_code, matcher.EM_AARCH64))
    with target.open("rb") as stream, binary_data.file_data(stream) as data:
        assessment = matcher.match_code(data, [matcher.CodeReference.from_json(entry)])
        assert assessment.patch_status == "fixed_code_match"
        assert matcher.file_backed_ranges(data)[1] == [(120, len(reference_code))]

    version_target = tmp_path / "versioned"
    version_target.write_bytes(
        elf_with_symbols(
            x86_return(encoded_version(1, 2, 1)),
            matcher.EM_X86_64,
            [{"name": "BrotliDecoderVersion"}],
        )
    )
    with version_target.open("rb") as stream, binary_data.file_data(stream) as data:
        result = metadata.decoder_metadata(data)
        assert result["versions"][0]["version"] == "1.2.1"
