"""Check sparse binary access against the bytes and file interfaces it implements."""

import hashlib
import io
import os
from itertools import product

import brotli_binary_data as binary_data
import pytest


@pytest.fixture
def sparse_data(tmp_path, monkeypatch):
    # Small chunks exercise overlapping searches and reads spanning several chunks.
    monkeypatch.setattr(binary_data, "COPY_CHUNK_BYTES", 3)
    monkeypatch.setattr(binary_data, "SEARCH_CHUNK_BYTES", 3)
    content = b"\x00ababa\xff0123"
    path = tmp_path / "binary"
    path.write_bytes(content)
    with path.open("rb") as stream, binary_data.file_data(stream) as data:
        yield content, data


def test_sparse_indexing_matches_bytes(sparse_data):
    content, data = sparse_data
    for index in range(-len(content) - 1, len(content) + 1):
        if -len(content) <= index < len(content):
            assert data[index] == content[index]
        else:
            with pytest.raises(IndexError):
                data[index]
    bounds = (None, -20, -len(content), -1, 0, 1, len(content), 20)
    for start, stop, step in product(bounds, bounds, (-3, -1, 1, 2, 3)):
        key = slice(start, stop, step)
        assert data[key] == content[key], key
    with pytest.raises(ValueError, match="slice step"):
        data[::0]


def test_sparse_find_obeys_bytes_bounds_and_chunk_overlap(sparse_data):
    content, data = sparse_data
    bounds = (-20, -len(content), -1, 0, 1, len(content), 20)
    for needle, start, end in product(
        (b"", b"\x00", b"a", b"aba", b"baba\xff0", content, b"missing"),
        bounds,
        (*bounds, None),
    ):
        assert data.find(needle, start, end) == content.find(needle, start, end), (
            needle,
            start,
            end,
        )


def test_sparse_prefix_and_membership_match_bytes(sparse_data):
    content, data = sparse_data
    for needle in (b"", b"a", b"\x00", b"aba", b"missing", b"\xff", content):
        assert (needle in data) == (needle in content)
        assert (bytearray(needle) in data) == (needle in content)
        assert (memoryview(needle) in data) == (needle in content)
    for needle in (0, 1, 97, 254, 255):
        assert (needle in data) == (needle in content)
    for needle in (-1, 256):
        with pytest.raises(ValueError, match="range"):
            assert needle not in data
    with pytest.raises(TypeError, match="bytes-like"):
        assert "a" not in data
    for prefix, start, end in product(
        (b"", b"\x00", b"aba", content, b"missing", (b"missing", b"\x00")),
        (-20, -1, 0, 1, len(content), len(content) + 1),
        (None, -1, 0, 3, len(content), 20),
    ):
        assert data.startswith(prefix, start, end) == content.startswith(prefix, start, end)


def test_sparse_validated_ranges_and_seek_match_file(sparse_data):
    content, data = sparse_data
    for offset in range(len(content) + 1):
        for size in range(len(content) - offset + 1):
            assert data.read_at(offset, size) == content[offset : offset + size]
    for offset, size in ((-1, 0), (0, -1), (len(content) + 1, 0), (len(content), 1)):
        with pytest.raises(ValueError, match="outside file"):
            data.read_at(offset, size)
    expected = io.BytesIO(content)
    for whence, offset, size in (
        (io.SEEK_SET, 0, 0),
        (io.SEEK_SET, 0, 1),
        (io.SEEK_CUR, 2, 3),
        (io.SEEK_CUR, -2, -1),
        (io.SEEK_END, -1, 10),
        (io.SEEK_END, 0, 1),
        (io.SEEK_SET, len(content) + 5, 1),
    ):
        assert data.seek(offset, whence) == expected.seek(offset, whence)
        assert data.read(size) == expected.read(size)
        assert data.tell() == expected.tell()
    with pytest.raises(ValueError, match="whence"):
        data.seek(0, 99)
    assert data.readable() is True
    assert data.seekable() is True
    assert data.writable() is False
    assert data.closed is False


def test_sparse_hash_covers_every_chunk_without_moving_cursor(sparse_data):
    content, data = sparse_data
    data.seek(2)
    assert binary_data.sha256_data(data) == hashlib.sha256(content).hexdigest()
    assert binary_data.sha256_data(content) == hashlib.sha256(content).hexdigest()
    assert data.tell() == 2


def test_file_lifetime_and_explicit_limit_equality(tmp_path):
    path = tmp_path / "binary"
    path.write_bytes(b"x")
    with path.open("rb") as stream, binary_data.file_data(stream, max_bytes=1) as data:
        descriptor = data.fileno()
        assert data[0] == ord("x")
    assert data.closed is True
    data.close()
    with pytest.raises(ValueError, match="closed"):
        data.fileno()
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(descriptor)
    path.write_bytes(b"")
    with path.open("rb") as stream, binary_data.file_data(stream, max_bytes=0) as empty:
        assert empty.read() == b""


def test_stream_limit_accepts_exact_size_and_checks_across_chunks(monkeypatch):
    monkeypatch.setattr(binary_data, "COPY_CHUNK_BYTES", 3)
    monkeypatch.setattr(binary_data, "SMALL_BYTES_LIMIT", 4)
    for length in (0, 1, 3, 4, 5, 9):
        content = bytes(range(length))
        with binary_data.read_data(io.BytesIO(content), max_bytes=length) as data:
            assert data[:] == content
        with (
            pytest.raises(binary_data.DataLimitError) as stopped,
            binary_data.read_data(io.BytesIO(content + b"x"), max_bytes=length),
        ):
            pass
        assert (stopped.value.limit, stopped.value.bytes_read) == (length, length + 1)
