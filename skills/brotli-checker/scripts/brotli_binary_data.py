"""Sparse, read-only access to binary inputs with explicit temporary lifetimes."""

from __future__ import annotations

import errno
import hashlib
import io
import os
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO, overload

if TYPE_CHECKING:
    from collections.abc import Generator

SMALL_BYTES_LIMIT = 8 * 1024 * 1024
COPY_CHUNK_BYTES = 1024 * 1024
SEARCH_CHUNK_BYTES = 4 * 1024 * 1024
MAX_BYTE = 0xFF


class DataLimitError(ValueError):
    """A stream or regular file exceeded an explicit byte limit."""

    def __init__(self, limit: int, bytes_read: int) -> None:
        super().__init__(f"Binary input exceeds the explicit {limit}-byte limit")
        self.limit = limit
        self.bytes_read = bytes_read


class DataChangedError(OSError):
    """An open input changed while it was being inspected."""


@dataclass(frozen=True)
class _FileSignature:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> _FileSignature:
        return cls(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            size=metadata.st_size,
            modified_ns=metadata.st_mtime_ns,
            changed_ns=metadata.st_ctime_ns,
        )


class FileData:
    """Read-only, pread-backed bytes and file access over one stable regular-file fd."""

    def __init__(self, descriptor: int, signature: _FileSignature) -> None:
        self._descriptor = descriptor
        self._signature = signature
        self._position = 0

    @classmethod
    def from_stream(cls, stream: BinaryIO, max_bytes: int | None = None) -> FileData:
        _validate_limit(max_bytes)
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            msg = "Binary input is not a regular file"
            raise ValueError(msg)
        if max_bytes is not None and metadata.st_size > max_bytes:
            raise DataLimitError(max_bytes, 0)
        descriptor = os.dup(stream.fileno())
        try:
            signature = _FileSignature.from_stat(os.fstat(descriptor))
        except BaseException:
            os.close(descriptor)
            raise
        if max_bytes is not None and signature.size > max_bytes:
            os.close(descriptor)
            raise DataLimitError(max_bytes, 0)
        return cls(descriptor, signature)

    def __len__(self) -> int:
        return self._signature.size

    @overload
    def __getitem__(self, key: int) -> int: ...

    @overload
    def __getitem__(self, key: slice) -> bytes: ...

    def __getitem__(self, key: int | slice) -> int | bytes:
        if isinstance(key, int):
            offset = key + len(self) if key < 0 else key
            if not 0 <= offset < len(self):
                raise IndexError(key)
            return self.read_at(offset, 1)[0]
        start, stop, step = key.indices(len(self))
        indexes = range(start, stop, step)
        if not indexes:
            return b""
        if step > 0:
            content = self.read_at(start, stop - start)
            return content if step == 1 else content[::step]
        lowest = indexes[-1]
        content = self.read_at(lowest, start - lowest + 1)
        return bytes(content[index - lowest] for index in indexes)

    def __contains__(self, needle: object) -> bool:
        if isinstance(needle, int):
            if not 0 <= needle <= MAX_BYTE:
                msg = "byte must be in range(0, 256)"
                raise ValueError(msg)
            return self.find(bytes((needle,))) >= 0
        if isinstance(needle, (bytes, bytearray, memoryview)):
            return self.find(bytes(needle)) >= 0
        msg = f"a bytes-like object is required, not {type(needle).__name__}"
        raise TypeError(msg)

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset > len(self) or size > len(self) - offset:
            msg = "Binary range outside file"
            raise ValueError(msg)
        chunks = []
        remaining = size
        position = offset
        while remaining:
            chunk = os.pread(self.fileno(), min(COPY_CHUNK_BYTES, remaining), position)
            if not chunk:
                self.check_unchanged()
                msg = "Binary input ended while a validated range was being read"
                raise DataChangedError(msg)
            chunks.append(chunk)
            position += len(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def find(  # noqa: C901 -- Bytes-compatible bounds plus chunk-overlap search.
        self, sub: bytes, start: int = 0, end: int | None = None
    ) -> int:
        needle = bytes(sub)
        length = len(self)
        if start < 0:
            start = max(0, length + start)
        elif start > length:
            return -1
        if end is None:
            end = length
        elif end < 0:
            end = max(0, length + end)
        else:
            end = min(end, length)
        if end < start:
            return -1
        if not needle:
            return start
        overlap = len(needle) - 1
        tail = b""
        position = start
        while position < end:
            chunk = os.pread(self.fileno(), min(SEARCH_CHUNK_BYTES, end - position), position)
            if not chunk:
                self.check_unchanged()
                return -1
            candidate = tail + chunk
            found = candidate.find(needle)
            if found >= 0:
                offset = position - len(tail) + found
                if offset + len(needle) <= end:
                    return offset
            tail = candidate[-overlap:] if overlap else b""
            position += len(chunk)
        return -1

    def startswith(
        self, prefix: bytes | tuple[bytes, ...], start: int = 0, end: int | None = None
    ) -> bool:
        if isinstance(prefix, tuple):
            return any(self.startswith(item, start, end) for item in prefix)
        normalized_start, normalized_stop, _ = slice(start, end).indices(len(self))
        if len(prefix) > normalized_stop - normalized_start:
            return False
        return (
            self.find(prefix, normalized_start, normalized_start + len(prefix)) == normalized_start
        )

    def read(self, size: int = -1) -> bytes:
        if self._position >= len(self):
            return b""
        if size is None or size < 0:
            size = len(self) - self._position
        else:
            size = max(0, min(size, len(self) - self._position))
        content = self.read_at(self._position, size)
        self._position += len(content)
        return content

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            position = offset
        elif whence == io.SEEK_CUR:
            position = self._position + offset
        elif whence == io.SEEK_END:
            position = len(self) + offset
        else:
            msg = f"Invalid whence: {whence}"
            raise ValueError(msg)
        if position < 0:
            raise OSError(errno.EINVAL, "Invalid argument")
        self._position = position
        return position

    def tell(self) -> int:
        return self._position

    def fileno(self) -> int:
        if self._descriptor < 0:
            msg = "I/O operation on closed binary data"
            raise ValueError(msg)
        return self._descriptor

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    @property
    def closed(self) -> bool:
        return self._descriptor < 0

    def check_unchanged(self) -> None:
        current = _FileSignature.from_stat(os.fstat(self.fileno()))
        if current != self._signature:
            msg = "Binary input changed while it was being inspected"
            raise DataChangedError(msg)

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1


type Buffer = bytes | FileData


def _validate_limit(max_bytes: int | None) -> None:
    if max_bytes is not None and max_bytes < 0:
        msg = "max_bytes must be nonnegative or None"
        raise ValueError(msg)


def _read_size(total: int, max_bytes: int | None) -> int:
    if max_bytes is None:
        return COPY_CHUNK_BYTES
    return min(COPY_CHUNK_BYTES, max_bytes - total + 1)


@contextmanager
def file_data(stream: BinaryIO, max_bytes: int | None = None) -> Generator[FileData, None, None]:
    """Yield sparse access to an already-open regular file without reading it eagerly."""
    data = FileData.from_stream(stream, max_bytes)
    completed = False
    try:
        yield data
        completed = True
    finally:
        try:
            if completed:
                data.check_unchanged()
        finally:
            data.close()


@contextmanager
def read_data(stream: BinaryIO, max_bytes: int | None = None) -> Generator[Buffer, None, None]:
    """Read a sequential stream as small bytes or a temporary pread-backed file."""
    _validate_limit(max_bytes)
    buffered = bytearray()
    temporary: BinaryIO | None = None
    total = 0
    try:
        while True:
            chunk = stream.read(_read_size(total, max_bytes))
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise DataLimitError(max_bytes, total)
            if temporary is None and total <= SMALL_BYTES_LIMIT:
                buffered.extend(chunk)
                continue
            if temporary is None:
                temporary = tempfile.TemporaryFile(  # noqa: SIM115 -- Closed after yielded data.
                    prefix="brotli-binary-"
                )
                temporary.write(buffered)
                buffered.clear()
            temporary.write(chunk)
        if temporary is None:
            yield bytes(buffered)
            return
        temporary.flush()
        with file_data(temporary) as data:
            yield data
    finally:
        if temporary is not None:
            temporary.close()


def sha256_data(data: Buffer) -> str:
    """Hash bytes or an open regular file in fixed-size chunks."""
    digest = hashlib.sha256()
    if isinstance(data, FileData):
        data.check_unchanged()
        for offset in range(0, len(data), COPY_CHUNK_BYTES):
            digest.update(data.read_at(offset, min(COPY_CHUNK_BYTES, len(data) - offset)))
        data.check_unchanged()
        return digest.hexdigest()
    view = memoryview(data)
    try:
        for offset in range(0, len(view), COPY_CHUNK_BYTES):
            digest.update(view[offset : offset + COPY_CHUNK_BYTES])
    finally:
        view.release()
    return digest.hexdigest()
