# ruff: noqa: ANN401, C901, EM101, EM102, PLR0912, PLR0915, PLR2004, TRY003
"""Bounded, no-extraction readers for package and container payloads."""

from __future__ import annotations

import bz2
import gzip
import hashlib
import importlib
import io
import json
import lzma
import stat
import struct
import tarfile
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO, TYPE_CHECKING, Any, BinaryIO, cast

from brotli_binary_data import DataLimitError, read_data

if TYPE_CHECKING:
    from collections.abc import Generator, Iterator

    from brotli_binary_data import Buffer

AR_MAGIC = b"!<arch>\n"
RPM_MAGIC = b"\xed\xab\xee\xdb"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
CPIO_MAGICS = (b"070701", b"070702", b"070707")
MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_NAME_BYTES = 4096
MAX_ITEMS = 100_000
DEFAULT_MAX_MEMBERS = 100_000
DEFAULT_MAX_MEMBER_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
OCI_LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.oci.image.layer.nondistributable.v1.tar",
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
    "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
}


class PayloadError(ValueError):
    """Malformed, unsupported, or over-budget payload evidence."""


class PayloadUnavailableError(PayloadError):
    """An explicitly optional decompressor is unavailable."""


class NotOciImageError(PayloadError):
    """A valid tar payload lacks Docker-save or OCI-layout identity."""


@dataclass(frozen=True)
class PayloadLimits:
    max_members: int = DEFAULT_MAX_MEMBERS
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES

    def __post_init__(self) -> None:
        if min(self.max_members, self.max_member_bytes, self.max_total_bytes) < 0:
            raise ValueError("payload limits must be nonnegative")


DEFAULT_LIMITS = PayloadLimits()
ZSTD_MAGICS = (
    ZSTD_MAGIC,
    *(bytes((first, 0x2A, 0x4D, 0x18)) for first in range(0x50, 0x60)),
)


class SubrangeStream(io.RawIOBase):
    """Seekable read-only view over one Buffer range without copying it."""

    def __init__(self, data: Buffer, offset: int, size: int) -> None:
        if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
            raise PayloadError("payload member range outside input")
        self._data = data
        self._offset = offset
        self._size = size
        self._position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, target: Any) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed payload stream")
        size = min(len(target), self._size - self._position)
        if size <= 0:
            return 0
        content = self._data[self._offset + self._position : self._offset + self._position + size]
        target[:size] = content
        self._position += size
        return size

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            position = offset
        elif whence == io.SEEK_CUR:
            position = self._position + offset
        elif whence == io.SEEK_END:
            position = self._size + offset
        else:
            raise ValueError("invalid payload stream whence")
        if position < 0:
            raise OSError("negative payload stream position")
        self._position = min(position, self._size)
        return self._position

    def tell(self) -> int:
        return self._position


class _ExpandedLimitStream(io.RawIOBase):
    """Count every expanded byte consumed by a streaming container parser."""

    def __init__(self, source: IO[bytes], limit: int) -> None:
        self.source = source
        self.limit = limit
        self.bytes_read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, target: Any) -> int:
        content = self.source.read(len(target))
        if not content:
            return 0
        self.bytes_read += len(content)
        if self.bytes_read > self.limit:
            raise PayloadError("OCI cumulative expanded-byte limit reached")
        target[: len(content)] = content
        return len(content)


@dataclass(frozen=True)
class PayloadMember:
    name: str
    size: int
    data: Buffer | bytes = field(repr=False)
    file_offset: int = 0
    kind: str = "file"
    metadata: dict[str, Any] = field(default_factory=dict)

    @contextmanager
    def open(self) -> Generator[IO[bytes]]:
        stream = cast("IO[bytes]", SubrangeStream(self.data, self.file_offset, self.size))
        try:
            yield stream
        finally:
            stream.close()

    def read(self) -> bytes:
        return bytes(self.data[self.file_offset : self.file_offset + self.size])


@dataclass(frozen=True)
class RpmPayload:
    metadata: dict[str, Any]
    compressor: str
    member: PayloadMember


@dataclass(frozen=True)
class OciFilesystem:
    members: tuple[PayloadMember, ...]
    history: tuple[dict[str, Any], ...]
    gaps: tuple[str, ...]
    manifest: str


def _validate_range(data: Buffer, offset: int, size: int) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise PayloadError("payload range outside input")


def _checked(data: Buffer, offset: int, size: int) -> bytes:
    _validate_range(data, offset, size)
    return data[offset : offset + size]


def _safe_name(value: str) -> str:
    if len(value.encode("utf-8", "surrogateescape")) > MAX_NAME_BYTES:
        raise PayloadError("payload member name exceeds limit")
    normalized = value.replace("\\", "/").removeprefix("./")
    path = PurePosixPath(normalized)
    if not normalized or normalized.startswith("/") or ".." in path.parts:
        raise PayloadError("unsafe absolute or parent-traversing payload member name")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized):
        raise PayloadError("payload member name contains control characters")
    return path.as_posix()


def _bounded_members(
    members: Iterator[PayloadMember], limits: PayloadLimits
) -> Iterator[PayloadMember]:
    total = 0
    for count, member in enumerate(members, 1):
        total += member.size
        if count > limits.max_members:
            raise PayloadError("payload member count limit reached")
        if member.size > limits.max_member_bytes:
            raise PayloadError(f"payload member exceeds {limits.max_member_bytes}-byte limit")
        if total > limits.max_total_bytes:
            raise PayloadError("payload cumulative member-byte limit reached")
        yield member


def payload_kind(
    data: Buffer, label: str = "", limits: PayloadLimits = DEFAULT_LIMITS
) -> str | None:
    if data.startswith(AR_MAGIC):
        first = next(iter(iter_ar_members(data, limits)), None)
        return "deb" if first is not None and first.name == "debian-binary" else "ar"
    if data.startswith(RPM_MAGIC):
        return "rpm"
    if data.startswith(ZSTD_MAGICS):
        return "zstd"
    if data.startswith(CPIO_MAGICS):
        return "cpio"
    suffix = Path(label.lower()).suffix
    if suffix in {".oci", ".docker"}:
        return "oci"
    return None


def _oci_archive_candidate_unchecked(data: Buffer, limits: PayloadLimits) -> bool:
    markers: set[str] = set()
    with (
        cast("IO[bytes]", SubrangeStream(data, 0, len(data))) as source,
        tarfile.open(fileobj=source, mode="r:") as archive,
    ):
        for count, info in enumerate(archive, 1):
            if count > limits.max_members:
                return False
            name = info.name.replace("\\", "/").removeprefix("./")
            if name in {"manifest.json", "index.json", "oci-layout"}:
                markers.add(name)
            if "manifest.json" in markers or {"index.json", "oci-layout"} <= markers:
                return True
    return False


def oci_archive_candidate(data: Buffer, limits: PayloadLimits = DEFAULT_LIMITS) -> bool:
    """Identify OCI/Docker root markers without applying OCI path restrictions to other tars."""
    try:
        return _oci_archive_candidate_unchecked(data, limits)
    except UnicodeError:
        # Tar's pax decoder can reject surrogate-escaped ordinary member names.
        # That does not make the archive an OCI candidate; the caller's normal
        # tar path retains its established display-safe handling.
        return False
    except PayloadError:
        raise
    except (tarfile.TarError, OSError, EOFError) as error:
        raise PayloadError(f"cannot inspect tar payload: {error}") from error


def iter_payload_members(
    data: Buffer,
    kind: str,
    limits: PayloadLimits = DEFAULT_LIMITS,
) -> Iterator[PayloadMember]:
    """Dispatch one recognized payload using bounded temporary spooling only when required."""
    if kind == "ar":
        yield from iter_ar_members(data, limits)
        return
    if kind == "deb":
        yield from iter_deb_members(data, limits)
        return
    if kind == "cpio":
        yield from iter_cpio_members(data, limits)
        return
    if kind == "rpm":
        payload = rpm_payload(data)
        yield from iter_rpm_members(payload, limits)
        return
    if kind == "zstd":
        try:
            with (
                open_zstd(data) as stream,
                read_data(cast("BinaryIO", stream), limits.max_total_bytes) as expanded,
            ):
                yield PayloadMember(
                    "decompressed",
                    len(expanded),
                    expanded,
                    metadata={"container": "zstd"},
                )
        except DataLimitError as error:
            raise PayloadError("Zstandard output exceeds total-byte limit") from error
        return
    if kind == "oci":
        with open_oci_filesystems(data, limits) as images:
            for image_index, image in enumerate(images):
                for member in image.members:
                    yield PayloadMember(
                        member.name,
                        member.size,
                        member.data,
                        member.file_offset,
                        member.kind,
                        {**member.metadata, "image_index": image_index, "manifest": image.manifest},
                    )
        return
    raise PayloadError(f"unsupported payload kind: {kind}")


def iter_ar_members(
    data: Buffer, limits: PayloadLimits = DEFAULT_LIMITS
) -> Iterator[PayloadMember]:
    if not data.startswith(AR_MAGIC):
        raise PayloadError("not a regular ar archive")
    cursor = len(AR_MAGIC)
    string_table = b""

    def members() -> Iterator[PayloadMember]:
        nonlocal cursor, string_table
        while cursor < len(data):
            header = _checked(data, cursor, 60)
            if header[58:60] != b"`\n":
                raise PayloadError("invalid ar member header trailer")
            try:
                raw_name = header[:16].decode("ascii", "strict").rstrip()
            except UnicodeDecodeError as error:
                raise PayloadError("non-ASCII ar member header") from error
            try:
                stored_size = int(header[48:58].decode("ascii").strip())
            except ValueError as error:
                raise PayloadError("invalid ar member size") from error
            payload_offset = cursor + 60
            _validate_range(data, payload_offset, stored_size)
            name, content_offset, content_size = raw_name, payload_offset, stored_size
            if raw_name.startswith("#1/"):
                try:
                    name_size = int(raw_name[3:])
                except ValueError as error:
                    raise PayloadError("invalid BSD ar extended name") from error
                if name_size > stored_size or name_size > MAX_NAME_BYTES:
                    raise PayloadError("BSD ar extended name exceeds member")
                name = (
                    _checked(data, payload_offset, name_size)
                    .rstrip(b"\0")
                    .decode("utf-8", "surrogateescape")
                )
                content_offset += name_size
                content_size -= name_size
            elif raw_name == "//":
                if stored_size > MAX_METADATA_BYTES:
                    raise PayloadError("ar string table exceeds limit")
                string_table = _checked(data, payload_offset, stored_size)
                cursor = payload_offset + stored_size + (stored_size & 1)
                continue
            elif raw_name in ("/", "/SYM64/"):
                cursor = payload_offset + stored_size + (stored_size & 1)
                continue
            elif raw_name.startswith("/") and raw_name[1:].isdigit():
                table_offset = int(raw_name[1:])
                if table_offset >= len(string_table):
                    raise PayloadError("GNU ar name offset outside string table")
                table_end = string_table.find(b"/\n", table_offset)
                if table_end < 0:
                    raise PayloadError("unterminated GNU ar name")
                name = string_table[table_offset:table_end].decode("utf-8", "surrogateescape")
            else:
                name = raw_name.removesuffix("/")
            cursor = payload_offset + stored_size + (stored_size & 1)
            yield PayloadMember(
                _safe_name(name),
                content_size,
                data,
                content_offset,
                metadata={"container": "ar", "stored_size": stored_size},
            )
        if cursor != len(data):
            raise PayloadError("ar alignment extends beyond input")

    yield from _bounded_members(members(), limits)


def iter_deb_members(
    data: Buffer, limits: PayloadLimits = DEFAULT_LIMITS
) -> Iterator[PayloadMember]:
    members = iter(iter_ar_members(data, limits))
    try:
        marker = next(members)
    except StopIteration as error:
        raise PayloadError("empty Debian archive") from error
    if marker.name != "debian-binary" or marker.read() != b"2.0\n":
        raise PayloadError("Debian archive lacks exact debian-binary 2.0 marker")
    for member in members:
        if member.name.startswith(("control.tar", "data.tar")):
            yield member


@contextmanager
def open_zstd(data: Buffer) -> Generator[IO[bytes]]:
    """Open an optional streaming Zstandard decompressor without target execution."""
    source = cast("IO[bytes]", SubrangeStream(data, 0, len(data)))
    try:
        with open_zstd_stream(source) as stream:
            yield stream
    finally:
        source.close()


@contextmanager
def open_zstd_stream(source: IO[bytes]) -> Generator[IO[bytes]]:
    """Wrap an already bounded compressed stream with an optional decoder."""
    stream: IO[bytes] | None = None
    backend_errors: tuple[type[BaseException], ...] = ()
    try:
        try:
            module = importlib.import_module("compression.zstd")
            stream = cast("IO[bytes]", module.ZstdFile(source, "rb"))
        except (ImportError, AttributeError):
            try:
                module = importlib.import_module("zstandard")
            except ImportError as error:
                raise PayloadUnavailableError(
                    "Zstandard payload requires optional compression.zstd or zstandard"
                ) from error
            stream = cast("IO[bytes]", module.ZstdDecompressor().stream_reader(source))
        error_type = getattr(module, "ZstdError", None)
        if isinstance(error_type, type) and issubclass(error_type, BaseException):
            backend_errors = (error_type,)
        try:
            yield stream
        except backend_errors as error:
            raise PayloadError("invalid Zstandard payload") from error
    finally:
        if stream is not None:
            stream.close()


def _rpm_header(data: Buffer, offset: int) -> tuple[dict[int, Any], int]:
    header = _checked(data, offset, 16)
    if header[:8] != b"\x8e\xad\xe8\x01\0\0\0\0":
        raise PayloadError("invalid RPM header magic/version")
    index_count, store_size = struct.unpack(">II", header[8:16])
    if index_count > MAX_ITEMS or store_size > MAX_METADATA_BYTES:
        raise PayloadError("RPM header count or store exceeds limit")
    entries_offset = offset + 16
    store_offset = entries_offset + index_count * 16
    store = _checked(data, store_offset, store_size)
    values: dict[int, Any] = {}
    seen_tags = set()
    for index in range(index_count):
        tag, kind, value_offset, count = struct.unpack(
            ">IIII", _checked(data, entries_offset + index * 16, 16)
        )
        if value_offset > len(store) or count > MAX_ITEMS:
            raise PayloadError("RPM header entry outside bounded store")
        if tag in seen_tags:
            raise PayloadError("duplicate RPM header tag")
        seen_tags.add(tag)
        alignment = {3: 2, 4: 4, 5: 8}.get(kind, 1)
        if value_offset % alignment:
            raise PayloadError("misaligned RPM header value")
        if kind in (6, 8, 9):
            position = value_offset
            strings = []
            for _ in range(count):
                stop = store.find(b"\0", position, min(len(store), position + MAX_NAME_BYTES + 1))
                if stop < 0:
                    raise PayloadError("unterminated RPM header string")
                strings.append(store[position:stop].decode("utf-8", "replace"))
                position = stop + 1
            values[tag] = strings[0] if kind == 6 and count == 1 else strings
        elif kind in (4, 5):
            width = 4 if kind == 4 else 8
            raw = store[value_offset : value_offset + count * width]
            if len(raw) != count * width:
                raise PayloadError("truncated RPM integer entry")
            values[tag] = [
                int.from_bytes(raw[item : item + width], "big")
                for item in range(0, len(raw), width)
            ]
        elif kind == 7:
            values[tag] = store[value_offset : value_offset + count]
    return values, store_offset + store_size


def _rpm_file_digests(tags: dict[int, Any], algorithm: int | None) -> list[dict[str, Any]]:
    basenames = tags.get(1117)
    directories = tags.get(1118)
    directory_indexes = tags.get(1116)
    digests = tags.get(1035)
    if (
        not isinstance(basenames, list)
        or not isinstance(directories, list)
        or not isinstance(directory_indexes, list)
        or not isinstance(digests, list)
    ):
        return []
    if len(basenames) != len(directory_indexes) or len(basenames) != len(digests):
        raise PayloadError("RPM per-file digest arrays have inconsistent lengths")
    result = []
    for basename, directory_index, digest in zip(
        basenames, directory_indexes, digests, strict=True
    ):
        if (
            not isinstance(basename, str)
            or not isinstance(directory_index, int)
            or not 0 <= directory_index < len(directories)
            or not isinstance(directories[directory_index], str)
            or not isinstance(digest, str)
        ):
            raise PayloadError("invalid RPM per-file digest mapping")
        path = _safe_name((directories[directory_index] + basename).lstrip("/"))
        if digest:
            result.append({"path": path, "digest": digest.lower(), "algorithm": algorithm})
    return result


def rpm_payload(data: Buffer) -> RpmPayload:
    if not data.startswith(RPM_MAGIC) or len(data) < 96:
        raise PayloadError("not a complete RPM lead")
    _, signature_end = _rpm_header(data, 96)
    main_offset = (signature_end + 7) & ~7
    tags, payload_offset = _rpm_header(data, main_offset)
    compressor = tags.get(1125, "gzip")
    if isinstance(compressor, list):
        compressor = compressor[0] if compressor else ""
    if not isinstance(compressor, str) or compressor not in {
        "gzip",
        "bzip2",
        "xz",
        "lzma",
        "zstd",
        "none",
    }:
        raise PayloadError(f"unsupported RPM payload compressor: {compressor!r}")
    payload_format = tags.get(1124)
    if payload_format not in (None, "cpio"):
        raise PayloadError(f"unsupported RPM payload format: {payload_format!r}")
    epoch_values = tags.get(1003, [0])
    epoch = epoch_values[0] if isinstance(epoch_values, list) and epoch_values else 0
    digest_algorithm_values = tags.get(5011, [])
    digest_algorithm = (
        digest_algorithm_values[0]
        if isinstance(digest_algorithm_values, list) and digest_algorithm_values
        else None
    )
    metadata = {
        "name": tags.get(1000),
        "epoch": epoch,
        "version": tags.get(1001),
        "release": tags.get(1002),
        "arch": tags.get(1022),
        "payload_format": payload_format,
        "payload_flags": tags.get(1126),
        "payload_compressor": compressor,
        "file_digest_algorithm": digest_algorithm,
        "file_digests": _rpm_file_digests(tags, digest_algorithm),
    }
    return RpmPayload(
        metadata,
        compressor,
        PayloadMember(
            "payload.cpio", len(data) - payload_offset, data, payload_offset, "rpm_payload"
        ),
    )


@contextmanager
def open_rpm_payload(payload: RpmPayload) -> Generator[IO[bytes]]:
    with payload.member.open() as source:
        if payload.compressor == "none":
            yield source
        elif payload.compressor == "gzip":
            with gzip.GzipFile(fileobj=source) as stream:
                yield cast("IO[bytes]", stream)
        elif payload.compressor == "bzip2":
            with bz2.BZ2File(source) as stream:
                yield cast("IO[bytes]", stream)
        elif payload.compressor in ("xz", "lzma"):
            with lzma.LZMAFile(source) as stream:
                yield cast("IO[bytes]", stream)
        else:
            with open_zstd_stream(source) as stream:
                yield stream


def iter_rpm_members(
    payload: RpmPayload, limits: PayloadLimits = DEFAULT_LIMITS
) -> Iterator[PayloadMember]:
    try:
        with (
            open_rpm_payload(payload) as stream,
            read_data(cast("BinaryIO", stream), limits.max_total_bytes) as expanded,
        ):
            yield from iter_cpio_members(expanded, limits)
    except DataLimitError as error:
        raise PayloadError("RPM expanded payload exceeds total-byte limit") from error


def iter_cpio_members(
    data: Buffer, limits: PayloadLimits = DEFAULT_LIMITS
) -> Iterator[PayloadMember]:
    if not data.startswith(CPIO_MAGICS):
        raise PayloadError("unsupported cpio format")
    return _bounded_members(_iter_cpio(data), limits)


def _iter_cpio(data: Buffer) -> Iterator[PayloadMember]:
    cursor = 0
    while cursor < len(data):
        magic = _checked(data, cursor, 6)
        if magic in (b"070701", b"070702"):
            header = _checked(data, cursor, 110)
            try:
                values = [int(header[6 + index * 8 : 14 + index * 8], 16) for index in range(13)]
            except ValueError as error:
                raise PayloadError("invalid newc numeric field") from error
            mode, size, name_size, checksum = values[1], values[6], values[11], values[12]
            name_offset = cursor + 110
            data_offset = (name_offset + name_size + 3) & ~3
            next_offset = (data_offset + size + 3) & ~3
        elif magic == b"070707":
            header = _checked(data, cursor, 76)
            widths = (6, 6, 6, 6, 6, 6, 6, 11, 6, 11)
            position = 6
            parsed = []
            try:
                for width in widths:
                    parsed.append(int(header[position : position + width], 8))
                    position += width
            except ValueError as error:
                raise PayloadError("invalid odc numeric field") from error
            mode, name_size, size, checksum = parsed[2], parsed[8], parsed[9], 0
            name_offset = cursor + 76
            data_offset = name_offset + name_size
            next_offset = data_offset + size
        else:
            raise PayloadError("mixed or invalid cpio member magic")
        if not 0 < name_size <= MAX_NAME_BYTES + 1:
            raise PayloadError("invalid cpio member name size")
        name_raw = _checked(data, name_offset, name_size)
        if not name_raw.endswith(b"\0"):
            raise PayloadError("cpio member name lacks terminator")
        name = name_raw[:-1].decode("utf-8", "surrogateescape")
        _validate_range(data, data_offset, size)
        if name == "TRAILER!!!":
            return
        safe = _safe_name(name)
        if magic == b"070702":
            total = 0
            for offset in range(data_offset, data_offset + size, 1024 * 1024):
                total = (
                    total + sum(data[offset : min(offset + 1024 * 1024, data_offset + size)])
                ) & 0xFFFFFFFF
            if total != checksum:
                raise PayloadError("cpio crc checksum mismatch")
        kind = "file" if stat.S_ISREG(mode) else "symlink" if stat.S_ISLNK(mode) else "other"
        yield PayloadMember(
            safe, size, data, data_offset, kind, {"mode": mode, "container": "cpio"}
        )
        cursor = next_offset
    raise PayloadError("cpio archive lacks TRAILER!!!")


def _read_all_bounded(stream: IO[bytes], limit: int) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = stream.read(min(1024 * 1024, limit - total + 1))
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            raise PayloadError(f"expanded payload exceeds {limit}-byte limit")
        chunks.append(chunk)


def _tar_member_bytes(
    archive: tarfile.TarFile, info: tarfile.TarInfo, limits: PayloadLimits
) -> bytes:
    if info.size > limits.max_member_bytes:
        raise PayloadError("OCI layer member exceeds byte limit")
    stream = archive.extractfile(info)
    if stream is None:
        raise PayloadError("OCI regular member has no data stream")
    with stream:
        return _read_all_bounded(stream, limits.max_member_bytes)


@contextmanager
def _open_layer_stream(raw: bytes, media_type: str) -> Generator[IO[bytes]]:
    source = io.BytesIO(raw)
    try:
        if media_type.endswith("+gzip") or raw.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=source) as expanded:
                yield cast("IO[bytes]", expanded)
            return
        if media_type.endswith("+zstd") or raw.startswith(ZSTD_MAGICS):
            with open_zstd(raw) as expanded:
                yield expanded
            return
        yield source
    finally:
        source.close()


def apply_oci_layers(
    layers: list[tuple[str, bytes, str]],
    limits: PayloadLimits = DEFAULT_LIMITS,
    *,
    manifest: str = "supplied",
) -> OciFilesystem:
    """Apply ordered tar layers and return only the visible final filesystem."""
    visible: dict[str, PayloadMember] = {}
    history: list[dict[str, Any]] = []
    gaps: list[str] = []
    expanded_total = 0
    member_count = 0
    for layer_index, (layer_id, raw, media_type) in enumerate(layers):
        seen = set()
        whiteouts: list[tuple[str, str]] = []
        additions: list[tuple[str, bytes]] = []
        with _open_layer_stream(raw, media_type) as stream:
            counted = _ExpandedLimitStream(stream, limits.max_total_bytes - expanded_total)
            with tarfile.open(fileobj=counted, mode="r|") as archive:
                for info in archive:
                    name = _safe_name(info.name)
                    if name in seen:
                        raise PayloadError("OCI layer contains duplicate member path")
                    seen.add(name)
                    member_count += 1
                    if member_count > limits.max_members:
                        raise PayloadError("OCI layer member count limit reached")
                    path = PurePosixPath(name)
                    base = path.name
                    parent = path.parent.as_posix()
                    if base == ".wh..wh..opq":
                        whiteouts.append(("opaque", parent))
                        continue
                    if base.startswith(".wh."):
                        whiteouts.append(("whiteout", (path.parent / base[4:]).as_posix()))
                        continue
                    if info.isdir():
                        continue
                    if not info.isfile():
                        gaps.append(f"Layer {layer_id} nonregular member not followed: {name}")
                        history.append({"layer": layer_id, "action": "nonregular", "path": name})
                        continue
                    content = _tar_member_bytes(archive, info, limits)
                    additions.append((name, content))
            expanded_total += counted.bytes_read
        # Whiteouts describe changes to lower layers regardless of tar entry order.
        for action, target in whiteouts:
            if action == "opaque":
                prefix = "" if target == "." else target + "/"
                removed = [key for key in visible if key.startswith(prefix)]
            else:
                removed = [key for key in visible if key == target or key.startswith(target + "/")]
            for key in removed:
                del visible[key]
            history.append(
                {"layer": layer_id, "action": action, "path": target, "removed": sorted(removed)}
            )
        for name, content in additions:
            member = PayloadMember(
                name,
                len(content),
                content,
                0,
                metadata={"layer": layer_id, "layer_index": layer_index, "final": True},
            )
            visible[name] = member
            history.append(
                {
                    "layer": layer_id,
                    "action": "add_or_replace",
                    "path": name,
                    "size": len(content),
                    "historical_only": True,
                }
            )
    return OciFilesystem(
        tuple(visible[name] for name in sorted(visible)), tuple(history), tuple(gaps), manifest
    )


def _tar_map(data: Buffer, limits: PayloadLimits) -> dict[str, bytes]:
    """Materialize a bounded small fixture; production uses open_oci_filesystems."""
    if len(data) > limits.max_total_bytes:
        raise PayloadError("OCI archive exceeds cumulative byte limit")
    result = {}
    total = count = 0
    with (
        cast("IO[bytes]", SubrangeStream(data, 0, len(data))) as source,
        tarfile.open(fileobj=source, mode="r|") as archive,
    ):
        for info in archive:
            if info.isdir():
                continue
            if not info.isfile():
                raise PayloadError("OCI layout archive nonregular member not followed")
            name = _safe_name(info.name)
            if name in result:
                raise PayloadError("OCI archive contains duplicate member path")
            count += 1
            if count > limits.max_members:
                raise PayloadError("OCI archive member count limit reached")
            content = _tar_member_bytes(archive, info, limits)
            total += len(content)
            if total > limits.max_total_bytes:
                raise PayloadError("OCI archive cumulative byte limit reached")
            result[name] = content
    return result


def _member_sha256(member: PayloadMember) -> str:
    digest = hashlib.sha256()
    with member.open() as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _member_json(member: PayloadMember) -> Any:
    if member.size > MAX_METADATA_BYTES:
        raise PayloadError("OCI JSON metadata exceeds limit")
    try:
        return json.loads(member.read())
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        raise PayloadError("invalid OCI JSON metadata") from error


def _index_tar_member_unchecked(
    member: PayloadMember, limits: PayloadLimits, *, allow_nonregular: bool = False
) -> tuple[dict[str, PayloadMember], list[str]]:
    indexed: dict[str, PayloadMember] = {}
    gaps = []
    total = count = 0
    with member.open() as source, tarfile.open(fileobj=source, mode="r:") as archive:
        for info in archive:
            if info.isdir():
                continue
            name = _safe_name(info.name)
            if name in indexed:
                raise PayloadError("tar contains duplicate member path")
            count += 1
            if count > limits.max_members:
                raise PayloadError("tar member count limit reached")
            if info.size > limits.max_member_bytes:
                raise PayloadError("tar member exceeds byte limit")
            total += info.size
            if total > limits.max_total_bytes:
                raise PayloadError("tar cumulative member-byte limit reached")
            if not info.isfile():
                if not allow_nonregular:
                    raise PayloadError("OCI layout archive nonregular member not followed")
                gaps.append(f"Nonregular layer member not followed: {name}")
                continue
            indexed[name] = PayloadMember(
                name,
                info.size,
                member.data,
                member.file_offset + info.offset_data,
                metadata={"container": "tar"},
            )
    return indexed, gaps


def _index_tar_member(
    member: PayloadMember, limits: PayloadLimits, *, allow_nonregular: bool = False
) -> tuple[dict[str, PayloadMember], list[str]]:
    try:
        return _index_tar_member_unchecked(member, limits, allow_nonregular=allow_nonregular)
    except PayloadError:
        raise
    except (tarfile.TarError, OSError, EOFError) as error:
        raise PayloadError(f"cannot inspect tar payload: {error}") from error


def _spool_layer(
    stack: ExitStack,
    member: PayloadMember,
    media_type: str,
    limit: int,
) -> PayloadMember:
    with member.open() as probe:
        magic = probe.read(4)
    is_zstd = media_type.endswith("+zstd") or magic in ZSTD_MAGICS
    is_gzip = media_type.endswith("+gzip") or magic[:3] == b"\x1f\x8b\x08"
    if not is_zstd and not is_gzip:
        return member
    source = stack.enter_context(member.open())
    if is_zstd:
        expanded_stream = stack.enter_context(open_zstd_stream(source))
    else:
        expanded_stream = stack.enter_context(gzip.GzipFile(fileobj=source))
    try:
        expanded = stack.enter_context(read_data(cast("BinaryIO", expanded_stream), limit))
    except DataLimitError as error:
        raise PayloadError("OCI expanded layer exceeds total-byte limit") from error
    return PayloadMember(member.name, len(expanded), expanded, metadata={"expanded": True})


def _apply_indexed_layers(
    layers: list[tuple[str, PayloadMember, str]], limits: PayloadLimits
) -> OciFilesystem:
    visible: dict[str, PayloadMember] = {}
    history: list[dict[str, Any]] = []
    gaps: list[str] = []
    total = count = 0
    for layer_index, (layer_id, layer, _media_type) in enumerate(layers):
        entries, layer_gaps = _index_tar_member(layer, limits, allow_nonregular=True)
        gaps.extend(f"Layer {layer_id}: {gap}" for gap in layer_gaps)
        whiteouts = []
        additions = []
        for name, member in entries.items():
            count += 1
            total += member.size
            if count > limits.max_members or total > limits.max_total_bytes:
                raise PayloadError("OCI aggregate layer member budget reached")
            path = PurePosixPath(name)
            if path.name == ".wh..wh..opq":
                whiteouts.append(("opaque", path.parent.as_posix()))
            elif path.name.startswith(".wh."):
                whiteouts.append(("whiteout", (path.parent / path.name[4:]).as_posix()))
            else:
                additions.append((name, member))
        for action, target in whiteouts:
            if action == "opaque":
                prefix = "" if target == "." else target + "/"
                removed = [key for key in visible if key.startswith(prefix)]
            else:
                removed = [key for key in visible if key == target or key.startswith(target + "/")]
            for key in removed:
                del visible[key]
            history.append(
                {"layer": layer_id, "action": action, "path": target, "removed": sorted(removed)}
            )
        for name, member in additions:
            visible[name] = PayloadMember(
                name,
                member.size,
                member.data,
                member.file_offset,
                metadata={"layer": layer_id, "layer_index": layer_index, "final": True},
            )
            history.append(
                {
                    "layer": layer_id,
                    "action": "add_or_replace",
                    "path": name,
                    "size": member.size,
                    "historical_only": True,
                }
            )
    return OciFilesystem(
        tuple(visible[name] for name in sorted(visible)), tuple(history), tuple(gaps), "supplied"
    )


@contextmanager
def open_oci_filesystems(
    data: Buffer, limits: PayloadLimits = DEFAULT_LIMITS
) -> Generator[tuple[OciFilesystem, ...]]:
    """Keep slice-backed/spooled OCI members valid for the context lifetime."""
    outer = PayloadMember("image.tar", len(data), data)
    files, _ = _index_tar_member(outer, limits)
    with ExitStack() as stack:
        images: list[OciFilesystem] = []

        def expanded_layers(
            descriptors: list[tuple[str, PayloadMember, str]],
        ) -> list[tuple[str, PayloadMember, str]]:
            remaining = limits.max_total_bytes
            result = []
            for layer_id, member, media_type in descriptors:
                expanded = _spool_layer(stack, member, media_type, remaining)
                if expanded.metadata.get("expanded"):
                    remaining -= expanded.size
                result.append((layer_id, expanded, media_type))
            return result

        if "manifest.json" in files:
            manifests = _member_json(files["manifest.json"])
            if not isinstance(manifests, list) or len(manifests) > limits.max_members:
                raise PayloadError("invalid Docker manifest population")
            for index, manifest_entry in enumerate(manifests):
                layer_names = (
                    manifest_entry.get("Layers") if isinstance(manifest_entry, dict) else None
                )
                if not isinstance(layer_names, list):
                    raise PayloadError("invalid Docker layer list")
                descriptors = []
                for name in layer_names:
                    safe = _safe_name(name)
                    if safe not in files:
                        raise PayloadError("Docker manifest references missing layer")
                    descriptors.append(
                        (safe, files[safe], "application/vnd.oci.image.layer.v1.tar")
                    )
                image = _apply_indexed_layers(expanded_layers(descriptors), limits)
                images.append(
                    OciFilesystem(image.members, image.history, image.gaps, f"docker:{index}")
                )
            yield tuple(images)
            return
        if "index.json" not in files or "oci-layout" not in files:
            raise NotOciImageError("tar is not a Docker save or OCI image layout")
        layout_metadata = _member_json(files["oci-layout"])
        if (
            not isinstance(layout_metadata, dict)
            or layout_metadata.get("imageLayoutVersion") != "1.0.0"
        ):
            raise PayloadError("unsupported OCI image-layout version")
        index = _member_json(files["index.json"])
        manifests = index.get("manifests") if isinstance(index, dict) else None
        if not isinstance(manifests, list) or len(manifests) > limits.max_members:
            raise PayloadError("invalid OCI index manifest list")
        visited: set[str] = set()

        def resolve(descriptor: object, depth: int = 0) -> None:
            if depth > 4 or not isinstance(descriptor, dict):
                raise PayloadError("invalid or over-nested OCI descriptor")
            digest = descriptor.get("digest")
            if not isinstance(digest, str) or digest in visited:
                raise PayloadError("invalid, cyclic, or duplicate OCI digest")
            visited.add(digest)
            algorithm, separator, encoded = digest.partition(":")
            if (
                algorithm != "sha256"
                or separator != ":"
                or len(encoded) != 64
                or any(character not in "0123456789abcdef" for character in encoded)
            ):
                raise PayloadError("unsupported OCI digest")
            name = f"blobs/sha256/{encoded}"
            size = descriptor.get("size")
            if (
                name not in files
                or type(size) is not int
                or size != files[name].size
                or _member_sha256(files[name]) != encoded
            ):
                raise PayloadError("OCI blob missing or digest mismatch")
            manifest = _member_json(files[name])
            nested = manifest.get("manifests") if isinstance(manifest, dict) else None
            if isinstance(nested, list):
                for child in nested:
                    resolve(child, depth + 1)
                return
            layer_rows = manifest.get("layers") if isinstance(manifest, dict) else None
            if not isinstance(layer_rows, list):
                raise PayloadError("invalid OCI manifest layers")
            layers = []
            for row in layer_rows:
                if not isinstance(row, dict) or not isinstance(row.get("digest"), str):
                    raise PayloadError("invalid OCI layer descriptor")
                layer_digest = row["digest"]
                media_type = row.get("mediaType")
                algorithm, separator, layer_hash = layer_digest.partition(":")
                blob = f"blobs/sha256/{layer_hash}"
                if (
                    algorithm != "sha256"
                    or separator != ":"
                    or len(layer_hash) != 64
                    or any(character not in "0123456789abcdef" for character in layer_hash)
                    or blob not in files
                    or media_type not in OCI_LAYER_MEDIA_TYPES
                    or type(row.get("size")) is not int
                    or row["size"] != files[blob].size
                ):
                    raise PayloadError("OCI layer blob missing or digest unsupported")
                if _member_sha256(files[blob]) != layer_hash:
                    raise PayloadError("OCI layer digest mismatch")
                layers.append((layer_digest, files[blob], media_type))
            image = _apply_indexed_layers(expanded_layers(layers), limits)
            images.append(OciFilesystem(image.members, image.history, image.gaps, digest))

        for descriptor in manifests:
            resolve(descriptor)
        yield tuple(images)


def oci_filesystems(
    data: Buffer, limits: PayloadLimits = DEFAULT_LIMITS
) -> tuple[OciFilesystem, ...]:
    """Materialize bounded small fixtures; production uses open_oci_filesystems."""
    files = _tar_map(data, limits)
    images: list[OciFilesystem] = []
    if "manifest.json" in files:  # Docker save archive.
        manifests = json.loads(files["manifest.json"])
        if not isinstance(manifests, list) or len(manifests) > limits.max_members:
            raise PayloadError("invalid Docker manifest population")
        for index, manifest_entry in enumerate(manifests):
            layer_names = manifest_entry.get("Layers") if isinstance(manifest_entry, dict) else None
            if not isinstance(layer_names, list):
                raise PayloadError("invalid Docker layer list")
            layers = []
            for name in layer_names:
                safe = _safe_name(name)
                if safe not in files:
                    raise PayloadError("Docker manifest references missing layer")
                layers.append((safe, files[safe], "application/vnd.oci.image.layer.v1.tar"))
            images.append(apply_oci_layers(layers, limits, manifest=f"docker:{index}"))
        return tuple(images)
    if "index.json" not in files or "oci-layout" not in files:
        raise PayloadError("tar is not a Docker save or OCI image layout")
    index = json.loads(files["index.json"])
    manifests = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(manifests, list) or len(manifests) > limits.max_members:
        raise PayloadError("invalid OCI index manifest list")
    visited: set[str] = set()

    def resolve_descriptor(descriptor: object, depth: int = 0) -> None:
        if depth > 4:
            raise PayloadError("OCI index nesting exceeds limit")
        if not isinstance(descriptor, dict) or not isinstance(descriptor.get("digest"), str):
            raise PayloadError("invalid OCI manifest descriptor")
        digest = descriptor["digest"]
        if digest in visited:
            raise PayloadError("OCI descriptor cycle or duplicate reference")
        visited.add(digest)
        algorithm, separator, encoded = digest.partition(":")
        if (
            algorithm != "sha256"
            or separator != ":"
            or len(encoded) != 64
            or any(character not in "0123456789abcdef" for character in encoded)
        ):
            raise PayloadError("unsupported OCI digest")
        name = f"blobs/sha256/{encoded}"
        if name not in files or hashlib.sha256(files[name]).hexdigest() != encoded:
            raise PayloadError("OCI manifest blob missing or digest mismatch")
        manifest = json.loads(files[name])
        nested = manifest.get("manifests") if isinstance(manifest, dict) else None
        if isinstance(nested, list):
            if len(nested) > limits.max_members:
                raise PayloadError("OCI nested index exceeds descriptor limit")
            for child in nested:
                resolve_descriptor(child, depth + 1)
            return
        descriptors = manifest.get("layers") if isinstance(manifest, dict) else None
        if not isinstance(descriptors, list):
            raise PayloadError("invalid OCI manifest layers")
        layers = []
        for layer in descriptors:
            if not isinstance(layer, dict):
                raise PayloadError("invalid OCI layer descriptor")
            layer_digest = layer.get("digest", "")
            media_type = layer.get("mediaType", "")
            algorithm, separator, encoded = layer_digest.partition(":")
            blob_name = f"blobs/sha256/{encoded}"
            if algorithm != "sha256" or separator != ":" or blob_name not in files:
                raise PayloadError("OCI layer blob missing or digest unsupported")
            if hashlib.sha256(files[blob_name]).hexdigest() != encoded:
                raise PayloadError("OCI layer digest mismatch")
            layers.append((layer_digest, files[blob_name], media_type))
        images.append(apply_oci_layers(layers, limits, manifest=digest))

    for descriptor in manifests:
        resolve_descriptor(descriptor)
    return tuple(images)
