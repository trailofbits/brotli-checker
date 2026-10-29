"""Offline package ownership and dated vendor-version assertions."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from bisect import bisect_left
from dataclasses import dataclass
from datetime import date
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlparse

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from brotli_binary_data import Buffer

MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_PACKAGES = 100_000
MAX_FILES = 1_000_000
MAX_ASSERTIONS = 100_000
MAX_FIELD_CHARS = 4096
HASH_CHUNK_BYTES = 1024 * 1024
CONTROL_LIMIT = 0x20
DELETE = 0x7F
MD5_HEX_CHARS = 32
SHA256_HEX_CHARS = 64
FIELD_PARTS = 2
HEX = re.compile(r"[0-9a-f]+")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
DPKG_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]*")
APK_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+_.-]*")
RPM_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.-]*")
DEBIAN_UPSTREAM = re.compile(r"[A-Za-z0-9.+~-]+")
DEBIAN_REVISION = re.compile(r"[A-Za-z0-9+.~]+")
RPM_VERSION_PART = re.compile(r"[A-Za-z0-9._+~^]+")
APK_SUFFIXES = ("alpha", "beta", "pre", "rc", "", "cvs", "svn", "git", "hg", "p")
APK_TOKEN_INITIAL = 0
APK_TOKEN_DIGIT = 1
APK_TOKEN_LETTER = 2
APK_TOKEN_SUFFIX = 3
APK_TOKEN_SUFFIX_NUMBER = 4
APK_TOKEN_COMMIT = 5
APK_TOKEN_REVISION = 6
APK_TOKEN_END = 7
type HashAlgorithm = Literal["MD5", "SHA-1", "SHA-256"]


@dataclass(frozen=True)
class MetadataRecord:
    label: str
    data: Buffer


@dataclass(frozen=True)
class PackageHash:
    algorithm: HashAlgorithm
    value: str


@dataclass(frozen=True)
class PackageFile:
    path: str
    hashes: tuple[PackageHash, ...] = ()


@dataclass(frozen=True)
class PackageRecord:
    manager: Literal["dpkg", "apk", "rpm"]
    name: str
    version: str
    architecture: str
    files: tuple[PackageFile, ...]
    source: str


@dataclass(frozen=True)
class PackageDatabase:
    packages: tuple[PackageRecord, ...]
    gaps: tuple[str, ...]
    limited: bool


@dataclass(frozen=True)
class OwnershipMatch:
    manager: str
    package: str
    version: str
    architecture: str
    path: str
    evidence_strength: Literal["package_id", "package_file_hash_match", "artifact_hash_bound"]
    hash_verified: bool | None


@dataclass(frozen=True)
class OwnershipAssessment:
    status: Literal["unowned", "unique", "ambiguous", "modified"]
    matches: tuple[OwnershipMatch, ...]
    gaps: tuple[str, ...]


@dataclass(frozen=True)
class PackageOwnershipIndex:
    paths: tuple[str, ...]
    owners: tuple[tuple[tuple[PackageRecord, PackageFile], ...], ...]

    def lookup(self, path: str) -> tuple[tuple[PackageRecord, PackageFile], ...]:
        position = bisect_left(self.paths, path)
        if position >= len(self.paths) or self.paths[position] != path:
            return ()
        return self.owners[position]


@dataclass(frozen=True)
class VendorAssertion:
    vendor: Literal["debian", "ubuntu", "redhat"]
    release: str
    package: str
    fixed_version: str
    advisory_url: str
    snapshot_date: str


@dataclass(frozen=True)
class VendorSnapshot:
    schema_version: int
    vendor: Literal["debian", "ubuntu", "redhat"]
    release: str
    snapshot_date: str
    assertions: tuple[VendorAssertion, ...]


@dataclass(frozen=True)
class VendorVersionAssessment:
    package: str
    installed_version: str
    fixed_version: str
    vendor: str
    release: str
    advisory_url: str
    snapshot_date: str
    status: Literal["precedes_vendor_fixed_version", "meets_vendor_fixed_version"]
    patch_status: Literal["unknown"] = "unknown"


def _text(data: Buffer, label: str) -> str:
    if len(data) > MAX_METADATA_BYTES:
        msg = f"{label} exceeds the {MAX_METADATA_BYTES}-byte metadata limit"
        raise ValueError(msg)
    try:
        return data[: len(data)].decode("utf-8")
    except UnicodeDecodeError as error:
        msg = f"{label} is not UTF-8 package metadata"
        raise ValueError(msg) from error


def _safe_field(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_FIELD_CHARS:
        msg = f"Invalid package metadata field: {field}"
        raise ValueError(msg)
    if any(ord(character) < CONTROL_LIMIT or ord(character) == DELETE for character in value):
        msg = f"Package metadata field contains controls: {field}"
        raise ValueError(msg)
    return value


def _path(value: str) -> str:
    normalized = value.strip().replace("\\", "/").removeprefix("./").lstrip("/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or ".." in path.parts
        or any(
            ord(character) < CONTROL_LIMIT or ord(character) == DELETE for character in normalized
        )
    ):
        msg = "Invalid package-owned path"
        raise ValueError(msg)
    return path.as_posix()


def _paragraphs(text: str) -> Iterable[dict[str, str]]:
    paragraph: dict[str, str] = {}
    current = None
    for line in [*text.splitlines(), ""]:
        if not line:
            if paragraph:
                yield paragraph
                paragraph = {}
                current = None
            continue
        if line[0].isspace():
            if current is None:
                msg = "Package metadata continuation lacks a field"
                raise ValueError(msg)
            paragraph[current] += "\n" + line[1:]
            continue
        if ":" not in line:
            msg = "Package metadata line lacks a field separator"
            raise ValueError(msg)
        field, value = line.split(":", 1)
        if field in paragraph:
            msg = f"Duplicate package metadata field: {field}"
            raise ValueError(msg)
        current = field
        paragraph[field] = value.lstrip()


def _dpkg_info_package(label: str, suffix: str) -> tuple[str, str | None] | None:
    name = label.replace("\\", "/").rsplit("/", 1)[-1]
    if not name.endswith(suffix):
        return None
    stem = name[: -len(suffix)]
    package, separator, architecture = stem.partition(":")
    if DPKG_PACKAGE.fullmatch(package) is None:
        return None
    return package, architecture if separator else None


def parse_dpkg_database(  # noqa: C901, PLR0912, PLR0915 -- One bounded database join.
    status: Buffer, info_files: tuple[MetadataRecord, ...]
) -> PackageDatabase:
    """Parse only supplied same-root dpkg status and info records."""
    gaps = []
    installed: dict[tuple[str, str], tuple[str, str]] = {}
    for paragraph in _paragraphs(_text(status, "dpkg status")):
        if paragraph.get("Status") != "install ok installed":
            continue
        name = paragraph.get("Package", "")
        version = paragraph.get("Version", "")
        architecture = paragraph.get("Architecture", "")
        if (
            DPKG_PACKAGE.fullmatch(name) is None
            or not version
            or not architecture
            or len(version) > MAX_FIELD_CHARS
        ):
            gaps.append("Invalid installed dpkg package record")
            continue
        try:
            debian_version_compare(version, version)
        except ValueError:
            gaps.append(f"Invalid installed dpkg version: {name}")
            continue
        key = name, architecture
        if key in installed:
            gaps.append(f"Duplicate installed dpkg package: {name}:{architecture}")
            continue
        if len(installed) >= MAX_PACKAGES:
            gaps.append("Package limit reached")
            break
        installed[key] = version, "dpkg status"
    files: dict[tuple[str, str | None], dict[str, list[PackageHash]]] = {}
    file_count = 0
    for record in info_files:
        parsed = _dpkg_info_package(record.label, ".list")
        digest_file = False
        if parsed is None:
            parsed = _dpkg_info_package(record.label, ".md5sums")
            digest_file = parsed is not None
        if parsed is None:
            gaps.append(f"Unsupported dpkg info record: {record.label}")
            continue
        owned = files.setdefault(parsed, {})
        for line in _text(record.data, record.label).splitlines():
            if not line:
                continue
            hashes: list[PackageHash] = []
            path_text = line
            if digest_file:
                fields = line.split(None, 1)
                if (
                    len(fields) != FIELD_PARTS
                    or len(fields[0]) != MD5_HEX_CHARS
                    or HEX.fullmatch(fields[0]) is None
                ):
                    gaps.append(f"Invalid dpkg md5sums entry: {record.label}")
                    continue
                hashes.append(PackageHash("MD5", fields[0]))
                path_text = fields[1]
            try:
                path = _path(path_text)
            except ValueError as error:
                gaps.append(f"{record.label}: {error}")
                continue
            if path not in owned:
                file_count += 1
                if file_count > MAX_FILES:
                    gaps.append("Package file limit reached")
                    break
                owned[path] = []
            owned[path].extend(hashes)
        if file_count > MAX_FILES:
            break
    packages = []
    for (name, architecture), (version, source) in installed.items():
        combined: dict[str, list[PackageHash]] = {}
        for key in ((name, None), (name, architecture)):
            for path, hashes in files.get(key, {}).items():
                combined.setdefault(path, []).extend(hashes)
        package_files = tuple(
            PackageFile(path, tuple(sorted(set(hashes), key=lambda item: item.algorithm)))
            for path, hashes in sorted(combined.items())
        )
        if not package_files:
            gaps.append(f"No supplied dpkg file ownership metadata: {name}:{architecture}")
        packages.append(PackageRecord("dpkg", name, version, architecture, package_files, source))
    limited = any("limit reached" in gap for gap in gaps)
    return PackageDatabase(
        tuple(sorted(packages, key=lambda item: (item.name, item.architecture))),
        tuple(gaps),
        limited,
    )


def _apk_checksum(value: str) -> PackageHash | None:
    prefixes: dict[str, tuple[HashAlgorithm, int]] = {
        "Q1": ("SHA-1", 20),
        "Q2": ("SHA-256", 32),
    }
    if value[:2] not in prefixes:
        return None
    algorithm, size = prefixes[value[:2]]
    try:
        decoded = base64.b64decode(value[2:], validate=True)
    except ValueError:
        return None
    if len(decoded) != size:
        return None
    return PackageHash(algorithm, decoded.hex())


def parse_apk_database(  # noqa: C901, PLR0912, PLR0915 -- Stateful installed DB records.
    installed: Buffer,
) -> PackageDatabase:
    """Parse one supplied same-root apk v2 installed database."""
    gaps = []
    packages = []
    current: dict[str, str] = {}
    files: list[PackageFile] = []
    directory = ""
    last_file = -1

    def finish() -> None:
        nonlocal current, files, directory, last_file
        if not current and not files:
            return
        name, version, architecture = current.get("P"), current.get("V"), current.get("A")
        if (
            name is None
            or version is None
            or architecture is None
            or APK_PACKAGE.fullmatch(name) is None
            or len(version) > MAX_FIELD_CHARS
            or len(architecture) > MAX_FIELD_CHARS
        ):
            gaps.append("Invalid installed apk package record")
        elif len(packages) >= MAX_PACKAGES:
            if "Package limit reached" not in gaps:
                gaps.append("Package limit reached")
        else:
            try:
                _apk_tokens(version)
            except ValueError:
                gaps.append(f"Invalid installed apk version: {name}")
            else:
                packages.append(
                    PackageRecord("apk", name, version, architecture, tuple(files), "apk installed")
                )
        current, files, directory, last_file = {}, [], "", -1

    for line in [*_text(installed, "apk installed database").splitlines(), ""]:
        if not line:
            finish()
            continue
        if len(line) < FIELD_PARTS or line[1] != ":":
            gaps.append("Invalid apk installed database line")
            continue
        field, value = line[0], line[2:]
        if field in {"P", "V", "A"}:
            if field in current:
                gaps.append(f"Duplicate apk package field: {field}")
            else:
                current[field] = value
        elif field == "F":
            if value in {"", "."}:
                directory = ""
                continue
            try:
                directory = _path(value)
            except ValueError as error:
                gaps.append(str(error))
                directory = ""
        elif field == "R":
            if len(files) >= MAX_FILES:
                gaps.append("Package file limit reached")
                continue
            try:
                path = _path(f"{directory}/{value}" if directory else value)
            except ValueError as error:
                gaps.append(str(error))
                continue
            files.append(PackageFile(path))
            last_file = len(files) - 1
        elif field == "Z":
            digest = _apk_checksum(value)
            if last_file < 0 or digest is None:
                gaps.append("Invalid apk file checksum")
            else:
                files[last_file] = PackageFile(files[last_file].path, (digest,))
    limited = any("limit reached" in gap for gap in gaps)
    return PackageDatabase(tuple(packages), tuple(gaps), limited)


def package_from_rpm_metadata(  # noqa: C901 -- Bounded RPM identity/digest validation.
    metadata: Mapping[str, object],
    member_paths: Iterable[str] = (),
    member_sha256: Mapping[str, str] | None = None,
) -> PackageRecord:
    """Create ownership evidence from a supplied parsed RPM and its supplied payload members."""
    name = _safe_field(metadata.get("name"), "RPM name")
    version = _safe_field(metadata.get("version"), "RPM version")
    release = _safe_field(metadata.get("release"), "RPM release")
    architecture = _safe_field(metadata.get("arch"), "RPM architecture")
    if RPM_PACKAGE.fullmatch(name) is None:
        msg = "Invalid RPM package name"
        raise ValueError(msg)
    epoch = metadata.get("epoch", 0)
    if type(epoch) is not int or epoch < 0:
        msg = "Invalid RPM epoch"
        raise ValueError(msg)
    evr = f"{epoch}:{version}-{release}" if epoch else f"{version}-{release}"
    _split_rpm(evr)
    hashes = member_sha256 or {}
    files_by_path: dict[str, list[PackageHash]] = {}
    rpm_digests = metadata.get("file_digests", [])
    if not isinstance(rpm_digests, list):
        msg = "Invalid RPM file digest population"
        raise ValueError(msg)  # noqa: TRY004 -- Malformed package metadata is a value error.
    algorithms: dict[int, tuple[HashAlgorithm, int]] = {
        1: ("MD5", 32),
        2: ("SHA-1", 40),
        8: ("SHA-256", 64),
    }
    for entry in rpm_digests:
        if not isinstance(entry, dict):
            msg = "Invalid RPM file digest entry"
            raise ValueError(msg)  # noqa: TRY004 -- Malformed package metadata is a value error.
        path = _path(entry.get("path", ""))
        algorithm = entry.get("algorithm")
        digest = entry.get("digest")
        if type(algorithm) is not int or algorithm not in algorithms or not isinstance(digest, str):
            msg = f"Unsupported RPM file digest: {path}"
            raise ValueError(msg)
        algorithm_name, size = algorithms[algorithm]
        if len(digest) != size or HEX.fullmatch(digest) is None:
            msg = f"Invalid RPM file digest: {path}"
            raise ValueError(msg)
        files_by_path.setdefault(path, []).append(PackageHash(algorithm_name, digest))
    for index, value in enumerate(member_paths):
        if index >= MAX_FILES:
            msg = "RPM member path limit reached"
            raise ValueError(msg)
        path = _path(value)
        files_by_path.setdefault(path, [])
        digest = hashes.get(path)
        if digest is not None:
            if len(digest) != SHA256_HEX_CHARS or HEX.fullmatch(digest) is None:
                msg = f"Invalid RPM member SHA-256: {path}"
                raise ValueError(msg)
            files_by_path[path].append(PackageHash("SHA-256", digest))
    files = tuple(
        PackageFile(path, tuple(sorted(set(values), key=lambda item: item.algorithm)))
        for path, values in sorted(files_by_path.items())
    )
    return PackageRecord("rpm", name, evr, architecture, files, "RPM header/payload")


def _hashes(data: Buffer, algorithms: set[HashAlgorithm]) -> dict[str, str]:
    constructors = {
        "MD5": lambda: hashlib.md5(usedforsecurity=False),
        "SHA-1": lambda: hashlib.sha1(usedforsecurity=False),
        "SHA-256": hashlib.sha256,
    }
    digests = {name: constructors[name]() for name in algorithms}
    for offset in range(0, len(data), HASH_CHUNK_BYTES):
        chunk = data[offset : min(len(data), offset + HASH_CHUNK_BYTES)]
        for digest in digests.values():
            digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def build_ownership_index(database: PackageDatabase) -> PackageOwnershipIndex:
    """Index supplied same-root package paths once for bounded repeated artifact lookup."""
    by_path: dict[str, list[tuple[PackageRecord, PackageFile]]] = {}
    for package in database.packages:
        for package_file in package.files:
            by_path.setdefault(package_file.path, []).append((package, package_file))
    paths = tuple(sorted(by_path))
    return PackageOwnershipIndex(
        paths,
        tuple(tuple(by_path[path]) for path in paths),
    )


def _validate_actual_hashes(actual_hashes: Mapping[str, str]) -> dict[str, str]:
    sizes = {"MD5": MD5_HEX_CHARS, "SHA-1": 40, "SHA-256": SHA256_HEX_CHARS}
    validated = {}
    for algorithm, value in actual_hashes.items():
        if (
            algorithm not in sizes
            or not isinstance(value, str)
            or len(value) != sizes[algorithm]
            or HEX.fullmatch(value) is None
        ):
            msg = f"Invalid supplied artifact hash: {algorithm}"
            raise ValueError(msg)
        validated[algorithm] = value
    return validated


def resolve_ownership_hashes(  # noqa: C901 -- Hash presence/mismatch states are explicit.
    path: str,
    actual_hashes: Mapping[str, str],
    database: PackageDatabase,
    *,
    index: PackageOwnershipIndex | None = None,
) -> OwnershipAssessment:
    """Resolve one artifact from already streamed hashes and supplied same-root metadata."""
    normalized = _path(path)
    actual = _validate_actual_hashes(actual_hashes)
    ownership_index = index or build_ownership_index(database)
    candidates = []
    gaps = list(database.gaps)
    for package, package_file in ownership_index.lookup(normalized):
        declared: dict[str, set[str]] = {}
        for item in package_file.hashes:
            declared.setdefault(item.algorithm, set()).add(item.value)
        if not declared:
            candidates.append(
                OwnershipMatch(
                    package.manager,
                    package.name,
                    package.version,
                    package.architecture,
                    normalized,
                    "package_id",
                    None,
                )
            )
            continue
        missing = sorted(set(declared) - actual.keys())
        conflicting = sorted(name for name, values in declared.items() if len(values) != 1)
        verified = (
            not missing
            and not conflicting
            and all(actual[name] in values for name, values in declared.items())
        )
        if missing:
            gaps.append(
                f"Package file hash not supplied ({','.join(missing)}): {package.name}:{normalized}"
            )
        elif conflicting:
            gaps.append(f"Conflicting package file hashes: {package.name}:{normalized}")
        elif not verified:
            gaps.append(f"Package file hash mismatch: {package.name}:{normalized}")
        candidates.append(
            OwnershipMatch(
                package.manager,
                package.name,
                package.version,
                package.architecture,
                normalized,
                (
                    "artifact_hash_bound"
                    if verified and "SHA-256" in declared
                    else "package_file_hash_match"
                    if verified
                    else "package_id"
                ),
                verified if not missing and not conflicting else None,
            )
        )
    if not candidates:
        status = "unowned"
    elif any(item.hash_verified is False for item in candidates):
        status = "modified"
    elif len(candidates) > 1:
        status = "ambiguous"
    else:
        status = "unique"
    return OwnershipAssessment(status, tuple(candidates), tuple(gaps))


def resolve_ownership(
    path: str,
    artifact: Buffer,
    database: PackageDatabase,
    *,
    index: PackageOwnershipIndex | None = None,
) -> OwnershipAssessment:
    """Relate one supplied artifact to supplied same-root package records only."""
    normalized = _path(path)
    ownership_index = index or build_ownership_index(database)
    algorithms = {
        item.algorithm
        for _, package_file in ownership_index.lookup(normalized)
        for item in package_file.hashes
    }
    return resolve_ownership_hashes(
        normalized,
        _hashes(artifact, algorithms),
        database,
        index=ownership_index,
    )


def _split_debian(value: str) -> tuple[int, str, str]:
    if len(value) > MAX_FIELD_CHARS:
        msg = "Debian version exceeds field limit"
        raise ValueError(msg)
    epoch_text, separator, remainder = value.partition(":")
    if separator:
        if not epoch_text.isascii() or not epoch_text.isdigit():
            msg = "Invalid Debian version epoch"
            raise ValueError(msg)
        epoch = int(epoch_text)
    else:
        epoch, remainder = 0, epoch_text
    upstream, separator, revision = remainder.rpartition("-")
    if not separator:
        upstream, revision = remainder, "0"
    if not upstream:
        msg = "Invalid Debian version"
        raise ValueError(msg)
    if DEBIAN_UPSTREAM.fullmatch(upstream) is None or DEBIAN_REVISION.fullmatch(revision) is None:
        msg = "Invalid Debian version characters"
        raise ValueError(msg)
    return epoch, upstream, revision


def _debian_order(character: str) -> int:
    if character == "~":
        return -1
    if not character:
        return 0
    if character.isalpha() and character.isascii():
        return ord(character)
    return ord(character) + 256


def _debian_part(left: str, right: str) -> int:
    while left or right:
        while (left and not left[0].isdigit()) or (right and not right[0].isdigit()):
            left_char = left[0] if left and not left[0].isdigit() else ""
            right_char = right[0] if right and not right[0].isdigit() else ""
            if _debian_order(left_char) != _debian_order(right_char):
                return -1 if _debian_order(left_char) < _debian_order(right_char) else 1
            left = left[1:] if left_char else left
            right = right[1:] if right_char else right
        left_digits = left[: len(left) - len(left.lstrip("0123456789"))]
        right_digits = right[: len(right) - len(right.lstrip("0123456789"))]
        left = left[len(left_digits) :]
        right = right[len(right_digits) :]
        left_number = left_digits.lstrip("0")
        right_number = right_digits.lstrip("0")
        if len(left_number) != len(right_number):
            return -1 if len(left_number) < len(right_number) else 1
        if left_number != right_number:
            return -1 if left_number < right_number else 1
    return 0


def debian_version_compare(left: str, right: str) -> int:
    left_epoch, left_upstream, left_revision = _split_debian(left)
    right_epoch, right_upstream, right_revision = _split_debian(right)
    if left_epoch != right_epoch:
        return -1 if left_epoch < right_epoch else 1
    result = _debian_part(left_upstream, right_upstream)
    return result or _debian_part(left_revision, right_revision)


def _split_rpm(value: str) -> tuple[int, str, str]:
    if len(value) > MAX_FIELD_CHARS:
        msg = "RPM version exceeds field limit"
        raise ValueError(msg)
    epoch_text, separator, remainder = value.partition(":")
    if separator:
        if not epoch_text.isascii() or not epoch_text.isdigit():
            msg = "Invalid RPM version epoch"
            raise ValueError(msg)
        epoch = int(epoch_text)
    else:
        epoch, remainder = 0, epoch_text
    version, separator, release = remainder.rpartition("-")
    if not separator:
        version, release = remainder, ""
    if not version:
        msg = "Invalid RPM version"
        raise ValueError(msg)
    if RPM_VERSION_PART.fullmatch(version) is None or (
        release and RPM_VERSION_PART.fullmatch(release) is None
    ):
        msg = "Invalid RPM version characters"
        raise ValueError(msg)
    return epoch, version, release


def _rpm_part(left: str, right: str) -> int:  # noqa: C901, PLR0911, PLR0912
    while left or right:
        while left and not left[0].isalnum() and left[0] not in "~^":
            left = left[1:]
        while right and not right[0].isalnum() and right[0] not in "~^":
            right = right[1:]
        if left.startswith("~") or right.startswith("~"):
            if not left.startswith("~"):
                return 1
            if not right.startswith("~"):
                return -1
            left, right = left[1:], right[1:]
            continue
        if left.startswith("^") or right.startswith("^"):
            if left.startswith("^") and not right:
                return 1
            if right.startswith("^") and not left:
                return -1
            if not left.startswith("^"):
                return 1
            if not right.startswith("^"):
                return -1
            left, right = left[1:], right[1:]
            continue
        if not left or not right:
            break
        left_numeric = left[0].isdigit()
        right_numeric = right[0].isdigit()
        pattern = r"\d+" if left_numeric else r"[A-Za-z]+"
        left_match = re.match(pattern, left)
        right_match = re.match(r"\d+" if right_numeric else r"[A-Za-z]+", right)
        if left_match is None or right_match is None:
            msg = "Invalid RPM version segment"
            raise ValueError(msg)
        left_segment, right_segment = left_match[0], right_match[0]
        left, right = left[len(left_segment) :], right[len(right_segment) :]
        if left_numeric != right_numeric:
            return 1 if left_numeric else -1
        if left_numeric:
            left_segment, right_segment = left_segment.lstrip("0"), right_segment.lstrip("0")
            if len(left_segment) != len(right_segment):
                return -1 if len(left_segment) < len(right_segment) else 1
        if left_segment != right_segment:
            return -1 if left_segment < right_segment else 1
    if left == right:
        return 0
    return 1 if left else -1


def rpm_version_compare(left: str, right: str) -> int:
    left_epoch, left_version, left_release = _split_rpm(left)
    right_epoch, right_version, right_release = _split_rpm(right)
    if left_epoch != right_epoch:
        return -1 if left_epoch < right_epoch else 1
    result = _rpm_part(left_version, right_version)
    return result or _rpm_part(left_release, right_release)


def _apk_tokens(  # noqa: C901, PLR0912, PLR0915 -- Mirrors apk token state.
    value: str,
) -> list[tuple[int, int | str, str]]:
    if not value or not value.isascii() or len(value) > MAX_FIELD_CHARS or not value[0].isdigit():
        msg = "Invalid apk version"
        raise ValueError(msg)
    tokens: list[tuple[int, int | str, str]] = []
    match = re.match(r"\d+", value)
    assert match is not None  # noqa: S101 -- Guarded by the digit check.
    raw = match[0]
    tokens.append((APK_TOKEN_INITIAL, int(raw), raw))
    cursor = len(raw)
    previous = APK_TOKEN_INITIAL
    while cursor < len(value):
        character = value[cursor]
        if "a" <= character <= "z" and previous <= APK_TOKEN_DIGIT:
            tokens.append((APK_TOKEN_LETTER, ord(character), character))
            previous, cursor = APK_TOKEN_LETTER, cursor + 1
            continue
        if character == "." or character.isdigit():
            if character == ".":
                if previous > APK_TOKEN_DIGIT:
                    break
                cursor += 1
            match = re.match(r"\d+", value[cursor:])
            if match is None or previous not in {
                APK_TOKEN_INITIAL,
                APK_TOKEN_DIGIT,
                APK_TOKEN_SUFFIX,
            }:
                break
            raw = match[0]
            token = APK_TOKEN_SUFFIX_NUMBER if previous == APK_TOKEN_SUFFIX else APK_TOKEN_DIGIT
            tokens.append((token, int(raw), raw))
            previous, cursor = token, cursor + len(raw)
            continue
        if character == "_" and previous <= APK_TOKEN_SUFFIX_NUMBER:
            match = re.match(r"_([a-z]+)", value[cursor:])
            if match is None or match[1] not in APK_SUFFIXES:
                break
            tokens.append((APK_TOKEN_SUFFIX, APK_SUFFIXES.index(match[1]), match[1]))
            previous, cursor = APK_TOKEN_SUFFIX, cursor + len(match[0])
            continue
        if character == "~" and previous < APK_TOKEN_COMMIT:
            match = re.match(r"~([0-9A-Fa-f]+)", value[cursor:])
            if match is None:
                break
            tokens.append((APK_TOKEN_COMMIT, match[1], match[1]))
            previous, cursor = APK_TOKEN_COMMIT, cursor + len(match[0])
            continue
        if value.startswith("-r", cursor) and previous < APK_TOKEN_REVISION:
            match = re.match(r"-r(\d+)", value[cursor:])
            if match is None:
                break
            tokens.append((APK_TOKEN_REVISION, int(match[1]), match[1]))
            previous, cursor = APK_TOKEN_REVISION, cursor + len(match[0])
            continue
        break
    if cursor != len(value):
        msg = f"Invalid apk version: {value}"
        raise ValueError(msg)
    return tokens


def apk_version_compare(left: str, right: str) -> int:  # noqa: C901
    left_tokens, right_tokens = _apk_tokens(left), _apk_tokens(right)
    for index in range(max(len(left_tokens), len(right_tokens))):
        if index >= len(left_tokens) or index >= len(right_tokens):
            remaining = right_tokens[index] if index >= len(left_tokens) else left_tokens[index]
            side = -1 if index >= len(left_tokens) else 1
            if remaining[0] == APK_TOKEN_SUFFIX and int(remaining[1]) < APK_SUFFIXES.index(""):
                return -side
            return side if remaining[0] < APK_TOKEN_END else 0
        left_token, right_token = left_tokens[index], right_tokens[index]
        if left_token[0] != right_token[0]:
            return -1 if left_token[0] > right_token[0] else 1
        if left_token[0] == APK_TOKEN_DIGIT and (
            left_token[2].startswith("0") or right_token[2].startswith("0")
        ):
            left_value, right_value = left_token[2], right_token[2]
        else:
            left_value, right_value = left_token[1], right_token[1]
        if left_value != right_value:
            if isinstance(left_value, int) and isinstance(right_value, int):
                return -1 if left_value < right_value else 1
            if isinstance(left_value, str) and isinstance(right_value, str):
                return -1 if left_value < right_value else 1
            msg = "Incompatible apk version token values"
            raise ValueError(msg)
    return 0


def load_vendor_snapshot(text: str) -> VendorSnapshot:  # noqa: C901
    if len(text) > MAX_METADATA_BYTES:
        msg = "Vendor snapshot exceeds metadata limit"
        raise ValueError(msg)
    try:
        metadata = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as error:
        msg = "Invalid vendor snapshot JSON"
        raise ValueError(msg) from error
    if not isinstance(metadata, dict) or set(metadata) != {
        "schema_version",
        "snapshot_date",
        "vendor",
        "release",
        "assertions",
    }:
        msg = "Invalid vendor snapshot fields"
        raise ValueError(msg)
    vendor = metadata["vendor"]
    snapshot_date = metadata["snapshot_date"]
    release = metadata["release"]
    if (
        type(metadata["schema_version"]) is not int
        or metadata["schema_version"] != 1
        or not isinstance(vendor, str)
        or vendor not in {"debian", "ubuntu", "redhat"}
        or not isinstance(snapshot_date, str)
        or DATE.fullmatch(snapshot_date) is None
        or not isinstance(release, str)
        or not release
        or len(release) > MAX_FIELD_CHARS
        or not isinstance(metadata["assertions"], list)
        or len(metadata["assertions"]) > MAX_ASSERTIONS
    ):
        msg = "Invalid vendor snapshot schema"
        raise ValueError(msg)
    try:
        date.fromisoformat(snapshot_date)
    except ValueError as error:
        msg = "Invalid vendor snapshot date"
        raise ValueError(msg) from error
    assertions = []
    seen = set()
    package_pattern = RPM_PACKAGE if vendor == "redhat" else DPKG_PACKAGE
    for entry in metadata["assertions"]:
        if not isinstance(entry, dict) or set(entry) != {
            "package",
            "fixed_version",
            "advisory_url",
        }:
            msg = "Invalid vendor assertion fields"
            raise ValueError(msg)
        package = entry["package"]
        fixed = entry["fixed_version"]
        url = entry["advisory_url"]
        parsed = urlparse(url) if isinstance(url, str) else None
        if (
            not isinstance(package, str)
            or len(package) > MAX_FIELD_CHARS
            or package_pattern.fullmatch(package) is None
            or not isinstance(fixed, str)
            or not fixed
            or len(fixed) > MAX_FIELD_CHARS
            or not isinstance(url, str)
            or len(url) > MAX_FIELD_CHARS
            or parsed is None
            or parsed.scheme != "https"
            or not parsed.netloc
        ):
            msg = "Invalid vendor assertion value"
            raise ValueError(msg)
        if package in seen:
            msg = f"Duplicate vendor assertion package: {package}"
            raise ValueError(msg)
        seen.add(package)
        if vendor == "redhat":
            rpm_version_compare(fixed, fixed)
        else:
            debian_version_compare(fixed, fixed)
        assertions.append(VendorAssertion(vendor, release, package, fixed, url, snapshot_date))
    return VendorSnapshot(1, vendor, release, snapshot_date, tuple(assertions))


def assess_vendor_assertions(
    package: PackageRecord, snapshot: VendorSnapshot
) -> tuple[VendorVersionAssessment, ...]:
    expected_manager = {"debian": "dpkg", "ubuntu": "dpkg", "redhat": "rpm"}[snapshot.vendor]
    if package.manager != expected_manager:
        return ()
    compare = rpm_version_compare if snapshot.vendor == "redhat" else debian_version_compare
    results = []
    for assertion in snapshot.assertions:
        if assertion.package != package.name:
            continue
        meets = compare(package.version, assertion.fixed_version) >= 0
        results.append(
            VendorVersionAssessment(
                package.name,
                package.version,
                assertion.fixed_version,
                assertion.vendor,
                assertion.release,
                assertion.advisory_url,
                assertion.snapshot_date,
                "meets_vendor_fixed_version" if meets else "precedes_vendor_fixed_version",
            )
        )
    return tuple(results)
