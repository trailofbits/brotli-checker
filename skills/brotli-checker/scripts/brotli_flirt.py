"""Optional, bounded python-flirt recognition for trusted Brotli PAT bundles."""

from __future__ import annotations

import hashlib
import heapq
import importlib
import importlib.metadata
import json
import re
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, NotRequired, Protocol, TypedDict, cast

from brotli_binary_data import Buffer, normalize_ranges
from brotli_binary_layout import inspect_layout
from brotli_binary_match import (
    EM_386,
    EM_AARCH64,
    EM_ARM,
    EM_PPC64,
    EM_X86_64,
    TARGETS,
    elf_header,
    executable_ranges,
    target_identity,
    valid_patch_functions,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

DEFAULT_FLIRT_BUNDLE = Path(__file__).resolve().parent.parent / "references/brotli-flirt.json"
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_PAT_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 4096
MAX_GROUPS = 4096
MAX_FUNCTIONS_PER_GROUP = 256
MAX_SIGNATURES_PER_FUNCTION = 64
MAX_FUNCTION_BYTES = 64 * 1024
MAX_PAT_RECORD_CHARACTERS = MAX_FUNCTION_BYTES * 2 + 512
MAX_CANDIDATES = 4096
MAX_MATCH_BYTES = 256 * 1024 * 1024
MAX_MATCHES = 128
MAX_REPORTED_GAPS = 128
MAX_REPORTED_SIGNATURES = 64
MAX_PROFILES_PER_MATCH = 64
MIN_FUNCTION_BYTES = 32
MIN_EXACT_RUN_BYTES = 16
MIN_EXACT_DENSITY_NUMERATOR = 1
MIN_EXACT_DENSITY_DENOMINATOR = 2
SCAN_CHUNK_BYTES = 1024 * 1024
EXACT_BYTE = 0xFF
VERSION_PARTS = 3
NAME_PARTS = 3
WILDCARD_BYTE = ".."
SUPPORTED_BACKEND_MINIMUM = (0, 10, 2)
SUPPORTED_BACKEND_MAJOR_MINOR = (0, 10)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,160}")
SYMBOL_PATTERN = re.compile(r"[^\x00-\x20\x7f]{1,256}")
PAT_RECORD_PATTERN = re.compile(
    r"(?P<head>(?:[0-9A-Fa-f]{2}|\.\.){32}) "
    r"00 0000 (?P<size>[0-9A-Fa-f]{4,16}) :0000 "
    r"(?P<identifier>[A-Za-z0-9_.:-]{1,160})"
    r"(?: (?P<tail>(?:[0-9A-Fa-f]{2}|\.\.)+))?"
)
LEGACY_GROUP_FIELDS = {
    "id",
    "machine",
    "elf_class",
    "byteorder",
    "source_sha256",
    "object_sha256",
    "headers_sha256",
    "source",
    "source_state",
    "compiler",
    "flags",
    "build_note",
    "functions",
}
NATIVE_GROUP_FIELDS = LEGACY_GROUP_FIELDS | {"format", "abi"}
NATIVE_PATCH_GROUP_FIELDS = NATIVE_GROUP_FIELDS | {"evidence_scope", "patch_functions"}
PATCH_EVIDENCE_SCOPE = "patch_bearing_population_v1"
IDENTITY_LIMITATION = "FLIRT recognition does not determine target patch status"
TargetIdentity = tuple[str, int, int, str, str]
NATIVE_MACHINES = {
    "i386": EM_386,
    "x86_64": EM_X86_64,
    "arm": EM_ARM,
    "armv7": EM_ARM,
    "aarch64": EM_AARCH64,
    "ppc64": EM_PPC64,
}
NATIVE_MAGICS = (
    b"MZ",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
)


class FlirtUnavailableError(ValueError):
    """The optional python-flirt backend is unavailable or incompatible."""


def flirt_target_candidate(data: Buffer) -> bool:
    return data.startswith(b"\x7fELF") or data.startswith(NATIVE_MAGICS)


class _BackendSignature(Protocol):
    @property
    def names(self) -> list[tuple[str, str, int]]: ...


class _BackendMatcher(Protocol):
    def match(self, data: bytes) -> list[_BackendSignature]: ...


class _Backend(Protocol):
    def parse_pat(self, text: str) -> list[_BackendSignature]: ...

    def compile(self, signatures: list[_BackendSignature]) -> _BackendMatcher: ...


class FlirtAssessment(TypedDict):
    status: Literal[
        "recognized", "partial", "unknown", "limited", "not_requested", "not_applicable"
    ]
    matches: list[dict[str, Any]]
    gaps: list[str]
    limitations: list[str]
    ambiguous_matches: list[dict[str, Any]]
    patch_profiles: NotRequired[list[dict[str, Any]]]


@dataclass(frozen=True)
class FlirtRecord:
    identifier: str
    size: int
    code: bytes
    mask: bytes
    anchor_offset: int
    anchor: bytes
    line: str

    def matches(self, data: bytes) -> bool:
        return len(data) >= self.size and not any(
            (actual ^ expected) & mask
            for actual, expected, mask in zip(data[: self.size], self.code, self.mask, strict=True)
        )


@dataclass(frozen=True)
class FlirtGroup:
    metadata: dict[str, Any]
    functions: dict[str, tuple[str, ...]]

    @property
    def identity(self) -> TargetIdentity:
        return (
            self.metadata.get("format", "elf"),
            self.metadata["machine"],
            self.metadata["elf_class"],
            self.metadata["byteorder"],
            self.metadata.get("abi", "sysv"),
        )

    @property
    def signature_ids(self) -> frozenset[str]:
        return frozenset(identifier for values in self.functions.values() for identifier in values)


@dataclass(frozen=True)
class FlirtCatalog:
    records: dict[str, FlirtRecord]
    groups: tuple[FlirtGroup, ...]
    matchers: dict[tuple[TargetIdentity, str], _BackendMatcher]
    profiles: dict[tuple[TargetIdentity, str], tuple[tuple[FlirtGroup, tuple[str, ...]], ...]]
    identities: dict[TargetIdentity, frozenset[str]]


@dataclass(frozen=True)
class _TargetContext:
    identity: TargetIdentity
    ranges: tuple[tuple[int, int], ...]
    format: str
    slice_index: int | None = None


class FlirtSession:
    """One lazily loaded backend per scan, including explicit unavailable evidence."""

    def __init__(self, path: Path = DEFAULT_FLIRT_BUNDLE) -> None:
        self.path = path
        self.catalog: FlirtCatalog | None = None
        self.error: str | None = None

    def analyze(self, data: Buffer) -> FlirtAssessment:
        if self.catalog is None and self.error is None:
            try:
                self.catalog = load_flirt_bundle(self.path)
            except (OSError, ValueError) as error:
                self.error = f"Automatic FLIRT unavailable: {error}"
        if self.catalog is not None:
            return match_flirt(data, self.catalog)
        return {
            "status": "limited",
            "matches": [],
            "gaps": [self.error or "FLIRT unavailable"],
            "limitations": [IDENTITY_LIMITATION],
            "ambiguous_matches": [],
        }

    def describe(self) -> dict:
        return {
            "status": "unavailable"
            if self.error
            else "enabled"
            if self.catalog
            else "not_applicable",
            "bundle": str(self.path),
            "reason": self.error,
        }


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        msg = f"{label} exceeds the {limit}-byte limit"
        raise ValueError(msg)
    return data


def _supported_backend_version(version: str) -> bool:
    parts = version.split(".")
    parsed = tuple(int(part) for part in parts[:VERSION_PARTS])
    return (
        len(parsed) == VERSION_PARTS
        and parsed[:2] == SUPPORTED_BACKEND_MAJOR_MINOR
        and parsed >= SUPPORTED_BACKEND_MINIMUM
    )


def _load_backend() -> _Backend:
    try:
        version = importlib.metadata.version("python-flirt")
        backend = importlib.import_module("flirt")
    except (ImportError, OSError, importlib.metadata.PackageNotFoundError) as error:
        msg = "python-flirt >=0.10.2,<0.11 is required for FLIRT references"
        raise FlirtUnavailableError(msg) from error
    try:
        supported = _supported_backend_version(version)
    except ValueError as error:
        msg = "python-flirt >=0.10.2,<0.11 is required for FLIRT references"
        raise FlirtUnavailableError(msg) from error
    if not supported:
        msg = "python-flirt >=0.10.2,<0.11 is required"
        raise FlirtUnavailableError(msg)
    if not callable(getattr(backend, "parse_pat", None)) or not callable(
        getattr(backend, "compile", None)
    ):
        msg = "Installed python-flirt does not expose the required API"
        raise FlirtUnavailableError(msg)
    return cast("_Backend", backend)


def _backend_call[T, R](label: str, operation: Callable[[T], R], argument: T) -> R:
    try:
        return operation(argument)
    except (KeyboardInterrupt, SystemExit, GeneratorExit, MemoryError):
        raise
    except BaseException as error:  # PyO3 PanicException intentionally inherits BaseException.
        msg = f"python-flirt could not {label}: {error}"
        raise ValueError(msg) from error


def _decode_tokens(tokens: str) -> tuple[bytes, bytes]:
    code = bytearray()
    mask = bytearray()
    for offset in range(0, len(tokens), 2):
        element = tokens[offset : offset + 2]
        if element == WILDCARD_BYTE:
            code.append(0)
            mask.append(0)
        else:
            code.append(int(element, 16))
            mask.append(EXACT_BYTE)
    return bytes(code), bytes(mask)


def _longest_exact_run(mask: bytes) -> tuple[int, int]:
    best_start = best_size = start = 0
    for end, value in enumerate((*mask, 0)):
        if value == EXACT_BYTE:
            continue
        size = end - start
        if size > best_size:
            best_start, best_size = start, size
        start = end + 1
    return best_start, best_size


def parse_pat_records(data: bytes) -> dict[str, FlirtRecord]:  # noqa: C901
    """Validate and parse the complete strict PAT subset without loading python-flirt."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        msg = "FLIRT PAT must be ASCII"
        raise ValueError(msg) from error
    lines = text.splitlines()
    terminators = [index for index, line in enumerate(lines) if line == "---"]
    if terminators != [len(lines) - 1]:
        msg = "FLIRT PAT must end at one --- terminator"
        raise ValueError(msg)
    records: dict[str, FlirtRecord] = {}
    normalized: dict[tuple[bytes, bytes], str] = {}
    for line in lines[:-1]:
        if line.startswith("#"):
            continue
        if len(line) > MAX_PAT_RECORD_CHARACTERS:
            msg = "FLIRT PAT record exceeds the line limit"
            raise ValueError(msg)
        match = PAT_RECORD_PATTERN.fullmatch(line)
        if match is None:
            msg = (
                "Unsupported FLIRT PAT record; references, aliases, CRCs, and unchecked tails "
                "are rejected"
            )
            raise ValueError(msg)
        identifier = match["identifier"]
        if identifier in records:
            msg = f"Duplicate FLIRT signature id: {identifier}"
            raise ValueError(msg)
        size = int(match["size"], 16)
        tail = match["tail"] or ""
        if not MIN_FUNCTION_BYTES <= size <= MAX_FUNCTION_BYTES or len(tail) != (size - 32) * 2:
            msg = f"FLIRT signature {identifier} has an invalid size or unchecked tail"
            raise ValueError(msg)
        code, mask = _decode_tokens(match["head"] + tail)
        exact = mask.count(EXACT_BYTE)
        anchor_offset, anchor_size = _longest_exact_run(mask)
        if (
            exact * MIN_EXACT_DENSITY_DENOMINATOR < size * MIN_EXACT_DENSITY_NUMERATOR
            or anchor_size < MIN_EXACT_RUN_BYTES
        ):
            msg = f"FLIRT signature {identifier} has insufficient exact bytes"
            raise ValueError(msg)
        anchor_offset += (anchor_size - MIN_EXACT_RUN_BYTES) // 2
        key = (code, mask)
        if previous := normalized.get(key):
            msg = f"Duplicate FLIRT pattern under ids {previous} and {identifier}"
            raise ValueError(msg)
        normalized[key] = identifier
        records[identifier] = FlirtRecord(
            identifier,
            size,
            code,
            mask,
            anchor_offset,
            code[anchor_offset : anchor_offset + MIN_EXACT_RUN_BYTES],
            line,
        )
        if len(records) > MAX_RECORDS:
            msg = "FLIRT PAT record limit reached"
            raise ValueError(msg)
    if not records:
        msg = "FLIRT PAT contains no supported records"
        raise ValueError(msg)
    return records


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and SHA256_PATTERN.fullmatch(value) is not None


def _parse_group(  # noqa: C901
    entry: object, records: dict[str, FlirtRecord]
) -> FlirtGroup:
    if not isinstance(entry, dict) or set(entry) not in (
        LEGACY_GROUP_FIELDS,
        NATIVE_GROUP_FIELDS,
        NATIVE_PATCH_GROUP_FIELDS,
    ):
        msg = "Invalid FLIRT reference group fields"
        raise ValueError(msg)
    native = "format" in entry
    identity = (entry["machine"], entry["elf_class"], entry["byteorder"])
    if (
        type(identity[0]) is not int
        or type(identity[1]) is not int
        or not isinstance(identity[2], str)
        or identity not in TARGETS
        or (
            native
            and (
                entry["format"] not in ("pe", "mach_o")
                or entry["abi"] not in ("windows", "darwin")
                or (entry["format"], entry["abi"]) not in (("pe", "windows"), ("mach_o", "darwin"))
            )
        )
        or (
            "evidence_scope" in entry
            and (
                entry["evidence_scope"] != PATCH_EVIDENCE_SCOPE
                or not valid_patch_functions(entry["patch_functions"])
            )
        )
        or entry["source_state"] not in ("fixed", "vulnerable")
        or not _valid_digest(entry["source_sha256"])
        or not _valid_digest(entry["object_sha256"])
        or not _valid_digest(entry["headers_sha256"])
    ):
        msg = "Invalid FLIRT reference group identity or provenance"
        raise ValueError(msg)
    for field in ("id", "source", "compiler", "flags", "build_note"):
        if not isinstance(entry[field], str) or not entry[field].strip():
            msg = f"Invalid FLIRT reference group {field}"
            raise ValueError(msg)
    if IDENTIFIER_PATTERN.fullmatch(entry["id"]) is None:
        msg = "Invalid FLIRT reference group id"
        raise ValueError(msg)
    functions = entry["functions"]
    if not isinstance(functions, dict) or not 0 < len(functions) <= MAX_FUNCTIONS_PER_GROUP:
        msg = "Invalid FLIRT reference group functions"
        raise ValueError(msg)
    parsed: dict[str, tuple[str, ...]] = {}
    for symbol, identifiers in functions.items():
        if (
            not isinstance(symbol, str)
            or SYMBOL_PATTERN.fullmatch(symbol) is None
            or not isinstance(identifiers, list)
            or not 0 < len(identifiers) <= MAX_SIGNATURES_PER_FUNCTION
            or any(
                not isinstance(identifier, str) or identifier not in records
                for identifier in identifiers
            )
            or len(identifiers) != len(set(identifiers))
        ):
            msg = "Invalid FLIRT function-to-signature mapping"
            raise ValueError(msg)
        parsed[symbol] = tuple(identifiers)
    if "patch_functions" in entry and set(parsed) != {
        name for names in entry["patch_functions"].values() for name in names
    }:
        msg = "Native patch-bearing FLIRT functions do not match their required role population"
        raise ValueError(msg)
    metadata = {key: value for key, value in entry.items() if key != "functions"}
    return FlirtGroup(metadata, parsed)


def _validate_bundle_header(bundle: object) -> str:
    if not isinstance(bundle, dict) or set(bundle) != {
        "schema_version",
        "pat_file",
        "pat_sha256",
        "groups",
    }:
        msg = "Invalid FLIRT bundle fields"
        raise ValueError(msg)
    pat_file = bundle["pat_file"]
    if (
        type(bundle["schema_version"]) is not int
        or bundle["schema_version"] != 1
        or not isinstance(pat_file, str)
        or Path(pat_file).name != pat_file
        or not pat_file.endswith(".pat")
        or not _valid_digest(bundle["pat_sha256"])
        or not isinstance(bundle["groups"], list)
        or not 0 < len(bundle["groups"]) <= MAX_GROUPS
    ):
        msg = "Invalid FLIRT bundle schema, PAT identity, or groups"
        raise ValueError(msg)
    return pat_file


def validate_bundle_data(
    bundle: object, pat_data: bytes
) -> tuple[dict[str, FlirtRecord], tuple[FlirtGroup, ...]]:
    """Validate hash-bound PAT bytes and provenance without loading the optional backend."""
    _validate_bundle_header(bundle)
    validated = cast("dict[str, Any]", bundle)
    if hashlib.sha256(pat_data).hexdigest() != validated["pat_sha256"]:
        msg = "FLIRT PAT hash does not match its bundle"
        raise ValueError(msg)
    records = parse_pat_records(pat_data)
    groups = tuple(_parse_group(entry, records) for entry in validated["groups"])
    group_ids = [group.metadata["id"] for group in groups]
    if len(group_ids) != len(set(group_ids)):
        msg = "Duplicate FLIRT reference group id"
        raise ValueError(msg)
    referenced = set().union(*(group.signature_ids for group in groups))
    if referenced != set(records):
        msg = "Every FLIRT PAT record must be referenced by a group"
        raise ValueError(msg)
    return records, groups


def _compile_identity(
    backend: _Backend, identity: TargetIdentity, records: Iterable[FlirtRecord]
) -> dict[str, _BackendMatcher]:
    selected = sorted(records, key=lambda record: record.identifier)
    text = "\n".join(record.line for record in selected) + "\n---\n"
    signatures = _backend_call("parse the trusted PAT subset", backend.parse_pat, text)
    if not isinstance(signatures, list) or len(signatures) != len(selected):
        msg = "python-flirt returned an unexpected signature population"
        raise ValueError(msg)
    expected = {record.identifier for record in selected}
    actual = set()
    for signature in signatures:
        names = signature.names
        if (
            not isinstance(names, list)
            or len(names) != 1
            or not isinstance(names[0], tuple)
            or len(names[0]) != NAME_PARTS
            or names[0][1:] != ("public", 0)
            or names[0][0] not in expected
        ):
            msg = "python-flirt did not preserve the single-name PAT contract"
            raise ValueError(msg)
        actual.add(names[0][0])
    if actual != expected:
        msg = f"python-flirt lost or duplicated signatures for ELF identity {identity}"
        raise ValueError(msg)
    return {
        signature.names[0][0]: _backend_call(
            "compile a trusted PAT record", backend.compile, [signature]
        )
        for signature in signatures
    }


def load_flirt_bundle(path: Path, *, backend: _Backend | None = None) -> FlirtCatalog:
    """Load and compile a hash-bound, generated PAT bundle without inspecting a target."""
    try:
        bundle = json.loads(_read_bounded(path, MAX_BUNDLE_BYTES, "FLIRT bundle"))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        msg = "Invalid FLIRT bundle JSON"
        raise ValueError(msg) from error
    pat_file = _validate_bundle_header(bundle)
    pat_path = path.parent / pat_file
    if pat_path.is_symlink() or pat_path.resolve().parent != path.parent.resolve():
        msg = "FLIRT PAT must be a regular adjacent file"
        raise ValueError(msg)
    pat_data = _read_bounded(pat_path, MAX_PAT_BYTES, "FLIRT PAT")
    records, groups = validate_bundle_data(bundle, pat_data)
    selected_backend = backend if backend is not None else _load_backend()
    matchers: dict[tuple[TargetIdentity, str], _BackendMatcher] = {}
    for identity in sorted({group.identity for group in groups}):
        identifiers = set().union(
            *(group.signature_ids for group in groups if group.identity == identity)
        )
        compiled = _compile_identity(
            selected_backend, identity, (records[identifier] for identifier in identifiers)
        )
        matchers.update(
            ((identity, identifier), matcher) for identifier, matcher in compiled.items()
        )
    profiles: dict[tuple[TargetIdentity, str], list[tuple[FlirtGroup, tuple[str, ...]]]] = {}
    identities: dict[TargetIdentity, set[str]] = {}
    for group in groups:
        identities.setdefault(group.identity, set()).update(group.signature_ids)
        names_by_identifier: dict[str, list[str]] = {}
        for symbol, identifiers in group.functions.items():
            for identifier in identifiers:
                names_by_identifier.setdefault(identifier, []).append(symbol)
        for identifier, names in names_by_identifier.items():
            profiles.setdefault((group.identity, identifier), []).append(
                (group, tuple(sorted(names)))
            )
    return FlirtCatalog(
        records,
        groups,
        matchers,
        {key: tuple(value) for key, value in profiles.items()},
        {key: frozenset(value) for key, value in identities.items()},
    )


def _candidate_starts(  # noqa: C901
    data: Buffer,
    records: dict[str, FlirtRecord],
    ranges: list[tuple[int, int]],
) -> tuple[dict[int, set[str]], bool]:
    anchors: dict[bytes, list[tuple[int, str]]] = {}
    for record in records.values():
        anchors.setdefault(record.anchor, []).append((record.anchor_offset, record.identifier))
    union, starts, coverage_ends = normalize_ranges(ranges)
    candidates: dict[int, set[str]] = {}
    count = 0
    for union_start, union_end in union:
        for position in range(union_start, union_end, SCAN_CHUNK_BYTES):
            core_end = min(union_end, position + SCAN_CHUNK_BYTES)
            chunk = data[position : min(union_end, core_end + MIN_EXACT_RUN_BYTES - 1)]
            streams = (_anchor_offsets(chunk, anchor) for anchor in sorted(anchors))
            for relative_anchor, anchor in heapq.merge(*streams):
                absolute_anchor = position + relative_anchor
                if absolute_anchor >= core_end:
                    break
                for anchor_offset, identifier in anchors[anchor]:
                    candidate = absolute_anchor - anchor_offset
                    owner = bisect_right(starts, candidate) - 1
                    record = records[identifier]
                    if owner < 0 or candidate + record.size > coverage_ends[owner]:
                        continue
                    count += 1
                    if count > MAX_CANDIDATES:
                        return candidates, True
                    candidates.setdefault(candidate, set()).add(identifier)
    return candidates, False


def _anchor_offsets(data: bytes, anchor: bytes) -> Iterable[tuple[int, bytes]]:
    cursor = 0
    while True:
        found = data.find(anchor, cursor)
        if found < 0:
            return
        yield found, anchor
        cursor = found + 1


def _profiles_for_signature(
    profiles_for_signature: tuple[tuple[FlirtGroup, tuple[str, ...]], ...],
) -> tuple[list[dict[str, Any]], list[str]]:
    profiles = []
    names = set()
    for group, symbols in profiles_for_signature:
        names.update(symbols)
        if len(profiles) < MAX_PROFILES_PER_MATCH:
            profiles.append(
                {
                    **group.metadata,
                    "source_state_provenance": group.metadata["source_state"],
                    "source_state": "provenance_only",
                    "candidate_names": symbols,
                }
            )
    return profiles, sorted(names)


def _target_contexts(data: Buffer) -> tuple[tuple[_TargetContext, ...], tuple[str, ...]]:
    if data.startswith(b"\x7fELF"):
        header = elf_header(data)
        _, ranges = executable_ranges(data)
        machine, bits, byteorder = target_identity(header)
        return (
            _TargetContext(("elf", machine, bits, byteorder, "sysv"), tuple(ranges), "elf"),
        ), ()
    layout = inspect_layout(data)
    if layout["kind"] not in {"pe", "mach_o", "mach_o_universal"}:
        msg = f"FLIRT target format is unsupported: {layout['kind']}"
        raise ValueError(msg)
    rows = layout["slices"] or [layout]
    contexts = []
    gaps = []
    for index, row in enumerate(rows):
        gaps.extend(str(gap) for gap in row["gaps"])
        machine = NATIVE_MACHINES.get(row["machine"])
        candidate = (machine, row["bits"], row["byteorder"])
        if machine is None or candidate not in TARGETS:
            gaps.append(f"Unsupported {row['kind']} FLIRT target identity: {row['machine']}")
            continue
        ranges = tuple(
            (item["file_offset"], item["size"])
            for item in row["ranges"]["executable"]
            if item["size"]
        )
        if not ranges:
            gaps.append(f"{row['kind']} has no validated executable file ranges")
            continue
        if row["kind"] == "pe":
            format_name, abi = "pe", "windows"
        else:
            format_name, abi = "mach_o", "darwin"
        contexts.append(
            _TargetContext(
                (format_name, machine, row["bits"], row["byteorder"], abi),
                ranges,
                format_name,
                index if layout["slices"] else None,
            )
        )
    if not contexts:
        msg = "; ".join(gaps) or "target has no supported executable layout"
        raise ValueError(msg)
    return tuple(contexts), tuple(gaps)


def _match_flirt_context(  # noqa: C901, PLR0912, PLR0915
    data: Buffer, catalog: FlirtCatalog, context: _TargetContext
) -> FlirtAssessment:
    limitations = [IDENTITY_LIMITATION]
    gaps: list[str] = []
    ambiguous_matches: list[dict[str, Any]] = []
    ambiguity_count = 0
    identity = context.identity
    compatible_ids = catalog.identities.get(identity)
    if not compatible_ids:
        if not any(value[0] == context.format for value in catalog.identities):
            return {
                "status": "not_applicable",
                "matches": [],
                "gaps": [],
                "limitations": limitations,
                "ambiguous_matches": [],
            }
        target = TARGETS[identity[1:4]][0]
        gap = f"No FLIRT references for {context.format} {target}"
        return {
            "status": "unknown",
            "matches": [],
            "gaps": [gap],
            "limitations": limitations,
            "ambiguous_matches": [],
        }
    records = {identifier: catalog.records[identifier] for identifier in compatible_ids}
    candidates, candidate_collection_limited = _candidate_starts(
        data, records, list(context.ranges)
    )
    limited = candidate_collection_limited
    if candidate_collection_limited:
        gap = "FLIRT candidate limit reached; recognition is incomplete"
        gaps.append(gap)
        limitations.append(gap)
    matches = []
    bytes_examined = 0
    stop = False
    for offset, candidate_ids in sorted(candidates.items()):
        size = max(records[identifier].size for identifier in candidate_ids)
        if bytes_examined + size > MAX_MATCH_BYTES:
            gap = "FLIRT target-byte work limit reached; recognition is incomplete"
            gaps.append(gap)
            limitations.append(gap)
            limited = True
            break
        sample = data[offset : offset + size]
        identifiers = []
        for identifier in sorted(candidate_ids):
            record = records[identifier]
            if bytes_examined + record.size > MAX_MATCH_BYTES:
                gap = "FLIRT signature-comparison work limit reached; recognition is incomplete"
                gaps.append(gap)
                limitations.append(gap)
                limited = stop = True
                break
            bytes_examined += record.size
            function = sample[: record.size]
            if not record.matches(function):
                continue
            matcher = catalog.matchers[(identity, identifier)]
            try:
                backend_matches = _backend_call(
                    "match a bounded target function", matcher.match, function
                )
            except ValueError as error:
                gap = str(error)
                gaps.append(gap)
                limitations.append(gap)
                limited = stop = True
                break
            names = [result.names for result in backend_matches]
            if names != [[(identifier, "public", 0)]]:
                gap = f"python-flirt returned an inconsistent result for {identifier}"
                gaps.append(gap)
                limitations.append(gap)
                limited = stop = True
                break
            identifiers.append(identifier)
        if stop:
            break
        identifiers = sorted(set(identifiers))
        if len(identifiers) > 1:
            ambiguity_count += 1
            if len(ambiguous_matches) < MAX_REPORTED_GAPS:
                ambiguous_matches.append(
                    {
                        "kind": "ambiguous_candidate",
                        "file_offset": offset,
                        "format": context.format,
                        **(
                            {"slice_index": context.slice_index}
                            if context.slice_index is not None
                            else {}
                        ),
                        "signature_count": len(identifiers),
                        "signature_ids": identifiers[:MAX_REPORTED_SIGNATURES],
                    }
                )
            elif "FLIRT ambiguity reporting limit reached" not in limitations:
                limitations.append("FLIRT ambiguity reporting limit reached")
            continue
        if len(identifiers) != 1:
            continue
        if len(matches) >= MAX_MATCHES:
            gap = "FLIRT match reporting limit reached; recognition is incomplete"
            gaps.append(gap)
            limitations.append(gap)
            limited = True
            break
        identifier = identifiers[0]
        record = records[identifier]
        profile_index = catalog.profiles[(identity, identifier)]
        profiles, candidate_names = _profiles_for_signature(profile_index)
        profile_count = len(profile_index)
        if profile_count > len(profiles) and not any(
            value.startswith("FLIRT profile reporting limit reached") for value in limitations
        ):
            gap = "FLIRT profile reporting limit reached; provenance is incomplete"
            gaps.append(gap)
            limitations.append(gap)
        matches.append(
            {
                "signature_id": identifier,
                "file_offset": offset,
                "size_bytes": record.size,
                "format": context.format,
                **({"slice_index": context.slice_index} if context.slice_index is not None else {}),
                "method": "python_flirt_full_function_pattern",
                "candidate_names": candidate_names,
                "definitive_name": candidate_names[0]
                if len(candidate_names) == 1 and not candidate_collection_limited
                else None,
                "ambiguity_complete": not candidate_collection_limited,
                "compatible_profile_count": profile_count,
                "compatible_profiles": profiles,
            }
        )
    if ambiguity_count:
        gaps.append(
            f"{ambiguity_count} FLIRT candidate(s) matched multiple signatures; names unresolved"
        )
    matched_ids = {row["signature_id"] for row in matches}
    patch_profiles = []
    if not limited and not ambiguity_count:
        patch_profiles.extend(
            {
                **group.metadata,
                "method": "native_flirt_patch_bearing_population",
                "source_state_provenance": group.metadata["source_state"],
                "source_state": "provenance_only",
                "target_patch_status": "unknown",
                "matched_signature_ids": sorted(group.signature_ids),
            }
            for group in catalog.groups
            if (
                group.identity == identity
                and group.metadata.get("evidence_scope") == PATCH_EVIDENCE_SCOPE
                and group.signature_ids <= matched_ids
            )
        )
    if limited:
        status: Literal["recognized", "partial", "unknown", "limited", "not_applicable"] = "limited"
    elif matches:
        status = "recognized"
    elif gaps:
        status = "partial"
    else:
        status = "unknown"
    return {
        "status": status,
        "matches": matches,
        "gaps": gaps,
        "limitations": limitations,
        "ambiguous_matches": ambiguous_matches,
        "patch_profiles": patch_profiles,
    }


def match_flirt(data: Buffer, catalog: FlirtCatalog) -> FlirtAssessment:  # noqa: C901
    """Recognize independent full-function patterns; never infer target patch state."""
    try:
        contexts, layout_gaps = _target_contexts(data)
    except ValueError as error:
        return {
            "status": "unknown",
            "matches": [],
            "gaps": [f"FLIRT target unsupported: {error}"],
            "limitations": [IDENTITY_LIMITATION],
            "ambiguous_matches": [],
        }
    matches = []
    gaps = [f"FLIRT layout limitation: {gap}" for gap in layout_gaps]
    limitations = [IDENTITY_LIMITATION]
    ambiguous = []
    patch_profiles = []
    limited = False
    statuses = []
    for context in contexts:
        result = _match_flirt_context(data, catalog, context)
        statuses.append(result["status"])
        matches.extend(result["matches"])
        gaps.extend(result["gaps"])
        limitations.extend(item for item in result["limitations"] if item not in limitations)
        ambiguous.extend(result["ambiguous_matches"])
        patch_profiles.extend(result.get("patch_profiles", []))
        limited = limited or result["status"] == "limited"
    if len(matches) > MAX_MATCHES:
        matches = matches[:MAX_MATCHES]
        gaps.append("FLIRT aggregate match reporting limit reached; recognition is incomplete")
        limited = True
    if len(ambiguous) > MAX_REPORTED_GAPS:
        ambiguous = ambiguous[:MAX_REPORTED_GAPS]
        limitations.append("FLIRT aggregate ambiguity reporting limit reached")
    if limited:
        status: Literal["recognized", "partial", "unknown", "limited", "not_applicable"] = "limited"
    elif matches:
        status = "recognized"
    elif statuses and all(item == "not_applicable" for item in statuses):
        status = "not_applicable"
    elif statuses and all(item in ("unknown", "not_applicable") for item in statuses):
        status = "unknown"
    elif gaps:
        status = "partial"
    else:
        status = "unknown"
    return {
        "status": status,
        "matches": matches,
        "gaps": gaps,
        "limitations": limitations,
        "ambiguous_matches": ambiguous,
        "patch_profiles": patch_profiles,
    }
