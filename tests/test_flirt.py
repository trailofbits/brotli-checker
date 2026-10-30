import hashlib
import json
from dataclasses import dataclass, replace
from types import SimpleNamespace

import brotli_flirt as subject
import pytest
from brotli_binary_data import file_data
from test_binary_match import elf


@dataclass(frozen=True)
class FakeSignature:
    names: list[tuple[str, str, int]]
    record: subject.FlirtRecord


class FakeMatcher:
    def __init__(self, signatures):
        self.signatures = signatures

    def match(self, data):
        return [signature for signature in self.signatures if signature.record.matches(data)]


class FakeBackend:
    def parse_pat(self, text):
        records = subject.parse_pat_records(text.encode())
        return [FakeSignature([(name, "public", 0)], record) for name, record in records.items()]

    def compile(self, signatures):
        return FakeMatcher(signatures)


class BackendPanic(BaseException):
    pass


class PanicBackend(FakeBackend):
    def parse_pat(self, text):
        del text
        msg = "parser panic"
        raise BackendPanic(msg)


class PanicMatcher:
    def match(self, data):
        del data
        msg = "matcher panic"
        raise BackendPanic(msg)


def pattern(code, identifier, wildcards=()):
    mask = bytearray(b"\xff" * len(code))
    for offset in wildcards:
        mask[offset] = 0
    rendered = "".join(
        f"{value:02X}" if selected else ".." for value, selected in zip(code, mask, strict=True)
    )
    return f"{rendered[:64]} 00 0000 {len(code):04X} :0000 {identifier} {rendered[64:]}"


def group(
    functions,
    *,
    identifier="profile",
    machine=183,
    state="fixed",
    native=None,
):
    result = {
        "id": identifier,
        "machine": machine,
        "elf_class": 64,
        "byteorder": "little",
        "source_sha256": "a" * 64,
        "object_sha256": "b" * 64,
        "headers_sha256": "c" * 64,
        "source": "trusted fixture",
        "source_state": state,
        "compiler": "fixture compiler",
        "flags": "-O2",
        "build_note": "reviewed pristine fixture headers",
        "functions": functions,
    }
    if native is not None:
        format_name, abi = native
        result.update(format=format_name, abi=abi)
    return result


def write_bundle(tmp_path, lines, groups):
    pat = tmp_path / "fixture.pat"
    pat.write_text("\n".join([*lines, "---", ""]))
    bundle = tmp_path / "fixture.json"
    bundle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "pat_file": pat.name,
                "pat_sha256": hashlib.sha256(pat.read_bytes()).hexdigest(),
                "groups": groups,
            }
        )
    )
    return bundle


def code(seed, size=64):
    return (hashlib.sha256(seed).digest() * ((size + 31) // 32))[:size]


def load(tmp_path, lines, groups):
    return subject.load_flirt_bundle(write_bundle(tmp_path, lines, groups), backend=FakeBackend())


def test_catalog_byte_limits_accept_boundary_and_reject_overflow(tmp_path, monkeypatch):
    function = code(b"catalog-size")
    bundle = write_bundle(tmp_path, [pattern(function, "size")], [group({"Decode": ["size"]})])
    pat = tmp_path / "fixture.pat"
    monkeypatch.setattr(subject, "MAX_BUNDLE_BYTES", bundle.stat().st_size)
    monkeypatch.setattr(subject, "MAX_PAT_BYTES", pat.stat().st_size)
    assert subject.load_flirt_bundle(bundle, backend=FakeBackend()).records
    pat.write_bytes(pat.read_bytes() + b" ")
    with pytest.raises(ValueError, match="limit"):
        subject.load_flirt_bundle(bundle, backend=FakeBackend())
    bundle.write_bytes(bundle.read_bytes() + b" ")
    with pytest.raises(ValueError, match="limit"):
        subject.load_flirt_bundle(bundle, backend=FakeBackend())


def test_minimum_function_and_exact_half_density_remain_valid():
    minimal = pattern(code(b"minimum", 32), "minimum").rstrip()
    assert subject.parse_pat_records((minimal + "\n---\n").encode())["minimum"].size == 32
    half = pattern(code(b"half", 64), "half", wildcards=range(32, 64))
    assert subject.parse_pat_records((half + "\n---\n").encode())["half"].size == 64


@pytest.mark.parametrize(
    "wildcards",
    [range(31, 64), [*range(15, 64, 2), 14]],
    ids=["insufficient-density-with-long-run", "insufficient-run-with-density"],
)
def test_density_and_contiguous_anchor_strength_are_independent(wildcards):
    weak = pattern(code(b"independent-strength", 64), "weak", wildcards=wildcards)
    with pytest.raises(ValueError, match="insufficient exact"):
        subject.parse_pat_records((weak + "\n---\n").encode())


def test_individual_full_function_match_is_identity_only(tmp_path):
    first = code(b"first")
    second = code(b"second")
    catalog = load(
        tmp_path,
        [pattern(first, "first"), pattern(second, "second")],
        [group({"DecodeLiteralBlockSwitch": ["first"], "UnrelatedApi": ["second"]})],
    )

    assessment = subject.match_flirt(elf(b"prefix" + first), catalog)

    assert assessment["status"] == "recognized"
    assert assessment["gaps"] == []
    assert assessment["ambiguous_matches"] == []
    assert len(assessment["matches"]) == 1
    match = assessment["matches"][0]
    assert match["signature_id"] == "first"
    assert match["candidate_names"] == ["DecodeLiteralBlockSwitch"]
    assert match["definitive_name"] == "DecodeLiteralBlockSwitch"
    assert match["ambiguity_complete"] is True
    assert match["compatible_profiles"][0]["source_state"] == "provenance_only"
    assert match["compatible_profiles"][0]["source_state_provenance"] == "fixed"
    assert "patch" not in json.dumps(match).lower()
    assert assessment["limitations"] == [subject.IDENTITY_LIMITATION]


def test_tail_bytes_and_executable_segment_scope_are_checked(tmp_path):
    function = code(b"tail", 96)
    catalog = load(
        tmp_path,
        [pattern(function, "tail")],
        [group({"ProcessCommands": ["tail"]})],
    )
    modified = function[:80] + bytes((function[80] ^ 1,)) + function[81:]

    assert subject.match_flirt(elf(modified), catalog)["status"] == "unknown"
    assert subject.match_flirt(elf(function, flags=4), catalog)["status"] == "unknown"


def test_file_backed_data_uses_the_same_bounded_match_path(tmp_path):
    function = code(b"file-data")
    catalog = load(
        tmp_path,
        [pattern(function, "file_data")],
        [group({"SafeProcessCommands": ["file_data"]})],
    )
    target = tmp_path / "target"
    target.write_bytes(elf(function))

    with target.open("rb") as stream, file_data(stream) as data:
        assessment = subject.match_flirt(data, catalog)

    assert assessment["status"] == "recognized"


def test_anchor_split_across_scan_chunks_matches_when_function_fits_segment(tmp_path, monkeypatch):
    function = bytes(range(64))
    catalog = load(
        tmp_path,
        [pattern(function, "split")],
        [group({"ProcessCommands": ["split"]})],
    )
    monkeypatch.setattr(subject, "SCAN_CHUNK_BYTES", 64)
    record = catalog.records["split"]
    prefix_size = subject.SCAN_CHUNK_BYTES - 4 - record.anchor_offset
    assert prefix_size > 0

    assessment = subject.match_flirt(elf(b"P" * prefix_size + function), catalog)

    assert assessment["status"] == "recognized"
    assert assessment["matches"][0]["signature_id"] == "split"


def test_candidate_must_fit_one_original_segment_and_cannot_start_before_range(tmp_path):
    function = bytes(range(64))
    catalog = load(
        tmp_path,
        [pattern(function, "owned")],
        [group({"ProcessCommands": ["owned"]})],
    )
    record = catalog.records["owned"]

    adjacent, adjacent_limited = subject._candidate_starts(  # noqa: SLF001
        function,
        {"owned": record},
        [(0, 40), (40, 24)],
    )
    before, before_limited = subject._candidate_starts(  # noqa: SLF001
        record.anchor + bytes(record.size),
        {"owned": record},
        [(0, record.size + len(record.anchor))],
    )

    assert adjacent == {}
    assert adjacent_limited is False
    assert before == {}
    assert before_limited is False


def test_self_overlapping_anchor_does_not_hide_true_function_start(tmp_path):
    function = b"A" * 16 + bytes(range(48))
    catalog = load(
        tmp_path,
        [pattern(function, "overlap", wildcards=(*range(16, 33), 48))],
        [group({"ProcessCommands": ["overlap"]})],
    )
    assert catalog.records["overlap"].anchor_offset == 0

    assessment = subject.match_flirt(elf(b"A" + function), catalog)

    assert assessment["status"] == "recognized"
    assert assessment["matches"][0]["signature_id"] == "overlap"


def test_centered_anchor_avoids_generic_prologue_candidate_exhaustion(tmp_path, monkeypatch):
    function = b"A" * 16 + bytes(range(48))
    catalog = load(
        tmp_path,
        [pattern(function, "centered")],
        [group({"ProcessCommands": ["centered"]})],
    )
    record = catalog.records["centered"]
    assert record.anchor_offset == 24
    decoy = b"A" * 16 + b"Z" * 48
    target = elf(decoy * 10 + function)
    monkeypatch.setattr(subject, "MAX_CANDIDATES", 4)

    old_record = replace(record, anchor_offset=0, anchor=function[:16])
    old_catalog = replace(catalog, records={"centered": old_record})
    old_assessment = subject.match_flirt(target, old_catalog)
    centered_assessment = subject.match_flirt(target, catalog)

    assert old_assessment["status"] == "limited"
    assert old_assessment["matches"] == []
    assert centered_assessment["status"] == "recognized"
    assert centered_assessment["matches"][0]["definitive_name"] == "ProcessCommands"


def test_overlapping_patterns_are_reported_as_ambiguity_not_named(tmp_path):
    function = code(b"collision")
    catalog = load(
        tmp_path,
        [pattern(function, "exact"), pattern(function, "broad", wildcards=(40,))],
        [
            group({"DecodeCommandBlockSwitch": ["exact"]}, identifier="exact_profile"),
            group({"OtherCandidate": ["broad"]}, identifier="broad_profile"),
        ],
    )

    assessment = subject.match_flirt(elf(function), catalog)

    assert assessment["status"] == "partial"
    assert assessment["matches"] == []
    assert assessment["gaps"] == [
        "1 FLIRT candidate(s) matched multiple signatures; names unresolved"
    ]
    assert assessment["ambiguous_matches"][0]["signature_ids"] == ["broad", "exact"]


def test_one_signature_can_carry_bounded_multi_profile_provenance(tmp_path):
    function = code(b"shared")
    catalog = load(
        tmp_path,
        [pattern(function, "shared")],
        [
            group({"NameA": ["shared"]}, identifier="fixed", state="fixed"),
            group({"NameB": ["shared"]}, identifier="vulnerable", state="vulnerable"),
        ],
    )

    match = subject.match_flirt(elf(function), catalog)["matches"][0]

    assert match["candidate_names"] == ["NameA", "NameB"]
    assert match["definitive_name"] is None
    assert {profile["source_state_provenance"] for profile in match["compatible_profiles"]} == {
        "fixed",
        "vulnerable",
    }


def test_profile_limit_keeps_all_names_and_total_count(tmp_path, monkeypatch):
    function = code(b"profile-limit")
    catalog = load(
        tmp_path,
        [pattern(function, "shared")],
        [
            group({"NameA": ["shared"]}, identifier="profile_a"),
            group({"NameB": ["shared"]}, identifier="profile_b"),
            group({"NameC": ["shared"]}, identifier="profile_c"),
        ],
    )
    monkeypatch.setattr(subject, "MAX_PROFILES_PER_MATCH", 1)

    assessment = subject.match_flirt(elf(function), catalog)

    assert assessment["status"] == "recognized"
    match = assessment["matches"][0]
    assert match["candidate_names"] == ["NameA", "NameB", "NameC"]
    assert match["compatible_profile_count"] == 3
    assert len(match["compatible_profiles"]) == 1
    assert any("profile reporting limit" in gap for gap in assessment["gaps"])


@pytest.mark.parametrize(
    "bad_line",
    [
        lambda line: line.replace(" 00 0000 ", " 01 1234 "),
        lambda line: line + " ^0040 external",
        lambda line: line.replace(" :0000 fixture ", " :0000 fixture :0001 alias "),
        lambda line: line[:-2],
        lambda line: "." * 64 + line[64:].rsplit(" ", 1)[0] + " " + "." * 64,
    ],
)
def test_unsupported_or_weak_pat_records_are_rejected(tmp_path, bad_line):
    function = code(b"strict")
    line = bad_line(pattern(function, "fixture"))
    bundle = write_bundle(tmp_path, [line], [group({"Function": ["fixture"]})])

    with pytest.raises(ValueError, match=r"FLIRT|Unsupported"):
        subject.load_flirt_bundle(bundle, backend=FakeBackend())


def test_duplicate_patterns_and_unreferenced_records_are_rejected(tmp_path):
    function = code(b"duplicate")
    duplicate = pattern(function, "second").replace("second", "second")
    bundle = write_bundle(
        tmp_path,
        [pattern(function, "first"), duplicate],
        [group({"Function": ["first"]})],
    )

    with pytest.raises(ValueError, match="Duplicate FLIRT pattern"):
        subject.load_flirt_bundle(bundle, backend=FakeBackend())


def test_hash_and_adjacent_path_binding_are_enforced(tmp_path):
    function = code(b"binding")
    bundle = write_bundle(
        tmp_path,
        [pattern(function, "fixture")],
        [group({"Function": ["fixture"]})],
    )
    content = json.loads(bundle.read_text())
    content["pat_sha256"] = "0" * 64
    bundle.write_text(json.dumps(content))
    with pytest.raises(ValueError, match="hash"):
        subject.load_flirt_bundle(bundle, backend=FakeBackend())

    content["pat_file"] = "../fixture.pat"
    bundle.write_text(json.dumps(content))
    with pytest.raises(ValueError, match="schema"):
        subject.load_flirt_bundle(bundle, backend=FakeBackend())


def test_recursive_json_parser_failure_is_invalid_bundle(tmp_path, monkeypatch):
    bundle = tmp_path / "recursive.json"
    bundle.write_text("{}")

    def recursive(_data):
        raise RecursionError

    monkeypatch.setattr(subject.json, "loads", recursive)
    with pytest.raises(ValueError, match="Invalid FLIRT bundle JSON"):
        subject.load_flirt_bundle(bundle, backend=FakeBackend())


def test_oversize_pat_line_is_rejected_before_record_regex():
    line = b"A" * (subject.MAX_PAT_RECORD_CHARACTERS + 1)

    with pytest.raises(ValueError, match="line limit"):
        subject.parse_pat_records(line + b"\n---\n")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda entry: entry.pop("headers_sha256"),
        lambda entry: entry.update(headers_sha256="not-a-digest"),
        lambda entry: entry.update(build_note=""),
        lambda entry: entry.update(byteorder=["little"]),
    ],
)
def test_required_group_provenance_is_validated(tmp_path, mutate):
    function = code(b"provenance")
    entry = group({"Function": ["fixture"]})
    mutate(entry)
    bundle = write_bundle(tmp_path, [pattern(function, "fixture")], [entry])

    with pytest.raises(ValueError, match=r"group fields|identity or provenance|build_note"):
        subject.load_flirt_bundle(bundle, backend=FakeBackend())


def test_boolean_bundle_schema_version_is_rejected(tmp_path):
    function = code(b"schema-boolean")
    bundle = write_bundle(
        tmp_path,
        [pattern(function, "fixture")],
        [group({"Function": ["fixture"]})],
    )
    content = json.loads(bundle.read_text())
    content["schema_version"] = True
    bundle.write_text(json.dumps(content))

    with pytest.raises(ValueError, match="Invalid FLIRT bundle schema"):
        subject.load_flirt_bundle(bundle, backend=FakeBackend())


def test_candidate_limit_is_an_explicit_incomplete_result(tmp_path, monkeypatch):
    function = code(b"limit")
    catalog = load(
        tmp_path,
        [pattern(function, "fixture")],
        [group({"Function": ["fixture"]})],
    )
    monkeypatch.setattr(subject, "MAX_CANDIDATES", 0)

    assessment = subject.match_flirt(elf(function), catalog)

    assert assessment["status"] == "limited"
    assert assessment["matches"] == []
    assert any("candidate limit" in value for value in assessment["limitations"])


def test_candidate_limit_never_retains_a_definitive_name(tmp_path, monkeypatch):
    function = code(b"limited-name")
    catalog = load(
        tmp_path,
        [pattern(function, "fixture")],
        [group({"Function": ["fixture"]})],
    )
    monkeypatch.setattr(subject, "MAX_CANDIDATES", 1)

    assessment = subject.match_flirt(elf(function + b"padding" + function), catalog)

    assert assessment["status"] == "limited"
    assert len(assessment["matches"]) == 1
    assert assessment["matches"][0]["definitive_name"] is None
    assert assessment["matches"][0]["ambiguity_complete"] is False


def test_match_output_limit_is_an_explicit_incomplete_result(tmp_path, monkeypatch):
    function = code(b"match-limit")
    catalog = load(
        tmp_path,
        [pattern(function, "fixture")],
        [group({"Function": ["fixture"]})],
    )
    monkeypatch.setattr(subject, "MAX_MATCHES", 0)

    assessment = subject.match_flirt(elf(function), catalog)

    assert assessment["status"] == "limited"
    assert assessment["matches"] == []
    assert any("match reporting limit" in value for value in assessment["limitations"])


def test_byte_work_budget_accepts_one_record_then_gaps_before_partial_candidate(
    tmp_path, monkeypatch
):
    first = code(b"budget-first")
    second = code(b"budget-second")
    catalog = load(
        tmp_path,
        [pattern(first, "first"), pattern(second, "second")],
        [group({"FirstName": ["first"], "SecondName": ["second"]})],
    )
    monkeypatch.setattr(subject, "MAX_MATCH_BYTES", len(first))

    exact = subject.match_flirt(elf(first), catalog)
    overflow = subject.match_flirt(elf(first + b"padding" + second), catalog)

    assert exact["status"] == "recognized"
    assert exact["gaps"] == []
    assert overflow["status"] == "limited"
    assert [match["signature_id"] for match in overflow["matches"]] == ["first"]
    assert any("target-byte work limit" in gap for gap in overflow["gaps"])
    assert "SecondName" not in json.dumps(overflow["matches"])


def test_missing_optional_backend_has_a_specific_error(tmp_path, monkeypatch):
    function = code(b"optional")
    bundle = write_bundle(
        tmp_path,
        [pattern(function, "fixture")],
        [group({"Function": ["fixture"]})],
    )

    def unavailable(_name):
        raise subject.importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(subject.importlib.metadata, "version", unavailable)
    with pytest.raises(subject.FlirtUnavailableError, match="python-flirt"):
        subject.load_flirt_bundle(bundle)


def test_incompatible_optional_backend_api_has_a_specific_error(monkeypatch):
    monkeypatch.setattr(subject.importlib.metadata, "version", lambda _name: "0.10.2")
    monkeypatch.setattr(subject.importlib, "import_module", lambda _name: object())

    with pytest.raises(subject.FlirtUnavailableError, match="required API"):
        subject._load_backend()  # noqa: SLF001 -- Optional import boundary regression.


@pytest.mark.parametrize(
    "backend",
    [
        SimpleNamespace(parse_pat=lambda _text: []),
        SimpleNamespace(compile=lambda _signatures: FakeMatcher([])),
    ],
)
def test_optional_backend_missing_one_required_callable_is_rejected(monkeypatch, backend):
    monkeypatch.setattr(subject.importlib.metadata, "version", lambda _name: "0.10.2")
    monkeypatch.setattr(subject.importlib, "import_module", lambda _name: backend)

    with pytest.raises(subject.FlirtUnavailableError, match="required API"):
        subject._load_backend()  # noqa: SLF001 -- Optional import boundary regression.


@pytest.mark.parametrize("version", ["0.9.99", "0.10.1", "0.11.0", "1.10.2"])
def test_optional_backend_unsupported_version_is_rejected(monkeypatch, version):
    monkeypatch.setattr(subject.importlib.metadata, "version", lambda _name: version)
    monkeypatch.setattr(
        subject.importlib,
        "import_module",
        lambda _name: SimpleNamespace(parse_pat=lambda _text: [], compile=lambda _items: None),
    )

    with pytest.raises(subject.FlirtUnavailableError, match=r">=0\.10\.2,<0\.11"):
        subject._load_backend()  # noqa: SLF001 -- Optional import boundary regression.


def test_backend_parser_panic_is_contained_as_invalid_references(tmp_path):
    function = code(b"parser-panic")
    bundle = write_bundle(
        tmp_path,
        [pattern(function, "fixture")],
        [group({"Function": ["fixture"]})],
    )

    with pytest.raises(ValueError, match=r"could not parse.*parser panic"):
        subject.load_flirt_bundle(bundle, backend=PanicBackend())


def test_backend_matcher_panic_becomes_an_explicit_gap(tmp_path):
    function = code(b"matcher-panic")
    catalog = load(
        tmp_path,
        [pattern(function, "fixture")],
        [group({"Function": ["fixture"]})],
    )
    catalog.matchers[("elf", 183, 64, "little", "sysv"), "fixture"] = PanicMatcher()

    assessment = subject.match_flirt(elf(function), catalog)

    assert assessment["status"] == "limited"
    assert assessment["matches"] == []
    assert any("could not match" in gap and "matcher panic" in gap for gap in assessment["gaps"])


def test_real_python_flirt_checks_generated_subset_when_installed(tmp_path):
    pytest.importorskip("flirt")
    function = code(b"real-backend", 80)
    bundle = write_bundle(
        tmp_path,
        [pattern(function, "real_fixture")],
        [group({"DecodeDistanceBlockSwitch": ["real_fixture"]})],
    )

    catalog = subject.load_flirt_bundle(bundle)

    assert subject.match_flirt(elf(function), catalog)["status"] == "recognized"
    modified = function[:-1] + bytes((function[-1] ^ 1,))
    assert subject.match_flirt(elf(modified), catalog)["status"] == "unknown"
