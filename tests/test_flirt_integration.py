import contextlib
import io
import json

import brotli_binary_inventory as binary_inventory
import brotli_binary_match as matcher
import brotli_binary_signatures as signatures
import brotli_flirt as flirt
import brotli_inventory as inventory
import pytest
from test_binary_match import elf, reference, write_catalog
from test_binary_metadata import elf_with_symbols
from test_flirt import FakeBackend, code, group, pattern, write_bundle


def load_fixture(tmp_path, function, *, name="ProcessCommands", state="fixed"):
    bundle = write_bundle(
        tmp_path,
        [pattern(function, "function")],
        [group({name: ["function"]}, state=state)],
    )
    return flirt.load_flirt_bundle(bundle, backend=FakeBackend())


def unmatched_reference(machine=matcher.EM_AARCH64):
    return matcher.CodeReference.from_json(reference(machine=machine, salt=b"unmatched"))


def run_main(*arguments):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        result = inventory.main(list(map(str, arguments)))
    return result, stdout.getvalue(), stderr.getvalue()


def test_individual_flirt_hit_is_unknown_even_with_fixed_source_provenance(tmp_path):
    function = code(b"identity-only")
    catalog = load_fixture(tmp_path, function, state="fixed")

    assessment = inventory.assess_binary(elf(function), [unmatched_reference()], catalog)

    assert assessment["kind"] == "decoder_function_signature"
    assert assessment["patch_status"] == "unknown"
    assert assessment["detection_status"] == "decoder_functions_recognized"
    assert assessment["gaps"] == []
    match = assessment["flirt"]["matches"][0]
    assert match["definitive_name"] == "ProcessCommands"
    assert match["compatible_profiles"][0]["source_state"] == "provenance_only"
    assert match["compatible_profiles"][0]["source_state_provenance"] == "fixed"


@pytest.mark.parametrize("state", ["fixed", "vulnerable"])
def test_code_match_precedence_and_flirt_evidence_coexist(tmp_path, state):
    entry = reference(state=state, salt=state.encode())
    code_reference = matcher.CodeReference.from_json(entry)
    function = code(b"supplemental-flirt")
    catalog = load_fixture(tmp_path, function)

    assessment = inventory.assess_binary(
        elf(code_reference.code + function), [code_reference], catalog
    )

    assert assessment["kind"] == "decoder_code_match"
    assert assessment["patch_status"] == f"{state}_code_match"
    assert assessment["detection_status"] == "decoder_code_identified"
    assert assessment["code_matches"]
    assert assessment["flirt"]["matches"]


def test_table_and_flirt_evidence_coexist_without_patch_promotion(tmp_path):
    function = code(b"table-and-function")
    catalog = load_fixture(tmp_path, function)
    payload = function + signatures.command_table("<")

    assessment = inventory.assess_binary(elf(payload), [unmatched_reference()], catalog)

    assert assessment["kind"] == "decoder_function_signature"
    assert assessment["patch_status"] == "unknown"
    assert assessment["recognition"]["status"] == "decoder_tables_detected"
    assert assessment["recognition"]["matches"]
    assert assessment["flirt"]["matches"]


def test_defined_symbol_and_flirt_evidence_coexist(tmp_path):
    function = code(b"symbol-and-function")
    catalog = load_fixture(tmp_path, function, name="BrotliDecoderDecompressStream")
    data = elf_with_symbols(
        function,
        matcher.EM_AARCH64,
        [{"name": "BrotliDecoderDecompressStream"}],
    )

    assessment = inventory.assess_binary(data, [unmatched_reference()], catalog)

    assert assessment["kind"] == "decoder_function_signature"
    assert assessment["patch_status"] == "unknown"
    assert assessment["decoder_metadata"]["defined_symbols"] == ["BrotliDecoderDecompressStream"]
    assert assessment["flirt"]["matches"]


def test_candidate_limit_reaches_inventory_gap_and_removes_definitive_name(tmp_path, monkeypatch):
    function = code(b"candidate-limit-integration")
    catalog = load_fixture(tmp_path, function)
    monkeypatch.setattr(flirt, "MAX_CANDIDATES", 1)

    assessment = inventory.assess_binary(
        elf(function + b"padding" + function), [unmatched_reference()], catalog
    )

    assert assessment["flirt"]["status"] == "limited"
    assert any("FLIRT candidate limit" in gap for gap in assessment["gaps"])
    assert assessment["flirt"]["matches"][0]["definitive_name"] is None
    assert assessment["flirt"]["matches"][0]["ambiguity_complete"] is False


def test_missing_target_profile_is_an_inventory_gap(tmp_path):
    function = code(b"wrong-target")
    catalog = load_fixture(tmp_path, function)

    assessment = inventory.assess_binary(
        elf(function, machine=matcher.EM_X86_64),
        [unmatched_reference(matcher.EM_X86_64)],
        catalog,
    )

    assert assessment["flirt"]["status"] == "unknown"
    assert any("No FLIRT references" in gap for gap in assessment["gaps"])


def test_non_elf_target_records_requested_flirt_format_gap(tmp_path):
    catalog = load_fixture(tmp_path, code(b"non-elf"))

    assessment = inventory.assess_binary(b"MZ" + bytes(128), [], catalog)

    assert assessment["flirt"]["status"] == "not_applicable"
    assert any("FLIRT executable mapping" in gap for gap in assessment["gaps"])


def test_binary_inventory_keeps_flirt_identity_separate_from_patch_status(tmp_path):
    function = code(b"binary-inventory")
    catalog = load_fixture(tmp_path, function)
    result = binary_inventory.BinaryInventory(
        {},
        [unmatched_reference()],
        max_file_bytes=None,
        max_total_bytes=None,
        max_files=10,
        archive_depth=0,
        flirt_catalog=catalog,
    )

    result.inspect(elf(function), "application", 0)

    assert result.findings[0]["kind"] == "decoder_function_signature"
    assert result.findings[0]["patch_status"] == "not_assessed"
    assert result.findings[0]["detection_status"] == "decoder_functions_recognized"
    assert result.findings[0]["flirt"]["matches"]


def test_requested_missing_backend_is_cli_gap(tmp_path, monkeypatch):
    target = tmp_path / "application"
    target.write_bytes(elf(code(b"cli")))
    references = write_catalog(tmp_path, [reference(salt=b"cli-reference")])

    def unavailable(_path):
        raise flirt.FlirtUnavailableError

    monkeypatch.setattr(inventory, "load_flirt_bundle", unavailable)
    monkeypatch.setattr(flirt, "load_flirt_bundle", unavailable)
    result, output, error = run_main(target, "--code-references", references, "--flirt", "--json")
    report = json.loads(output)
    assert result == 3
    assert error == ""
    assert report["flirt_requested"] is True
    assert any("FLIRT" in gap["reason"] for gap in report["coverage"]["gaps"])


def test_invalid_flirt_bundle_is_cli_error(tmp_path):
    target = tmp_path / "application"
    target.write_bytes(elf(code(b"cli-invalid")))
    references = write_catalog(tmp_path, [reference(salt=b"cli-invalid-reference")])
    invalid = tmp_path / "invalid-flirt.json"
    invalid.write_text("not json")
    result, output, error = run_main(
        target,
        "--code-references",
        references,
        "--flirt-references",
        invalid,
        "--json",
    )
    assert result == 2
    assert output == ""
    assert "Invalid binary references" in error


def test_optional_real_backend_flows_through_inventory_when_installed(tmp_path):
    pytest.importorskip("flirt")
    function = code(b"real-integration", 80)
    bundle = write_bundle(
        tmp_path,
        [pattern(function, "real")],
        [group({"DecodeDistanceBlockSwitch": ["real"]})],
    )
    catalog = flirt.load_flirt_bundle(bundle)

    assessment = inventory.assess_binary(elf(function), [unmatched_reference()], catalog)

    assert assessment["kind"] == "decoder_function_signature"
    assert assessment["patch_status"] == "unknown"
    assert assessment["flirt"]["matches"][0]["definitive_name"] == ("DecodeDistanceBlockSwitch")


def test_optional_real_backend_both_cli_paths_keep_fixed_provenance_unknown(tmp_path):
    pytest.importorskip("flirt")
    function = code(b"real-cli", 96)
    bundle = write_bundle(
        tmp_path,
        [pattern(function, "cli")],
        [group({"ProcessCommands": ["cli"]}, state="fixed")],
    )
    target = tmp_path / "application"
    target.write_bytes(elf(function))
    references = write_catalog(tmp_path, [reference(salt=b"not-the-function")])
    result, output, error = run_main(
        target,
        "--code-references",
        references,
        "--flirt-references",
        bundle,
        "--brotli-version",
        "1.2.1",
        "--json",
    )
    assert result == 3
    assert error == ""
    report = json.loads(output)
    assert report["flirt_requested"]
    assert report["user_summary"]["status"] == "decoder_recognized_patch_unresolved"
    item = report["findings"][0]
    assert item["patch_status"] == "unknown"
    assert item["evidence"]["flirt"]["matches"][0]["definitive_name"] == "ProcessCommands"
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert (
            binary_inventory.main(
                [
                    str(target),
                    "--code-references",
                    str(references),
                    "--flirt-references",
                    str(bundle),
                ]
            )
            == 1
        )  # Binary inventory's exit 1 means findings, not an affected verdict.
    report = json.loads(output.getvalue())
    assert report["flirt_requested"]
    assert report["findings"][0]["patch_status"] == "not_assessed"
    assert report["findings"][0]["flirt"] == item["evidence"]["flirt"]


def test_explicit_opt_out_does_not_load_backend(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory, "load_flirt_bundle", pytest.fail)
    target = tmp_path / "application"
    target.write_bytes(elf(code(b"no-optional-backend")))
    references = write_catalog(tmp_path, [reference(salt=b"unmatched")])
    result, output, error = run_main(
        target, "--code-references", references, "--no-flirt", "--json"
    )
    assert result == 3
    assert error == ""
    report = json.loads(output)
    assert report["flirt_requested"] is False
    assert report["findings"][0]["evidence"]["flirt"]["status"] == "not_requested"


@pytest.mark.parametrize("binary", [False, True])
def test_automatic_default_loads_once_and_recognizes_each_file(tmp_path, monkeypatch, binary):
    function = code(b"automatic-default")
    catalog = load_fixture(tmp_path, function)
    calls = []

    def load(path):
        calls.append(path)
        return catalog

    monkeypatch.setattr(flirt, "load_flirt_bundle", load)
    targets = []
    for name in ("first", "second"):
        target = tmp_path / name
        target.write_bytes(elf(function))
        targets.append(str(target))
    references = write_catalog(tmp_path, [reference(salt=b"unmatched")])
    output = io.StringIO()
    arguments = [*targets, "--code-references", str(references), "--no-xrefs"]
    if not binary:
        arguments.append("--json")
    with contextlib.redirect_stdout(output):
        (binary_inventory.main if binary else inventory.main)(arguments)
    report = json.loads(output.getvalue())
    assert len(calls) == 1
    assert report["flirt_requested"] is True
    assert report["flirt_configuration"]["status"] == "enabled"
    assert len(report["findings"]) == 2
    assert all(item["patch_status"] in {"unknown", "not_assessed"} for item in report["findings"])
    for item in report["findings"]:
        evidence = item if binary else item["evidence"]
        assert evidence["flirt"]["matches"]


def test_source_only_scan_does_not_load_automatic_backend(tmp_path, monkeypatch):
    monkeypatch.setattr(flirt, "load_flirt_bundle", pytest.fail)
    target = tmp_path / "notes.txt"
    target.write_text("ordinary source tree notes")
    references = write_catalog(tmp_path, [reference(salt=b"unmatched")])
    result, output, error = run_main(target, "--code-references", references, "--json")
    assert result == 3  # No findings is not an absence guarantee.
    assert error == ""
    report = json.loads(output)
    assert report["coverage"]["gap_count"] == 0
    assert report["flirt_configuration"]["status"] == "not_applicable"
