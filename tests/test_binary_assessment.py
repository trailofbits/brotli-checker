import contextlib
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills/brotli-checker/scripts"))
import brotli_inventory as scanner
from test_binary_inventory import run_scan
from test_binary_metadata import elf_with_symbols, encoded_version, x86_return


@pytest.mark.parametrize(
    ("version", "status", "exit_code"),
    [
        ((1, 0, 9), "potentially_vulnerable", 1),
        ((1, 1, 0), "potentially_vulnerable", 1),
        ((1, 2, 0), "potentially_vulnerable", 1),
        ((1, 0, 10), "unknown", 3),
        ((1, 1, 1), "unknown", 3),
        ((1, 2, 1), "unknown", 3),
        ((2, 0, 0), "unknown", 3),
    ],
)
def test_reported_versions_warn_but_never_clear_binaries(tmp_path, version, status, exit_code):
    target = tmp_path / "libbrotli.so"
    target.write_bytes(
        elf_with_symbols(
            x86_return(encoded_version(*version)), 62, [{"name": "BrotliDecoderVersion"}]
        )
    )
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert scanner.main([str(target), "--json"]) == exit_code
    report = json.loads(output.getvalue())
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["patch_status"] == status
    assert finding["evidence"]["decoder_metadata"]["versions"][0]["version"] == ".".join(
        map(str, version)
    )
    assert not finding["evidence"]["code_matches"]
    assert report["result"] != "reported_items_meet_fix_rules"
    text = scanner.render_text(report)
    if status == "potentially_vulnerable":
        assert "reports Brotli" in text
        assert "backport" in text
        assert "Possible vulnerable Brotli source" not in text
    result = run_scan(target)
    binary = json.loads(result.stdout)["findings"][0]
    assert binary["patch_status"] == ("not_assessed" if status == "unknown" else status)
    assert binary["decoder_metadata"] == finding["evidence"]["decoder_metadata"]


def test_imported_version_does_not_warn_as_embedded(tmp_path):
    target = tmp_path / "consumer.so"
    target.write_bytes(
        elf_with_symbols(
            x86_return(encoded_version(1, 2, 0)),
            62,
            [{"name": "BrotliDecoderVersion", "index": 0}],
        )
    )
    result = run_scan(target)
    finding = json.loads(result.stdout)["findings"][0]
    assert finding["patch_status"] == "not_assessed"
    assert finding["linkage"] == "decoder_import"
    assert not finding["decoder_metadata"]["versions"]


def test_old_version_cannot_hide_affected_code_and_fixed_code_cannot_clear_old_version(monkeypatch):
    from brotli_binary_match import CodeAssessment  # noqa: PLC0415

    data = elf_with_symbols(
        x86_return(encoded_version(1, 2, 0)), 62, [{"name": "BrotliDecoderVersion"}]
    )
    for states, expected in [
        (["vulnerable"], "vulnerable_code_match"),
        (["vulnerable", "fixed"], "mixed_code_matches"),
        (["fixed"], "potentially_vulnerable"),
    ]:
        assessment = CodeAssessment([{"state": state} for state in states], "test matches")
        monkeypatch.setattr(scanner, "match_code", lambda *_, result=assessment: result)
        actual = scanner.assess_binary(data, [])
        assert actual["patch_status"] == expected
        assert actual["code_matches"] == assessment.matches
