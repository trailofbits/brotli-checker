"""Real upstream dependencies are downloaded separately and never committed."""

import contextlib
import io
import json
import os
from pathlib import Path

import brotli_inventory as scanner
import pytest

FIXTURES = Path(__file__).parent / "known_answers"
SOURCES = Path(os.environ.get("BROTLI_TEST_SOURCES", FIXTURES / ".deps"))
ANSWERS = json.loads((FIXTURES / "answers.json").read_text())


@pytest.mark.parametrize("answer", ANSWERS, ids=lambda row: row["version"])
def test_upstream_source_known_answers(answer, tmp_path):
    source = SOURCES / f"brotli-{answer['version']}" / "c/dec/decode.c"
    if not source.is_file():
        pytest.skip("Populate tests/known_answers/.deps with CMake or set BROTLI_TEST_SOURCES")
    for modified in (False, True):
        target = tmp_path / "decoder.c"
        target.write_bytes(source.read_bytes() + (b"\n/* local change */\n" if modified else b""))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = scanner.main([str(target), "--json"])
        report = json.loads(output.getvalue())
        expected = answer["patch_status"]
        if modified:
            expected = "potentially_vulnerable" if expected == "vulnerable_source" else "unknown"
        assert result == (
            1
            if expected in {"vulnerable_source", "potentially_vulnerable"}
            else 0
            if expected == "fixed_source"
            else 3
        )
        assert [row["patch_status"] for row in report["findings"]] == [expected]
        assert report["findings"][0]["reachability"] == "unknown"
        assert report["coverage"]["gap_count"] == 0
