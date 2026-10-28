import copy
import json
import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_native_layouts.py"))


def test_native_fixture_manifest_is_bounded_and_conservative():
    fixtures = VERIFIER["load_manifest"](ROOT / "tests/native_fixtures.json")
    assert len(fixtures) == 4
    assert {item["release"] for item in fixtures} == {"1.2.0", "1.2.1"}
    assert {item["reviewed_source_state"] for item in fixtures} == {"fixed", "vulnerable"}
    assert {item["target_patch_status"] for item in fixtures} == {"unknown"}


def test_manifest_rejects_binary_patch_state_claim(tmp_path):
    source = json.loads((ROOT / "tests/native_fixtures.json").read_text())
    modified = copy.deepcopy(source)
    modified["fixtures"][0]["target_patch_status"] = "vulnerable"
    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(modified))
    with pytest.raises(ValueError, match="unsafe binary patch-state"):
        VERIFIER["load_manifest"](path)
