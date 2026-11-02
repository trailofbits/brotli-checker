import hashlib
import json

import brotli_binary_layout as layout
import brotli_wasm_profiles as profiles
import pytest
from test_binary_layout import uleb, wasm_name, wasm_section


def module_with_states(states):
    types = wasm_section(1, b"\x01\x60\0\0")
    functions = wasm_section(3, uleb(1 + len(states)) + b"\0" * (1 + len(states)))
    anchor = b"\0\x01\x0b"
    bodies = [anchor, *(b"\0\x41" + bytes((state,)) + b"\x1a\x0b" for state in states)]
    code = wasm_section(
        10,
        uleb(len(bodies)) + b"".join(uleb(len(body)) + body for body in bodies),
    )
    return b"\0asm\x01\0\0\0" + types + functions + code


def module(state):
    return module_with_states((state,))


def catalog(affected, fixed):
    affected_layout = layout.inspect_layout(affected)
    fixed_layout = layout.inspect_layout(fixed)
    affected_values = [
        item["function_identity"]["profile_sha256"] for item in affected_layout["functions"]
    ]
    fixed_values = [
        item["function_identity"]["profile_sha256"] for item in fixed_layout["functions"]
    ]
    anchor = sorted(set(affected_values) & set(fixed_values))

    def entry(identifier, data, state, required):
        return {
            "id": identifier,
            "implementation_family": "google-brotli-c-emscripten",
            "source_version": "test",
            "patch_status": f"{state}_code_match",
            "artifact_sha256": hashlib.sha256(data).hexdigest(),
            "noncustom_sha256": layout.inspect_layout(data)["wasm_noncustom_sha256"],
            "artifact_size": len(data),
            "function_count": 2,
            "verified_identity_count": 2,
            "family_anchors": anchor,
            "required_profiles": sorted(required),
            "qualification": {"fixture": True},
            "qualification_status": "source_rebuild_verified",
        }

    return (
        entry("affected", affected, "vulnerable", set(affected_values) - set(fixed_values)),
        entry("fixed", fixed, "fixed", set(fixed_values) - set(affected_values)),
    )


def test_reviewed_wasm_profiles_require_full_noncustom_module_for_patch_status():
    affected, fixed = module(0), module(1)
    references = catalog(affected, fixed)
    repackaged = affected + wasm_section(0, wasm_name("note") + b"different package metadata")

    result = profiles.match_wasm_profiles(repackaged, references)
    opposite = profiles.match_wasm_profiles(fixed, (references[0],))

    assert result.patch_status == "vulnerable_code_match"
    assert result.matches[0]["method"] == "validated_noncustom_wasm_sha256"
    assert result.matches[0]["implementation_family"] == "google-brotli-c-emscripten"
    assert opposite.patch_status == "unknown"
    assert opposite.matches == ()

    extended = profiles.match_wasm_profiles(module_with_states((0, 2)), references)
    assert extended.patch_status == "unknown"
    assert extended.matches[0]["method"] == "reviewed_wasm_function_population"
    assert extended.matches[0]["patch_status"] == "unknown"


def test_wasm_profile_population_union_never_becomes_a_fixed_component():
    affected, fixed = module(0), module(1)
    result = profiles.match_wasm_profiles(module_with_states((0, 1)), catalog(affected, fixed))

    assert result.patch_status == "unknown"
    assert {match["qualified_source_status"] for match in result.matches} == {
        "vulnerable_code_match",
        "fixed_code_match",
    }
    assert {match["patch_status"] for match in result.matches} == {"unknown"}


def test_packaged_wasm_catalog_is_family_specific_and_paired():
    catalog_entries = profiles.load_wasm_profile_catalog()
    assert {entry["patch_status"] for entry in catalog_entries} == {
        "vulnerable_code_match",
        "fixed_code_match",
    }
    assert {entry["implementation_family"] for entry in catalog_entries} == {
        "google-brotli-c-emscripten"
    }
    assert {entry["qualification"]["package"] for entry in catalog_entries} == {"@wasm-zoo/brotli"}
    assert {entry["qualification_status"] for entry in catalog_entries} == {
        "pending_source_rebuild"
    }


def test_wasm_catalog_rejects_nonhashable_profile_values_as_value_error(tmp_path):
    entry = dict(profiles.load_wasm_profile_catalog()[0])
    entry["family_anchors"] = [{}]
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps({"schema_version": 1, "profiles": [entry]}))

    with pytest.raises(ValueError, match="profile population"):
        profiles.load_wasm_profile_catalog(path)
