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


def state_only_module(state):
    types = wasm_section(1, b"\x01\x60\0\0")
    functions = wasm_section(3, b"\x01\0")
    body = b"\0\x41" + bytes((state,)) + b"\x1a\x0b"
    code = wasm_section(10, b"\x01" + uleb(len(body)) + body)
    return b"\0asm\x01\0\0\0" + types + functions + code


def graph_module(states):
    types = wasm_section(1, b"\x01\x60\0\0")
    count = 1 + 2 * len(states)
    functions = wasm_section(3, uleb(count) + b"\0" * count)
    bodies = [b"\0\x01\x0b"]
    for state in states:
        helper_index = len(bodies)
        bodies.append(b"\0\x41" + bytes((state,)) + b"\x1a\x0b")
        bodies.append(b"\0\x10" + uleb(helper_index) + b"\x0b")
    code = wasm_section(10, uleb(count) + b"".join(uleb(len(body)) + body for body in bodies))
    return b"\0asm\x01\0\0\0" + types + functions + code


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


def test_wasm_full_call_graph_union_never_combines_affected_and_fixed_components():
    affected, fixed = graph_module((0,)), graph_module((1,))
    mixed = profiles.match_wasm_profiles(graph_module((0, 1)), catalog(affected, fixed))

    assert mixed.patch_status == "unknown"
    assert len(mixed.matches) == 2
    assert {match["method"] for match in mixed.matches} == {"reviewed_wasm_function_population"}
    assert {match["patch_status"] for match in mixed.matches} == {"unknown"}


def test_partial_discriminating_wasm_fingerprint_is_reported_without_patch_verdict():
    affected, fixed = module(0), module(1)
    result = profiles.match_wasm_profiles(state_only_module(0), catalog(affected, fixed))

    assert result.matches == ()
    assert result.patch_status == "unknown"
    assert result.candidates == (
        {
            "id": "affected",
            "implementation_family": "google-brotli-c-emscripten",
            "source_version": "test",
            "patch_status": "unknown",
            "claimed_source_status": "vulnerable_code_match",
            "method": "partial_wasm_function_population",
            "family_anchor_hits": 0,
            "family_anchor_total": 1,
            "required_profile_hits": 1,
            "required_profile_total": 1,
        },
    )
    assert "remain unqualified" in result.gaps[0]


def test_wasm_noncustom_identity_ignores_only_well_formed_custom_sections():
    header = b"\0asm\x01\0\0\0"
    types = wasm_section(1, b"\x01\x60\0\0")
    functions = wasm_section(3, b"\x01\0")
    body = b"\0\x01\x0b"
    code = wasm_section(10, b"\x01" + uleb(len(body)) + body)
    first = wasm_section(0, wasm_name("first") + b"one")
    second = wasm_section(0, wasm_name("second") + b"two")
    variants = (
        header + first + types + functions + code,
        header + types + first + functions + second + code,
        header + types + functions + code + second,
    )

    layouts = [layout.inspect_layout(value) for value in variants]
    assert {item["wasm_noncustom_sha256"] for item in layouts} == {
        layouts[0]["wasm_noncustom_sha256"]
    }
    assert {item["functions"][0]["function_identity"]["profile_sha256"] for item in layouts} == {
        layouts[0]["functions"][0]["function_identity"]["profile_sha256"]
    }

    malformed = variants[0] + b"\0\x05x"
    malformed_layout = layout.inspect_layout(malformed)
    assert "wasm_noncustom_sha256" not in malformed_layout
    assert malformed_layout["gaps"]


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


@pytest.mark.parametrize("mutation", ["extra-field", "wasm-hash", "self-verified"])
def test_wasm_catalog_qualification_schema_cannot_self_assert_trust(tmp_path, mutation):
    entry = json.loads(json.dumps(profiles.load_wasm_profile_catalog()[0]))
    if mutation == "extra-field":
        entry["qualification"]["unreviewed"] = "claim"
    elif mutation == "wasm-hash":
        entry["qualification"]["wasm_sha256"] = "00" * 32
    else:
        entry["qualification_status"] = "source_rebuild_verified"
        entry["qualification"]["independent_rebuild_sha256"] = entry["artifact_sha256"]
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps({"schema_version": 1, "profiles": [entry]}))

    with pytest.raises(ValueError, match="qualification"):
        profiles.load_wasm_profile_catalog(path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_size", True),
        ("artifact_size", 0),
        ("function_count", -1),
        ("verified_identity_count", -1),
        ("verified_identity_count", 10**6),
    ],
)
def test_wasm_catalog_rejects_invalid_sizes_and_counts(tmp_path, field, value):
    entry = dict(profiles.load_wasm_profile_catalog()[0])
    entry[field] = value
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps({"schema_version": 1, "profiles": [entry]}))

    with pytest.raises(ValueError, match="catalog entry"):
        profiles.load_wasm_profile_catalog(path)


def test_wasm_catalog_profile_population_budget_is_enforced_before_hash_parsing(tmp_path):
    entry = dict(profiles.load_wasm_profile_catalog()[0])
    entry["required_profiles"] = [
        f"{index:064x}" for index in range(profiles.MAX_PROFILE_HASHES + 1)
    ]
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps({"schema_version": 1, "profiles": [entry]}))

    with pytest.raises(ValueError, match="profile population"):
        profiles.load_wasm_profile_catalog(path)
