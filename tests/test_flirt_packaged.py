"""Explicit packaged-corpus check, kept out of every mutant subprocess."""

import os

import brotli_flirt as flirt
import pytest


@pytest.mark.skipif(
    os.environ.get("BROTLI_FLIRT_REFERENCE_TESTS") != "1",
    reason="Optional complete packaged FLIRT corpus validation",
)
def test_packaged_corpus_compiles_and_retains_complete_profile_index():
    pytest.importorskip("flirt")
    catalog = flirt.load_flirt_bundle(flirt.DEFAULT_FLIRT_BUNDLE)
    assert catalog.records
    assert catalog.groups
    expected = {
        (group.identity, identifier)
        for group in catalog.groups
        for identifier in group.signature_ids
    }
    assert catalog.matchers.keys() == expected
    assert catalog.profiles.keys() == expected
    assert {identifier for _, identifier in expected} == catalog.records.keys()
    for group in catalog.groups:
        assert group.metadata["headers_sha256"]
        assert group.metadata["build_note"]
