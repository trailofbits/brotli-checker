import hashlib

import pytest
import verify_fingerprints as verifier

GO_OLD = b"""
func decodeBlockTypeAndLength(safe int, s *Reader, tree_type int) bool {
    if max_block_type <= 1 { return false }
    return true
}
func decodeLiteralBlockSwitchInternal(safe int, s *Reader) bool { return true }
func decodeCommandBlockSwitchInternal(safe int, s *Reader) bool { return true }
func decodeDistanceBlockSwitchInternal(safe int, s *Reader) bool { return true }
func decodeLiteralBlockSwitch(s *Reader) {}
func process() {
    if !safeDecodeLiteralBlockSwitch(s) { result = decoderNeedsMoreInput
    } else { decodeLiteralBlockSwitch(s) }
    if !safeDecodeCommandBlockSwitch(s) { result = decoderNeedsMoreInput
    } else { decodeCommandBlockSwitch(s) }
    if !safeDecodeDistanceBlockSwitch(s) { result = decoderNeedsMoreInput
    } else { decodeDistanceBlockSwitch(s) }
}
"""

GO_FIXED = b"""
func decodeBlockTypeAndLength(safe int, s *Reader, tree_type int) int {
    if max_block_type <= 1 { return decoderErrorFormatBlockSwitch }
    return decoderSuccess
}
func decodeLiteralBlockSwitchInternal(safe int, s *Reader) int { return decoderSuccess }
func decodeCommandBlockSwitchInternal(safe int, s *Reader) int { return decoderSuccess }
func decodeDistanceBlockSwitchInternal(safe int, s *Reader) int { return decoderSuccess }
func decodeLiteralBlockSwitch(s *Reader) {}
func process() {
    status = safeDecodeLiteralBlockSwitch(s); status = decodeLiteralBlockSwitch(s)
    if status != decoderSuccess {}; if status != decoderSuccess {}
    status = safeDecodeCommandBlockSwitch(s); status = decodeCommandBlockSwitch(s)
    if status != decoderSuccess {}
    status = safeDecodeDistanceBlockSwitch(s); status = decodeDistanceBlockSwitch(s)
    if status != decoderSuccess {}
}
"""

RUST_OLD = b"""
fn DecodeBlockTypeAndLength<T>(safe: bool, input : &[u8]) -> bool {
    if max_block_type <= 1 { return false }
    true
}
fn DecodeLiteralBlockSwitchInternal<T>(safe: bool, input: &[u8]) -> bool { true }
fn DecodeCommandBlockSwitchInternal<T>(safe: bool, input: &[u8]) -> bool { true }
fn DecodeDistanceBlockSwitchInternal<T>(safe: bool, input: &[u8]) -> bool { true }
fn BrotliDecompressStream() {
    if !DecodeCommandBlockSwitchInternal(safe, s, input) {}
    if (!DecodeLiteralBlockSwitchInternal(safe, s, input)) && safe {}
    if (!DecodeDistanceBlockSwitchInternal(safe, s, input)) && safe {}
}
"""

RUST_FIXED = b"""
fn DecodeBlockTypeAndLength<T>(
    safe: bool,
    input : &[u8]) -> BrotliDecoderErrorCode {
    if max_block_type <= 1 {
        return BrotliDecoderErrorCode::BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH
    }
    BrotliDecoderErrorCode::BROTLI_DECODER_SUCCESS
}
fn DecodeLiteralBlockSwitchInternal<T>(
    safe: bool, input: &[u8]) -> BrotliDecoderErrorCode {
    BrotliDecoderErrorCode::BROTLI_DECODER_SUCCESS
}
fn DecodeCommandBlockSwitchInternal<T>(
    safe: bool, input: &[u8]) -> BrotliDecoderErrorCode {
    BrotliDecoderErrorCode::BROTLI_DECODER_SUCCESS
}
fn DecodeDistanceBlockSwitchInternal<T>(
    safe: bool, input: &[u8]) -> BrotliDecoderErrorCode {
    BrotliDecoderErrorCode::BROTLI_DECODER_SUCCESS
}
fn BrotliDecompressStream() {
    match DecodeCommandBlockSwitchInternal(safe, s, input) {}
    match DecodeLiteralBlockSwitchInternal(safe, s, input) {}
    match DecodeDistanceBlockSwitchInternal(safe, s, input) {}
}
"""


def entry(implementation, state, data):
    blob = b"blob " + str(len(data)).encode() + b"\0" + data
    result = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "git_blob": hashlib.sha1(blob, usedforsecurity=False).hexdigest(),
        "size": len(data),
        "state": state,
        "sources": [
            {
                "label": "fixture",
                "url": "https://raw.githubusercontent.com/example/project/commit/source",
            }
        ],
    }
    if implementation in verifier.PORT_METADATA:
        result.update(
            implementation=implementation,
            component=verifier.PORT_METADATA[implementation]["component"],
            issue_relation=verifier.ISSUE_RELATION,
            upstream_fix=verifier.PORT_METADATA[implementation]["upstream_fix"],
        )
    return result


def test_verifier_uses_normal_inventory_import():
    assert verifier.checker.__name__ == "brotli_inventory"


def test_legacy_entries_need_no_new_metadata():
    assert verifier.implementation({}) == verifier.LEGACY_C
    assert verifier.verify_metadata({}) is None
    assert verifier.expected_source_status({"state": "vulnerable"}) == "vulnerable_source"
    assert verifier.expected_source_status({"state": "fixed"}) == "fixed_source"


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("implementation", "unknown_port", "unsupported registry implementation"),
        ("component", "wrong", "implementation component mismatch"),
        ("issue_relation", "same_bug", "implementation issue relation mismatch"),
        ("upstream_fix", "https://example.invalid/fix", "implementation upstream fix mismatch"),
    ],
)
def test_port_metadata_is_exact(field, value, error):
    candidate = entry(verifier.GO_PORT, "fixed", GO_FIXED)
    candidate[field] = value
    assert verifier.verify_metadata(candidate) == error


@pytest.mark.parametrize(
    ("implementation", "state", "data"),
    [
        (verifier.GO_PORT, "vulnerable", GO_OLD),
        (verifier.GO_PORT, "fixed", GO_FIXED),
        (verifier.RUST_PORT, "vulnerable", RUST_OLD),
        (verifier.RUST_PORT, "fixed", RUST_FIXED),
    ],
)
def test_independent_port_semantics(implementation, state, data):
    candidate = entry(implementation, state, data)
    assert verifier.verify_metadata(candidate) is None
    assert verifier.verify_pattern(candidate, data) is None


@pytest.mark.parametrize(
    ("implementation", "state", "data"),
    [
        (verifier.GO_PORT, "fixed", GO_OLD),
        (verifier.GO_PORT, "vulnerable", GO_FIXED),
        (verifier.RUST_PORT, "fixed", RUST_OLD),
        (verifier.RUST_PORT, "vulnerable", RUST_FIXED),
    ],
)
def test_opposite_port_semantics_are_rejected(implementation, state, data):
    candidate = entry(implementation, state, data)
    assert verifier.verify_pattern(candidate, data) is not None


@pytest.mark.parametrize(
    ("implementation", "state", "data"),
    [
        (verifier.GO_PORT, "vulnerable", GO_OLD),
        (verifier.GO_PORT, "fixed", GO_FIXED),
        (verifier.RUST_PORT, "vulnerable", RUST_OLD),
        (verifier.RUST_PORT, "fixed", RUST_FIXED),
    ],
)
def test_exact_port_source_classifies_but_modified_source_stays_unknown(
    implementation, state, data
):
    candidate = entry(implementation, state, data)
    registry = {"fingerprints": [candidate]}
    expected = "affected_port_source" if state == "vulnerable" else "fixed_port_source"
    assert verifier.expected_source_status(candidate) == expected

    result = verifier.checker.Inventory(registry, 1 << 24, 1 << 28, 100, 2)
    result.inspect(data, "fixture" + verifier.source_suffix(candidate), 0)
    statuses = {finding["patch_status"] for finding in result.findings}
    assert expected in statuses
    assert statuses.isdisjoint({"vulnerable_source", "fixed_source"})
    assert verifier.verify_classifications(candidate, data, registry) is None


def test_identity_verification_remains_independent_of_semantic_patterns():
    candidate = entry(verifier.GO_PORT, "vulnerable", GO_OLD)
    assert verifier.verify_identity(candidate, GO_OLD) is None
    assert verifier.verify_identity(candidate, GO_OLD + b"\n") == "source size mismatch"
