import base64
import copy
import hashlib
import json

import brotli_jsf as subject
import pytest


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def fixture(*, embedded=True, timestamp="2026-11-02T12:00:00Z", seed=b"k"):
    rfc8785 = pytest.importorskip("rfc8785")
    ed = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    private = ed.Ed25519PrivateKey.from_private_bytes(seed * 32)
    public = private.public_key().public_bytes_raw()
    policy = {
        "schema_version": 1,
        "public_keys": [b64(public)],
        "evaluation_time": "2026-11-02T12:01:00Z",
        "trust_expires_at": "2026-11-03T00:00:00Z",
        "max_document_age_seconds": 3600,
        "max_future_skew_seconds": 60,
    }
    signature = {"algorithm": "Ed25519"}
    if embedded:
        signature["publicKey"] = {"kty": "OKP", "crv": "Ed25519", "x": b64url(public)}
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"timestamp": timestamp},
        "components": [
            {
                "type": "library",
                "name": "brotli",
                "hashes": [{"alg": "SHA-256", "content": "A" * 64}],
            }
        ],
        "signature": signature,
    }
    signature["value"] = b64url(private.sign(rfc8785.dumps(document)))
    return document, policy, private


def verify(document, policy):
    return subject.verify_jsf_document(
        json.dumps(document).encode(),
        json.dumps(policy).encode(),
    )


def test_verified_jsf_binds_authenticated_component_hash_but_not_patch_state():
    document, policy, _ = fixture()
    result = verify(document, policy)
    assert result["signature_status"] == "verified"
    assert result["subject_sha256"] == ["a" * 64]
    assert result["freshness"]["status"] == "verified_within_local_policy_window"
    assert result["patch_status"] == "unknown"
    assert result["predicate_status"] == "authenticated_bom_claim_not_independently_verified"


def test_jsf_signature_is_over_jcs_not_wire_serialization():
    document, policy, _ = fixture(embedded=False)
    compact = json.dumps(document, separators=(",", ":")).encode()
    pretty = json.dumps(document, indent=4, sort_keys=True).encode()
    first = subject.verify_jsf_document(compact, json.dumps(policy).encode())
    second = subject.verify_jsf_document(pretty, json.dumps(policy).encode())
    assert first["canonical_payload_sha256"] == second["canonical_payload_sha256"]
    assert first["document_sha256"] != second["document_sha256"]


def test_jsf_never_trusts_embedded_key_or_keyid():
    document, policy, _ = fixture()
    other_document, _, other_private = fixture(seed=b"x")
    other_public = other_private.public_key().public_bytes_raw()
    document["signature"]["publicKey"]["x"] = b64url(other_public)
    document["signature"]["keyId"] = "attacker-selected-hint"
    document["signature"]["value"] = other_document["signature"]["value"]
    with pytest.raises(ValueError, match="not explicitly trusted"):
        verify(document, policy)


def test_jsf_tampering_and_unsupported_unsigned_options_fail_closed():
    document, policy, _ = fixture()
    document["components"][0]["hashes"][0]["content"] = "b" * 64
    with pytest.raises(ValueError, match="trusted key"):
        verify(document, policy)
    document, policy, _ = fixture()
    document["signature"]["excludes"] = ["components"]
    with pytest.raises(ValueError, match="Unsupported JSF signature"):
        verify(document, policy)


@pytest.mark.parametrize(
    ("timestamp", "message"),
    [
        ("2026-11-02T10:00:00Z", "allowed age"),
        ("2026-11-02T12:02:01Z", "future skew"),
    ],
)
def test_jsf_freshness_is_signed_and_explicit(timestamp, message):
    document, policy, private = fixture(timestamp=timestamp)
    unsigned = copy.deepcopy(document)
    del unsigned["signature"]["value"]
    rfc8785 = pytest.importorskip("rfc8785")
    document["signature"]["value"] = b64url(private.sign(rfc8785.dumps(unsigned)))
    with pytest.raises(ValueError, match=message):
        verify(document, policy)


def test_jsf_stale_trust_and_ambiguous_json_are_rejected():
    document, policy, _ = fixture()
    policy["trust_expires_at"] = "2026-11-01T00:00:00Z"
    with pytest.raises(ValueError, match="stale"):
        verify(document, policy)
    _, valid_policy, _ = fixture()
    raw = b'{"signature":{},"signature":{}}'
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        subject.verify_jsf_document(raw, json.dumps(valid_policy).encode())

    valid_policy["schema_version"] = True
    with pytest.raises(ValueError, match="policy schema"):
        subject.load_jsf_policy(json.dumps(valid_policy).encode())


def test_jsf_policy_fingerprint_tracks_semantics_not_wire_order():
    _, policy, _ = fixture()
    first = subject.load_jsf_policy(json.dumps(policy).encode())
    second = subject.load_jsf_policy(json.dumps(policy, sort_keys=True, indent=2).encode())
    assert first.semantic_sha256 == second.semantic_sha256
    assert len(first.semantic_sha256) == hashlib.sha256().digest_size * 2
