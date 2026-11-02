import base64
import copy
import hashlib
import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from typing import Any, cast

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


def test_jsf_policy_is_immutable_and_accepts_exact_boundaries():
    evaluated = datetime(2026, 11, 2, 12, tzinfo=UTC)
    keys = tuple(bytes([index]) * 32 for index in range(subject.MAX_KEYS))
    value = subject.JsfPolicy(
        keys,
        evaluated,
        evaluated,
        subject.MAX_FRESHNESS_SECONDS,
        24 * 60 * 60,
    )
    with pytest.raises(FrozenInstanceError):
        cast("Any", value).keys = ()
    document = {
        "metadata": {
            "timestamp": (evaluated - timedelta(seconds=subject.MAX_FRESHNESS_SECONDS)).isoformat()
        }
    }
    first = subject._document_time(document, value)  # noqa: SLF001
    assert first["status"] == "verified_within_local_policy_window"
    document["metadata"]["timestamp"] = (evaluated + timedelta(seconds=24 * 60 * 60)).isoformat()
    second = subject._document_time(document, value)  # noqa: SLF001
    assert second["status"] == "verified_within_local_policy_window"

    with pytest.raises(ValueError, match="key population"):
        subject.JsfPolicy((), evaluated, evaluated, 0, 0)
    with pytest.raises(ValueError, match="key population"):
        subject.JsfPolicy((*keys, b"x" * 32), evaluated, evaluated, 0, 0)
    with pytest.raises(ValueError, match="unique Ed25519"):
        subject.JsfPolicy((b"x" * 31,), evaluated, evaluated, 0, 0)
    with pytest.raises(ValueError, match="maximum document age"):
        subject.JsfPolicy(
            (b"x" * 32,),
            evaluated,
            evaluated,
            subject.MAX_FRESHNESS_SECONDS + 1,
            0,
        )
    with pytest.raises(ValueError, match="future skew"):
        subject.JsfPolicy((b"x" * 32,), evaluated, evaluated, 0, 24 * 60 * 60 + 1)


@pytest.mark.parametrize("field", ["evaluation_time", "trust_expires_at"])
def test_jsf_programmatic_policy_rejects_each_naive_time(field):
    values = {
        "keys": (b"x" * 32,),
        "evaluation_time": datetime(2026, 11, 2, tzinfo=UTC),
        "trust_expires_at": datetime(2026, 11, 3, tzinfo=UTC),
        "max_document_age_seconds": 0,
        "max_future_skew_seconds": 0,
    }
    values[field] = values[field].replace(tzinfo=None)
    with pytest.raises(ValueError, match="timezone-aware"):
        subject.JsfPolicy(**values)


def test_jsf_component_hashes_cover_metadata_and_nested_components(monkeypatch):
    document = {
        "metadata": {
            "component": {
                "hashes": [{"alg": "SHA-256", "content": "A" * 64}],
                "components": [{"hashes": [{"alg": "SHA-256", "content": "b" * 64}]}],
            }
        }
    }
    monkeypatch.setattr(subject, "MAX_COMPONENTS", 2)
    assert subject._component_hashes(document) == ["a" * 64, "b" * 64]  # noqa: SLF001
    document["metadata"]["component"]["components"][0]["components"] = [{}]
    with pytest.raises(ValueError, match="population exceeds"):
        subject._component_hashes(document)  # noqa: SLF001


@pytest.mark.parametrize(
    "component",
    [
        "not-an-object",
        {"components": {}},
        {"hashes": {}},
        {"hashes": [[]]},
        {"hashes": [{"alg": "SHA-256", "content": "g" * 64}]},
    ],
)
def test_jsf_component_shapes_fail_independently(component):
    with pytest.raises(ValueError, match="CycloneDX"):
        subject._component_hashes({"components": [component]})  # noqa: SLF001


@pytest.mark.parametrize(
    "mutation",
    [
        lambda signature: signature.update(algorithm="ES256"),
        lambda signature: signature.update(keyId=7),
        lambda signature: signature.update(value=b64url(b"x" * 63)),
        lambda signature: signature["publicKey"].update(extra=True),
        lambda signature: signature["publicKey"].update(kty="EC"),
    ],
)
def test_jsf_signature_fields_fail_independently(mutation):
    document, policy, _ = fixture()
    mutation(document["signature"])
    with pytest.raises(ValueError, match=r"JSF|Ed25519"):
        verify(document, policy)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda document: document.update(bomFormat="SPDX"),
        lambda document: document.update(specVersion="2.0"),
        lambda document: document.update(specVersion=1.6),
        lambda document: document.pop("specVersion"),
    ],
)
def test_jsf_requires_an_explicit_cyclonedx_1x_document(mutation):
    document, policy, _ = fixture()
    mutation(document)
    with pytest.raises(ValueError, match=r"CycloneDX 1\.x"):
        verify(document, policy)


@pytest.mark.parametrize(
    "document",
    [
        {"components": {}},
        {"metadata": {"component": []}},
    ],
)
def test_jsf_top_level_component_populations_are_not_silently_ignored(document):
    with pytest.raises(ValueError, match="CycloneDX"):
        subject._component_hashes(document)  # noqa: SLF001


def test_jsf_key_id_is_signed_but_never_a_trust_selector():
    jcs = pytest.importorskip("rfc8785")
    document, policy, private = fixture()
    document["signature"]["keyId"] = "not-a-policy-key-identifier"
    del document["signature"]["value"]
    document["signature"]["value"] = b64url(private.sign(jcs.dumps(document)))
    assert verify(document, policy)["signature_status"] == "verified"
    document["signature"]["keyId"] = "changed-without-resigning"
    with pytest.raises(ValueError, match="signature was not made"):
        verify(document, policy)
