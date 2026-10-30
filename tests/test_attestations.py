import base64
import contextlib
import hashlib
import io
import json
from typing import Any, cast

import brotli_attestations as subject
import brotli_inventory
import pytest
from test_binary_match import reference, write_catalog


def signed_fixture(*, keys=1, threshold=1):
    ed = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    private = [
        ed.Ed25519PrivateKey.from_private_bytes(bytes([index + 1]) * 32) for index in range(keys)
    ]
    policy = {
        "schema_version": 1,
        "public_keys": [
            base64.b64encode(key.public_key().public_bytes_raw()).decode() for key in private
        ],
        "threshold": threshold,
        "predicate_types": ["https://example.test/build/v1"],
    }
    statement = {
        "_type": subject.STATEMENT_TYPE,
        "subject": [{"name": "artifact", "digest": {"sha256": "a" * 64}}],
        "predicateType": policy["predicate_types"][0],
        "predicate": {"fixed": True},
    }
    payload = json.dumps(statement).encode()
    envelope = {
        "payloadType": subject.PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "keyid": "untrusted-hint",
                "sig": base64.b64encode(
                    key.sign(subject.pae(subject.PAYLOAD_TYPE, payload))
                ).decode(),
            }
            for key in private
        ],
    }
    return subject.load_trust_policy(json.dumps(policy).encode()), envelope


def test_signature_authenticates_subject_not_patch_claim():
    policy, envelope = signed_fixture()
    result = subject.verify_attestation(json.dumps(envelope).encode(), policy)
    assert result["signature_status"] == "verified"
    assert result["subject_sha256"] == ["a" * 64]
    assert result["patch_status"] == "unknown"
    assert result["predicate_status"] == "authenticated_claim_not_independently_verified"


def test_distinct_keys_required_not_duplicate_signatures():
    policy, envelope = signed_fixture(keys=2, threshold=2)
    assert (
        len(subject.verify_attestation(json.dumps(envelope).encode(), policy)["verified_keys"]) == 2
    )
    envelope["signatures"][1] = envelope["signatures"][0]
    with pytest.raises(ValueError, match="threshold"):
        subject.verify_attestation(json.dumps(envelope).encode(), policy)


def test_payload_and_type_tampering_rejected():
    policy, envelope = signed_fixture()
    envelope["payload"] = base64.b64encode(b"{}").decode()
    with pytest.raises(ValueError, match="threshold"):
        subject.verify_attestation(json.dumps(envelope).encode(), policy)
    envelope["payloadType"] = "application/json"
    with pytest.raises(ValueError, match="payload type"):
        subject.verify_attestation(json.dumps(envelope).encode(), policy)


def test_duplicate_json_keys_rejected():
    with pytest.raises(ValueError, match="Duplicate"):
        subject.load_trust_policy(b'{"schema_version":1,"schema_version":1}')


def test_pae_uses_byte_lengths_and_binds_type():
    assert subject.pae("type", b"body") == b"DSSEv1 4 type 4 body"
    assert subject.pae("\u00e9", b"x") == b"DSSEv1 2 \xc3\xa9 1 x"


@pytest.mark.parametrize("field", ["threshold", "public_keys", "predicate_types"])
def test_empty_or_invalid_trust_policy_never_verifies(field):
    value = {
        "schema_version": 1,
        "public_keys": [base64.b64encode(b"k" * 32).decode()],
        "threshold": 1,
        "predicate_types": ["predicate"],
    }
    value[field] = 0 if field == "threshold" else []
    with pytest.raises(ValueError, match="Invalid"):
        subject.load_trust_policy(json.dumps(value).encode())


def test_duplicate_trusted_keys_cannot_inflate_threshold():
    key = base64.b64encode(b"k" * 32).decode()
    with pytest.raises(ValueError, match="unique"):
        subject.load_trust_policy(
            json.dumps(
                {
                    "schema_version": 1,
                    "public_keys": [key, key],
                    "threshold": 2,
                    "predicate_types": ["predicate"],
                }
            ).encode()
        )


def test_untrusted_hint_does_not_change_authenticated_signer():
    policy, envelope = signed_fixture()
    before = subject.verify_attestation(json.dumps(envelope).encode(), policy)
    envelope["signatures"][0]["keyid"] = "attacker-selected-name"
    after = subject.verify_attestation(json.dumps(envelope).encode(), policy)
    assert after["verified_keys"] == before["verified_keys"]


def test_inspection_binds_only_exact_scanned_subject(tmp_path):
    policy, envelope = signed_fixture()
    trust = tmp_path / "trust.json"
    trust.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "public_keys": [base64.b64encode(k).decode() for k in policy.keys],
                "threshold": 1,
                "predicate_types": list(policy.predicate_types),
            }
        )
    )
    bundle = tmp_path / "attestation.json"
    bundle.write_text(json.dumps(envelope))
    inputs = subject.capture_attestation_inputs([bundle], trust)
    records, gaps = subject.inspect_captured_attestations(
        inputs,
        [{"id": "match", "sha256": "a" * 64}, {"id": "different", "sha256": "b" * 64}],
    )
    assert gaps == []
    assert records[0]["bound_artifacts"] == ["match"]
    assert records[0]["patch_status"] == "unknown"
    assert records[0]["attestation_input_sha256"] == inputs.bundles[0].sha256
    assert inputs.policy is not None
    assert records[0]["trust_policy_input_sha256"] == inputs.policy.sha256
    with pytest.raises(ValueError, match="explicit local trust"):
        subject.inspect_captured_attestations(subject.AttestationInputs(None, inputs.bundles), [])


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_nonfinite_trust_policy_json_is_rejected(constant):
    with pytest.raises(ValueError, match="Nonfinite"):
        subject.load_trust_policy(('{"ignored":' + constant + "}").encode())


def test_nested_json_cannot_exceed_structure_budget():
    raw = b'{"nested":' + b"[" * 65 + b"0" + b"]" * 65 + b"}"
    with pytest.raises(ValueError, match="structure budget"):
        subject.load_trust_policy(raw)


def test_programmatic_zero_threshold_cannot_bypass_authentication():
    policy, envelope = signed_fixture()
    envelope["signatures"][0]["sig"] = base64.b64encode(b"x" * 64).decode()
    with pytest.raises(ValueError, match="threshold"):
        subject.TrustPolicy(policy.keys, 0, policy.predicate_types)


def test_semantic_policy_fingerprint_is_internal_and_order_independent():
    first, _ = signed_fixture(keys=2)
    second = subject.TrustPolicy(
        tuple(reversed(first.keys)),
        first.threshold,
        tuple(reversed(first.predicate_types)),
    )
    assert first.semantic_sha256 == second.semantic_sha256
    with pytest.raises(TypeError):
        cast("Any", subject.TrustPolicy)(
            first.keys,
            first.threshold,
            first.predicate_types,
            "f" * 64,
        )


def test_attestation_capture_rejects_symlinks_and_binds_exact_bytes(tmp_path):
    policy, envelope = signed_fixture()
    raw = json.dumps(envelope).encode()
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(raw)
    trust = tmp_path / "trust.json"
    trust.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "public_keys": [base64.b64encode(key).decode() for key in policy.keys],
                "threshold": policy.threshold,
                "predicate_types": list(policy.predicate_types),
            }
        )
    )
    captured = subject.capture_attestation_inputs([bundle], trust)
    assert captured.bundles[0].raw == raw
    assert captured.bundles[0].sha256 == hashlib.sha256(raw).hexdigest()
    bundle.write_bytes(b"changed after capture")
    records, gaps = subject.inspect_captured_attestations(captured, [])
    assert gaps == []
    assert records[0]["attestation_sha256"] == hashlib.sha256(raw).hexdigest()
    link = tmp_path / "bundle-link"
    link.symlink_to(bundle)
    with pytest.raises(ValueError, match="non-symlink"):
        subject.capture_attestation_inputs([link], trust)


def test_programmatic_captured_documents_cannot_supply_fake_digests():
    captured = subject.CapturedDocument("bundle", b"raw")
    assert captured.sha256 == hashlib.sha256(b"raw").hexdigest()
    with pytest.raises(TypeError):
        cast("Any", subject.CapturedDocument)("bundle", b"raw", "f" * 64)


def test_cli_attestation_preserves_unknown_patch_and_binds_exact_target(tmp_path):
    ed = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    private = ed.Ed25519PrivateKey.from_private_bytes(b"k" * 32)
    target = tmp_path / "application"
    target.write_bytes(b"unrecognized application bytes")
    statement = {
        "_type": subject.STATEMENT_TYPE,
        "predicateType": "https://example.test/build",
        "predicate": {"fixed": True},
        "subject": [
            {
                "name": "ignored",
                "digest": {"sha256": hashlib.sha256(target.read_bytes()).hexdigest()},
            }
        ],
    }
    payload = json.dumps(statement).encode()
    bundle = tmp_path / "bundle.json"
    bundle.write_text(
        json.dumps(
            {
                "payloadType": subject.PAYLOAD_TYPE,
                "payload": base64.b64encode(payload).decode(),
                "signatures": [
                    {
                        "sig": base64.b64encode(
                            private.sign(subject.pae(subject.PAYLOAD_TYPE, payload))
                        ).decode()
                    }
                ],
            }
        )
    )
    policy = tmp_path / "trust.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "threshold": 1,
                "predicate_types": [statement["predicateType"]],
                "public_keys": [base64.b64encode(private.public_key().public_bytes_raw()).decode()],
            }
        )
    )
    catalog = write_catalog(tmp_path, [reference(salt=b"unused")])
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        status = brotli_inventory.main(
            [
                str(target),
                "--attestation",
                str(bundle),
                "--attestation-policy",
                str(policy),
                "--code-references",
                str(catalog),
                "--no-flirt",
                "--json",
            ]
        )
    report = json.loads(output.getvalue())
    assert status == 3
    assert report["attestations"][0]["bound_artifacts"] == [report["artifacts"][0]["id"]]
    assert report["attestations"][0]["patch_status"] == "unknown"
    assert {item["category"] for item in report["evidence_envelope"]["feeds"]} >= {
        "attestation",
        "trust-policy",
    }
