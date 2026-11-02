import argparse
import base64
import json
from pathlib import Path

import brotli_trust_inputs as subject
import pytest
from brotli_attestations import PAYLOAD_TYPE, STATEMENT_TYPE, CapturedDocument

DIGEST = "a" * 64


def message_bundle(digest=DIGEST):
    return json.dumps(
        {
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": base64.b64encode(bytes.fromhex(digest)).decode(),
                }
            }
        }
    ).encode()


def empty_inputs(**updates):
    values = {
        "sigstore_bundles": (),
        "sigstore_trust_config": None,
        "sigstore_policy": None,
        "sigstore_verifier": None,
        "jsf_documents": (),
        "jsf_policy": None,
    }
    values.update(updates)
    return subject.TrustInputs(**values)


def test_capture_requires_complete_explicit_trust_inputs(tmp_path):
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(message_bundle())
    with pytest.raises(ValueError, match="require trust config"):
        subject.capture_trust_inputs(sigstore_bundles=[bundle])
    policy = tmp_path / "policy.json"
    policy.write_text("{}")
    with pytest.raises(ValueError, match="at least one bundle"):
        subject.capture_trust_inputs(sigstore_policy=policy)
    with pytest.raises(ValueError, match="JSF documents require"):
        subject.capture_trust_inputs(jsf_documents=[bundle])
    with pytest.raises(ValueError, match="verifier path must be absolute"):
        subject.capture_trust_inputs(
            sigstore_bundles=[bundle],
            sigstore_trust_config=policy,
            sigstore_policy=policy,
            sigstore_verifier=Path("sigstore"),
        )


def test_capture_argument_wrapper_has_one_mapping(tmp_path):
    document = tmp_path / "bom.json"
    policy = tmp_path / "policy.json"
    document.write_text("{}")
    policy.write_text("{}")
    inputs = subject.capture_trust_arguments(argparse.Namespace(jsf=[document], jsf_policy=policy))
    assert inputs.jsf_documents[0].raw == b"{}"
    assert inputs.jsf_policy is not None
    assert inputs.jsf_policy.raw == b"{}"


def test_capture_identity_documents_use_same_immutable_bytes(tmp_path):
    jsf = tmp_path / "bom.json"
    policy = tmp_path / "policy.json"
    jsf.write_bytes(b'{"bomFormat":"CycloneDX"}')
    policy.write_bytes(b'{"schema_version":1}')
    captured = subject.capture_trust_inputs(jsf_documents=[jsf], jsf_policy=policy)
    jsf.write_bytes(b"changed")
    documents = captured.identity_documents()
    assert documents[0] == ("jsf_document", str(jsf.absolute()), b'{"bomFormat":"CycloneDX"}')
    assert documents[1] == ("jsf_policy", str(policy.absolute()), b'{"schema_version":1}')


def test_sigstore_claimed_subject_selection_supports_message_and_dsse():
    assert subject.sigstore_claimed_subjects(message_bundle()) == (DIGEST,)
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "artifact", "digest": {"sha256": DIGEST}}],
        "predicateType": "https://example.test/predicate/v1",
        "predicate": {},
    }
    dsse = {
        "dsseEnvelope": {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
            "signatures": [],
        }
    }
    assert subject.sigstore_claimed_subjects(json.dumps(dsse).encode()) == (DIGEST,)


def test_sigstore_verifies_only_documented_scanned_digest(monkeypatch):
    calls = []

    def verified(bundle, trust, policy, *, artifact_sha256, verifier_path):
        calls.append((bundle, trust, policy, artifact_sha256, verifier_path))
        return {"subject_sha256": [artifact_sha256], "patch_status": "unknown"}

    monkeypatch.setattr(subject, "verify_sigstore_bundle", verified)
    inputs = empty_inputs(
        sigstore_bundles=(CapturedDocument("bundle", message_bundle()),),
        sigstore_trust_config=CapturedDocument("trust", b"trust"),
        sigstore_policy=CapturedDocument("policy", b"policy"),
        sigstore_verifier=Path("/trusted/sigstore"),
    )
    records, gaps = subject.inspect_trust_inputs(
        inputs,
        [{"id": "first", "sha256": DIGEST}, {"id": "alias", "sha256": DIGEST}],
    )
    assert gaps == []
    assert len(calls) == 1
    assert calls[0][3] == DIGEST
    assert records[0]["bound_artifacts"] == ["alias", "first"]


def test_unmatched_sigstore_subject_is_gap_without_trying_verifier(monkeypatch):
    monkeypatch.setattr(
        subject,
        "verify_sigstore_bundle",
        lambda *_args, **_kwargs: pytest.fail("unmatched bundles must not be trial-verified"),
    )
    inputs = empty_inputs(
        sigstore_bundles=(CapturedDocument("bundle", message_bundle()),),
        sigstore_trust_config=CapturedDocument("trust", b"trust"),
        sigstore_policy=CapturedDocument("policy", b"policy"),
        sigstore_verifier=Path("/trusted/sigstore"),
    )
    records, gaps = subject.inspect_trust_inputs(inputs, [{"id": "other", "sha256": "b" * 64}])
    assert records == []
    assert gaps == [{"path": "bundle", "reason": "Sigstore bundle has no scanned subject"}]


def test_jsf_authenticated_subjects_join_exact_artifacts(monkeypatch):
    monkeypatch.setattr(
        subject,
        "verify_jsf_document",
        lambda *_: {"subject_sha256": [DIGEST], "patch_status": "unknown"},
    )
    inputs = empty_inputs(
        jsf_documents=(CapturedDocument("bom", b"bom"),),
        jsf_policy=CapturedDocument("policy", b"policy"),
    )
    records, gaps = subject.inspect_trust_inputs(
        inputs,
        [{"id": "target", "sha256": DIGEST}, {"id": "other", "sha256": "b" * 64}],
    )
    assert gaps == []
    assert records[0]["bound_artifacts"] == ["target"]
    assert records[0]["subject_binding"] == "exact_scanned_sha256"
    assert records[0]["patch_status"] == "unknown"
