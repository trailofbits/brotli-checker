"""Opt-in replay of Sigstore's retained happy-path-v0.3 conformance fixture."""

import base64
import json
import os
from pathlib import Path

import brotli_sigstore as subject
import pytest

FIXTURE_URL = (
    "https://github.com/sigstore/sigstore-conformance/tree/main/"
    "test/assets/bundle-verify/happy-path-v0.3"
)
BUNDLE_SHA256 = "5d84161191e6d3f4c0b95ff68296461a62fd180ad0b053da6292bf617ed033b3"
ARTIFACT_SHA256 = "a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf"
REQUIRED = (
    "BROTLI_SIGSTORE_CONFORMANCE_BUNDLE",
    "BROTLI_SIGSTORE_CONFORMANCE_TRUST_CONFIG",
    "BROTLI_SIGSTORE_CONFORMANCE_VERIFIER",
)


def policy():
    return json.dumps(
        {
            "schema_version": 1,
            "certificate_identity": (
                "https://github.com/sigstore-conformance/"
                "extremely-dangerous-public-oidc-beacon/.github/workflows/"
                "extremely-dangerous-oidc-beacon.yml@refs/heads/main"
            ),
            "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
            "evaluation_time": "2024-03-19T17:30:00Z",
            "trust_config_expires_at": "2027-01-01T00:00:00Z",
            "max_signature_age_seconds": 3600,
            "max_future_skew_seconds": 60,
        }
    ).encode()


@pytest.mark.skipif(
    any(not os.environ.get(name) for name in REQUIRED),
    reason=f"set {', '.join(REQUIRED)} to replay {FIXTURE_URL}",
)
def test_official_sigstore_bundle_and_digest_tampering():
    bundle = Path(os.environ[REQUIRED[0]]).read_bytes()
    trust = Path(os.environ[REQUIRED[1]]).read_bytes()
    verifier = Path(os.environ[REQUIRED[2]])
    result = subject.verify_sigstore_bundle(
        bundle,
        trust,
        policy(),
        artifact_sha256=ARTIFACT_SHA256,
        verifier_path=verifier,
    )
    assert result["bundle_sha256"] == BUNDLE_SHA256
    assert result["verifier_version"] == subject.EXPECTED_SIGSTORE_VERSION

    tampered = json.loads(bundle)
    tampered["messageSignature"]["messageDigest"]["digest"] = base64.b64encode(bytes(32)).decode()
    with pytest.raises(ValueError, match="Offline Sigstore verification failed"):
        subject.verify_sigstore_bundle(
            json.dumps(tampered).encode(),
            trust,
            policy(),
            artifact_sha256="0" * 64,
            verifier_path=verifier,
        )
